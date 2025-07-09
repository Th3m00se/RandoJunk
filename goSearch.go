// Current capabilities
// Domain Controller Discovery: Uses the DsGetDcNameW API.
// Current User Retrieval: Retrieves the currently logged-in user's domain and username.
// LDAP Query: Queries Active Directory for file servers using the current user's credentials.
// Threading with Goroutines and Channels: Performs share listing concurrently.
// SQLite Database Storage: Stores the results in an SQLite database.

// install these libraries
// go get github.com/go-ldap/ldap/v3
// go get github.com/hirochachacha/go-smb2
// go get github.com/hirochachacha/go-smb2/sspi
// go get github.com/mattn/go-sqlite3

// Main code:
// ******************
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/security"
	"github.com/go-ldap/ldap/v3"
	"github.com/hirochachacha/go-smb2"
	"github.com/hirochachacha/go-smb2/sspi"
	_ "github.com/mattn/go-sqlite3"
)

// DsGetDcName function from netapi32.dll
var (
	netapi32         = windows.NewLazySystemDLL("netapi32.dll")
	procDsGetDcNameW = netapi32.NewProc("DsGetDcNameW")
)

type DS_DOMAIN_CONTROLLER_INFO_W struct {
	DomainControllerName *uint16
	DomainControllerAddress *uint16
	DomainControllerAddressType uint32
	DomainGuid *windows.GUID
	DomainName *uint16
	DnsForestName *uint16
	Flags uint32
	DcSiteName *uint16
	ClientSiteName *uint16
}

func getDomainController() (string, error) {
	var dcInfo *DS_DOMAIN_CONTROLLER_INFO_W
	ret, _, _ := procDsGetDcNameW.Call(
		0, // ComputerName
		0, // DomainName
		0, // DomainGuid
		0, // SiteName
		0, // Flags
		uintptr(unsafe.Pointer(&dcInfo)),
	)

	if ret != 0 {
		return "", fmt.Errorf("DsGetDcNameW failed with error code: %d", ret)
	}

	defer func() {
		windows.NetApiBufferFree(windows.Handle(uintptr(unsafe.Pointer(dcInfo))))
	}()

	domainControllerName := windows.UTF16PtrToString(dcInfo.DomainControllerName)
	return domainControllerName, nil
}

func getCurrentUser() (string, string, error) {
	user, err := security.CurrentAccount()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current user: %v", err)
	}

	username := user.Name()
	domain := user.Domain()

	return domain, username, nil
}

func getADFileServers(domainController, domain, username string) ([]string, error) {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s", domainController))
	if err != nil {
		return nil, fmt.Errorf("failed to dial LDAP: %v", err)
	}
	defer l.Close()

	// Bind using the current user's credentials
	err = l.Bind(fmt.Sprintf("%s@%s", username, domain), "")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP: %v", err)
	}

	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("DC=%s", strings.ReplaceAll(domain, ".", ",DC=")),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=computer)(servicePrincipalName=*cifs*))",
		[]string{"dNSHostName"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %v", err)
	}

	var fileServers []string
	for _, entry := range sr.Entries {
		fileServers = append(fileServers, entry.GetAttributeValue("dNSHostName"))
	}

	return fileServers, nil
}

func listShares(server string, wg *sync.WaitGroup, results chan<- map[string][]string) {
	defer wg.Done()

	conn, err := smb2.Dial(server, &smb2.Dialer{
		Initiator: &sspi.Initiator{
			AuthIdentity: sspi.AuthIdentity{
				Username: "",
				Domain:   "",
				Password: "",
			},
		},
	})
	if err != nil {
		results <- map[string][]string{server: {fmt.Sprintf("Failed to dial SMB server: %v", err)}}
		return
	}
	defer conn.Close()

	ctx := context.Background()
	shares, err := conn.ListShares(ctx)
	if err != nil {
		results <- map[string][]string{server: {fmt.Sprintf("Failed to list shares: %v", err)}}
		return
	}

	var shareNames []string
	for _, share := range shares {
		shareNames = append(shareNames, share.Name())
	}

	results <- map[string][]string{server: shareNames}
}

func initDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %v", err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS shares (
		server TEXT NOT NULL,
		share TEXT NOT NULL
	);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %v", err)
	}

	return db, nil
}

func storeResults(db *sql.DB, results map[string][]string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO shares (server, share) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for server, shares := range results {
		for _, share := range shares {
			_, err := stmt.Exec(server, share)
			if err != nil {
				return fmt.Errorf("failed to insert data: %v", err)
			}
		}
	}

	return tx.Commit()
}

func main() {
	domainController, err := getDomainController()
	if err != nil {
		log.Fatalf("Failed to get domain controller: %v", err)
	}

	domain, username, err := getCurrentUser()
	if err != nil {
		log.Fatalf("Failed to get current user: %v", err)
	}

	fileServers, err := getADFileServers(domainController, domain, username)
	if err != nil {
		log.Fatalf("Failed to get file servers: %v", err)
	}

	dbPath := "shares.db"
	db, err := initDatabase(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	var wg sync.WaitGroup
	results := make(chan map[string][]string, len(fileServers))

	for _, server := range fileServers {
		wg.Add(1)
		go listShares(server, &wg, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		for server, shares := range result {
			fmt.Printf("Listing shares on %s:\n", server)
			for _, share := range shares {
				fmt.Printf(" - %s\n", share)
			}

			// Store the results in the database
			err := storeResults(db, result)
			if err != nil {
				log.Printf("Failed to store results for %s: %v\n", server, err)
			}
		}
	}
}
