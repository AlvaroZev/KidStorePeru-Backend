package main

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/fortnite"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// Database configuration - hardcoded for portability
const (
	DB_HOST     = "ballast.proxy.rlwy.net"
	DB_PORT     = 44201
	DB_USER     = "postgres"
	DB_PASSWORD = "feIjJFjgDnUmFIdGiNhcTSydADlcgbiG"
	DB_NAME     = "railway"
)

func main() {
	// Construct the PostgreSQL connection string using hardcoded values
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}
	defer db.Close()

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	fmt.Println("Successfully connected to the database")

	// Update pavos for all accounts
	fmt.Println("Starting pavos update for all accounts...")
	updateAllPavos(db)
	fmt.Println("Pavos update completed")
}

// updateAllPavos updates the pavos for all game accounts in the database
func updateAllPavos(db *sql.DB) {
	// Get all game accounts from the database
	gameAccounts, err := database.GetAllGameAccounts(db)
	if err != nil {
		log.Fatalf("Could not fetch all game accounts: %v", err)
	}

	if len(gameAccounts) == 0 {
		fmt.Println("No game accounts found in the database")
		return
	}

	fmt.Printf("Found %d game accounts to update\n", len(gameAccounts))

	// Update pavos for each account
	successCount := 0
	errorCount := 0

	for i, account := range gameAccounts {
		fmt.Printf("Updating pavos for account %d/%d: %s (ID: %s)\n",
			i+1, len(gameAccounts), account.DisplayName, account.ID)

		_, err := fortnite.UpdatePavosGameAccount(db, account.ID)
		if err != nil {
			fmt.Printf("Error updating pavos for account %s: %v\n", account.ID, err)
			errorCount++
		} else {
			fmt.Printf("Successfully updated pavos for account %s\n", account.ID)
			successCount++
		}
	}

	fmt.Printf("\nUpdate summary:\n")
	fmt.Printf("- Total accounts: %d\n", len(gameAccounts))
	fmt.Printf("- Successfully updated: %d\n", successCount)
	fmt.Printf("- Errors: %d\n", errorCount)
}
