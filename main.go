package main

import (
	"fmt"
	"os"
)

func main() {
	// Run migration from old single-account format if needed
	if err := migrateToMultiAccount(); err != nil {
		fmt.Printf("Migration warning: %v\n", err)
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "init":
		// Backwards compatibility: init = add-account for first account
		accounts, _ := listAccounts()
		if len(accounts) > 0 {
			fmt.Println("Account already exists. Use 'add-account' to add more accounts.")
			fmt.Printf("Current accounts: %d\n", len(accounts))
			os.Exit(1)
		}
		addAccount()
	case "add-account":
		addAccount()
	case "list-accounts":
		listAccountsCmd()
	case "switch":
		if len(os.Args) < 3 {
			fmt.Println("Usage: noorsigner switch <npub>")
			os.Exit(1)
		}
		switchAccount(os.Args[2])
	case "remove-account":
		if len(os.Args) < 3 {
			fmt.Println("Usage: noorsigner remove-account <npub>")
			os.Exit(1)
		}
		removeAccountCmd(os.Args[2])
	case "daemon":
		startDaemon()
	case "sign":
		signWithStoredKey()
	case "test-daemon":
		testDaemonSigning()
	case "test":
		if len(os.Args) < 3 {
			fmt.Println("Usage: noorsigner test <nsec>")
			os.Exit(1)
		}
		nsec := os.Args[2]
		testSigning(nsec)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: noorsigner <command>")
	fmt.Println()
	fmt.Println("Account Management:")
	fmt.Println("  add-account     - Add a new account (nsec + password)")
	fmt.Println("  list-accounts   - List all stored accounts")
	fmt.Println("  switch <npub>   - Switch to a different account")
	fmt.Println("  remove-account <npub> - Remove an account")
	fmt.Println()
	fmt.Println("Daemon:")
	fmt.Println("  daemon          - Start signing daemon")
	fmt.Println()
	fmt.Println("Other:")
	fmt.Println("  init            - Initialize (alias for add-account, first account only)")
	fmt.Println("  sign            - Sign event with stored key (requires password)")
	fmt.Println("  test-daemon     - Test signing via daemon")
	fmt.Println("  test <nsec>     - Test signing with direct nsec input")
}

// addAccount adds a new account
func addAccount() {
	fmt.Println("🔐 Add Account")
	fmt.Println("Setting up secure nsec storage with password protection")
	fmt.Println()

	// Get nsec from user (masked like password)
	fmt.Println("Enter your nsec (nsec1... or hex):")
	fmt.Println("(Input is hidden for security - paste and press Enter)")
	nsec, err := readPassword("")
	if err != nil {
		fmt.Printf("Error reading nsec: %v\n", err)
		os.Exit(1)
	}

	// Validate nsec format and get npub
	privateKey, err := nsecToPrivateKey(nsec)
	if err != nil {
		fmt.Printf("Invalid nsec format: %v\n", err)
		os.Exit(1)
	}
	npub := privateKeyToNpub(privateKey)

	// Check if account already exists
	if accountExists(npub) {
		fmt.Printf("Account already exists: %s\n", npub)
		os.Exit(1)
	}

	// Get password (loop until valid)
	var password1 string
	for {
		var err error
		password1, err = readPassword("Enter password for encryption: ")
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			os.Exit(1)
		}

		if len(password1) < 8 {
			fmt.Println("❌ Password must be at least 8 characters! Please try again.")
			fmt.Println()
			continue
		}

		password2, err := readPassword("Confirm password: ")
		if err != nil {
			fmt.Printf("Error reading password confirmation: %v\n", err)
			os.Exit(1)
		}

		if password1 != password2 {
			fmt.Println("❌ Passwords do not match! Please try again.")
			fmt.Println()
			continue
		}

		// Password valid and confirmed
		break
	}

	// Encrypt nsec
	encryptedKey, err := encryptNsec(nsec, password1)
	if err != nil {
		fmt.Printf("Error encrypting nsec: %v\n", err)
		os.Exit(1)
	}

	// Save to account directory
	err = saveAccountEncryptedKey(npub, encryptedKey)
	if err != nil {
		fmt.Printf("Error saving encrypted key: %v\n", err)
		os.Exit(1)
	}

	// Set as active account
	err = saveActiveAccount(npub)
	if err != nil {
		fmt.Printf("Error setting active account: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("✅ Account added successfully!")
	fmt.Printf("Your npub: %s\n", npub)
	fmt.Println("This account is now active.")

	accountDir, _ := getAccountDir(npub)
	fmt.Printf("Encrypted key saved to: %s\n", accountDir)
}

// listAccountsCmd lists all stored accounts
func listAccountsCmd() {
	accounts, err := listAccounts()
	if err != nil {
		fmt.Printf("Error listing accounts: %v\n", err)
		os.Exit(1)
	}

	if len(accounts) == 0 {
		fmt.Println("No accounts found. Use 'add-account' to add one.")
		return
	}

	activeNpub, _ := loadActiveAccount()

	fmt.Println("Stored accounts:")
	fmt.Println()
	for _, acc := range accounts {
		marker := "  "
		if acc.Npub == activeNpub {
			marker = "* "
		}
		fmt.Printf("%s%s\n", marker, acc.Npub)
	}
	fmt.Println()
	fmt.Printf("Total: %d account(s)\n", len(accounts))
	if activeNpub != "" {
		fmt.Println("* = active account")
	}
}

// switchAccount switches to a different account
func switchAccount(npub string) {
	// Check if account exists
	if !accountExists(npub) {
		fmt.Printf("Account not found: %s\n", npub)
		fmt.Println("Use 'list-accounts' to see available accounts.")
		os.Exit(1)
	}

	// Check if already active
	activeNpub, _ := loadActiveAccount()
	if activeNpub == npub {
		fmt.Println("This account is already active.")
		return
	}

	// Load and verify account can be decrypted
	encKey, err := loadAccountEncryptedKey(npub)
	if err != nil {
		fmt.Printf("Error loading account: %v\n", err)
		os.Exit(1)
	}

	// Ask for password to verify
	password, err := readPassword("Enter password for this account: ")
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	// Try to decrypt to verify password
	nsec, err := decryptNsec(encKey, password)
	if err != nil {
		fmt.Println("❌ Invalid password!")
		os.Exit(1)
	}

	// Verify nsec is valid
	_, err = nsecToPrivateKey(nsec)
	if err != nil {
		fmt.Println("❌ Corrupted key file!")
		os.Exit(1)
	}

	// Set as active account (file)
	err = saveActiveAccount(npub)
	if err != nil {
		fmt.Printf("Error setting active account: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()

	// If daemon is running, switch it live
	if isDaemonRunning() {
		fmt.Println("🔄 Daemon detected, switching live...")
		err = switchAccountViaDaemon(npub, password)
		if err != nil {
			fmt.Printf("⚠️  Could not switch daemon: %v\n", err)
			fmt.Println("   Restart daemon manually: pkill noorsigner && noorsigner daemon")
		} else {
			fmt.Printf("✅ Switched to account: %s\n", npub)
			fmt.Println("   Daemon updated - no restart needed!")
		}
	} else {
		fmt.Printf("✅ Switched to account: %s\n", npub)
		fmt.Println("   Daemon not running. Start with: noorsigner daemon")
	}
}

// removeAccountCmd removes an account
func removeAccountCmd(npub string) {
	// Check if account exists
	if !accountExists(npub) {
		fmt.Printf("Account not found: %s\n", npub)
		os.Exit(1)
	}

	// Load account to verify password
	encKey, err := loadAccountEncryptedKey(npub)
	if err != nil {
		fmt.Printf("Error loading account: %v\n", err)
		os.Exit(1)
	}

	// Ask for password to confirm
	password, err := readPassword("Enter password to confirm removal: ")
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	// Verify password
	_, err = decryptNsec(encKey, password)
	if err != nil {
		fmt.Println("❌ Invalid password!")
		os.Exit(1)
	}

	// Remove account
	err = removeAccount(npub)
	if err != nil {
		fmt.Printf("Error removing account: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("✅ Account removed: %s\n", npub)

	// Check if there are remaining accounts
	accounts, _ := listAccounts()
	if len(accounts) == 0 {
		fmt.Println("No accounts remaining. Use 'add-account' to add one.")
	} else {
		activeNpub, err := loadActiveAccount()
		if err != nil || activeNpub == "" {
			// Set first remaining account as active
			saveActiveAccount(accounts[0].Npub)
			fmt.Printf("Active account set to: %s\n", accounts[0].Npub)
		}
	}
}

// initKeySigner is kept for backwards compatibility (calls addAccount)
func initKeySigner() bool {
	addAccount()
	return true
}

func testSigning(nsec string) {
	fmt.Println("Testing key signer...")

	// Convert nsec to private key
	privateKey, err := nsecToPrivateKey(nsec)
	if err != nil {
		fmt.Printf("Error converting nsec: %v\n", err)
		return
	}

	// Generate npub from private key
	npub := privateKeyToNpub(privateKey)
	fmt.Printf("Your npub: %s\n", npub)

	// Create test event hash and sign it
	testHash := generateTestEventHash()
	signature, err := signNostrEvent(privateKey, testHash)
	if err != nil {
		fmt.Printf("Error signing: %v\n", err)
		return
	}

	fmt.Printf("Test signature: %s\n", signature)
	fmt.Println("✅ Key signer working correctly!")
}

func signWithStoredKey() {
	fmt.Println("🔐 Signing with stored key")

	// Get active account
	activeNpub, err := loadActiveAccount()
	if err != nil {
		fmt.Println("No active account. Use 'add-account' to add one.")
		os.Exit(1)
	}

	// Load encrypted key for active account
	encryptedKey, err := loadAccountEncryptedKey(activeNpub)
	if err != nil {
		fmt.Printf("Error loading key: %v\n", err)
		os.Exit(1)
	}

	// Get password
	password, err := readPassword("Enter password: ")
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		return
	}

	// Decrypt nsec
	nsec, err := decryptNsec(encryptedKey, password)
	if err != nil {
		fmt.Println("❌ Invalid password or corrupted key file!")
		return
	}

	// Convert to private key
	privateKey, err := nsecToPrivateKey(nsec)
	if err != nil {
		fmt.Printf("Error with decrypted nsec: %v\n", err)
		return
	}

	// Show npub
	npub := privateKeyToNpub(privateKey)
	fmt.Printf("Signing as: %s\n", npub)

	// Create test signature
	testHash := generateTestEventHash()
	signature, err := signNostrEvent(privateKey, testHash)
	if err != nil {
		fmt.Printf("Error signing: %v\n", err)
		return
	}

	fmt.Printf("Test signature: %s\n", signature)
	fmt.Println("✅ Signing successful!")
}
