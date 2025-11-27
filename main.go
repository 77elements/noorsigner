package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: noorsigner <command>")
		fmt.Println("Commands:")
		fmt.Println("  init         - Initialize key signer with nsec and password")
		fmt.Println("  daemon       - Start daemon")
		fmt.Println("  sign         - Sign event with stored key (requires password)")
		fmt.Println("  test-daemon  - Test signing via daemon")
		fmt.Println("  test         - Test signing with direct nsec input")
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "init":
		initKeySigner()
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
		os.Exit(1)
	}
}

func initKeySigner() bool {
	fmt.Println("🔐 Key Signer Initialization")
	fmt.Println("Setting up secure nsec storage with password protection")
	fmt.Println()

	// Get nsec from user (masked like password)
	fmt.Println("Enter your nsec (nsec1... or hex):")
	fmt.Println("(Input is hidden for security - paste and press Enter)")
	nsec, err := readPassword("")
	if err != nil {
		fmt.Printf("Error reading nsec: %v\n", err)
		return false
	}

	// Validate nsec format
	_, err = nsecToPrivateKey(nsec)
	if err != nil {
		fmt.Printf("Invalid nsec format: %v\n", err)
		return false
	}

	// Get password (loop until valid)
	var password1 string
	for {
		var err error
		password1, err = readPassword("Enter password for encryption: ")
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			return false
		}

		if len(password1) < 8 {
			fmt.Println("❌ Password must be at least 8 characters! Please try again.")
			fmt.Println()
			continue
		}

		password2, err := readPassword("Confirm password: ")
		if err != nil {
			fmt.Printf("Error reading password confirmation: %v\n", err)
			return false
		}

		if password1 != password2 {
			fmt.Println("❌ Passwords do not match! Please try again.")
			fmt.Println()
			continue
		}

		// Password valid and confirmed
		break
	}
	
	// Encrypt and save nsec
	encryptedKey, err := encryptNsec(nsec, password1)
	if err != nil {
		fmt.Printf("Error encrypting nsec: %v\n", err)
		return false
	}

	err = saveEncryptedKey(encryptedKey)
	if err != nil {
		fmt.Printf("Error saving encrypted key: %v\n", err)
		return false
	}

	// Generate and show npub
	privateKey, _ := nsecToPrivateKey(nsec)
	npub := privateKeyToNpub(privateKey)

	fmt.Println()
	fmt.Println("✅ Key signer initialized successfully!")
	fmt.Printf("Your npub: %s\n", npub)

	storageDir, _ := getStorageDir()
	fmt.Printf("Encrypted key saved to: %s\n", storageDir)

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
	
	// Load encrypted key
	encryptedKey, err := loadEncryptedKey()
	if err != nil {
		fmt.Printf("Error loading key: %v\n", err)
		fmt.Println("Run 'key-signer init' first to set up your key.")
		return
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