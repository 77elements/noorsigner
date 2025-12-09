package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
)

// NOTE: getSocketPath(), createListener(), cleanupListener(), dialConnection()
// are defined in daemon_unix.go (Unix) and daemon_windows.go (Windows)

// SignRequest represents a signing request via IPC
type SignRequest struct {
	ID              string `json:"id"`
	Method          string `json:"method"`
	EventJSON       string `json:"event_json,omitempty"`
	Plaintext       string `json:"plaintext,omitempty"`
	RecipientPubkey string `json:"recipient_pubkey,omitempty"`
	Payload         string `json:"payload,omitempty"`
	SenderPubkey    string `json:"sender_pubkey,omitempty"`
	// Multi-account fields
	Pubkey    string `json:"pubkey,omitempty"`
	Npub      string `json:"npub,omitempty"`
	Nsec      string `json:"nsec,omitempty"`
	Password  string `json:"password,omitempty"`
	SetActive bool   `json:"set_active,omitempty"`
}

// SignResponse represents a signing response
type SignResponse struct {
	ID        string `json:"id"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// AccountResponse represents an account in list response
type AccountResponse struct {
	Pubkey    string `json:"pubkey"`
	Npub      string `json:"npub"`
	CreatedAt int64  `json:"created_at"`
}

// ListAccountsResponse represents list_accounts response
type ListAccountsResponse struct {
	ID           string            `json:"id"`
	Accounts     []AccountResponse `json:"accounts"`
	ActivePubkey string            `json:"active_pubkey"`
	Error        string            `json:"error,omitempty"`
}

// AccountActionResponse represents add/switch/remove account response
type AccountActionResponse struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Pubkey  string `json:"pubkey,omitempty"`
	Npub    string `json:"npub,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ActiveAccountResponse represents get_active_account response
type ActiveAccountResponse struct {
	ID         string `json:"id"`
	Pubkey     string `json:"pubkey"`
	Npub       string `json:"npub"`
	IsUnlocked bool   `json:"is_unlocked"`
	Error      string `json:"error,omitempty"`
}

// Daemon holds the daemon state
type Daemon struct {
	privateKey *btcec.PrivateKey
	npub       string
	pubkey     string
	listener   net.Listener
	shutdown   chan bool
	mu         sync.RWMutex // Protects privateKey, npub, pubkey during account switch
}

// startDaemon starts the key signing daemon
func startDaemon() {
	fmt.Println("🔐 Starting NoorSigner Daemon")

	// Get active account
	activeNpub, err := loadActiveAccount()
	if err != nil {
		// No active account - check for accounts or run init
		accounts, listErr := listAccounts()
		if listErr != nil || len(accounts) == 0 {
			fmt.Println("⚠️  No accounts found - initializing...")
			fmt.Println()
			addAccount()
			fmt.Println()
			fmt.Println("✅ Initialization complete! Starting daemon...")
			fmt.Println()

			// Reload active account
			activeNpub, err = loadActiveAccount()
			if err != nil {
				fmt.Printf("Error loading active account: %v\n", err)
				return
			}
		} else {
			// Accounts exist but no active account - set first one as active
			activeNpub = accounts[0].Npub
			if err := saveActiveAccount(activeNpub); err != nil {
				fmt.Printf("Error setting active account: %v\n", err)
				return
			}
		}
	}

	// Load encrypted key for active account
	encryptedKey, err := loadAccountEncryptedKey(activeNpub)
	if err != nil {
		fmt.Printf("Error loading account key: %v\n", err)
		return
	}

	// Check for existing trust session first
	var nsec string
	fmt.Println("🔍 Checking for existing Trust Mode session...")
	trustSession, err := loadAccountTrustSession(activeNpub)
	if err != nil {
		fmt.Printf("   No trust session found: %v\n", err)
	} else {
		fmt.Printf("   Trust session found, expires: %s\n", trustSession.ExpiresAt.Format("15:04:05"))
		valid := isTrustSessionValid(trustSession)
		fmt.Printf("   Session valid: %v\n", valid)
	}

	if err == nil && isTrustSessionValid(trustSession) {
		// Valid trust session exists - decrypt cached nsec
		fmt.Printf("✅ Found valid Trust Mode session (expires: %s)\n",
			trustSession.ExpiresAt.Format("15:04:05"))
		fmt.Println("🔓 Daemon unlocked via Trust Mode - no password required!")

		// Decrypt cached nsec from trust session
		nsec, err = decryptTrustSessionNsec(trustSession)
		if err != nil {
			fmt.Printf("Error decrypting trust session: %v\n", err)
			// Clear invalid trust session
			clearAccountTrustSession(activeNpub)
			return
		}
	} else {
		// No valid trust session - create one (Trust Mode is mandatory for daemon)
		fmt.Println()
		fmt.Println("🛡️  NoorSigner uses Trust Mode for background operation")
		fmt.Println("   Your password will be cached for 24 hours")
		fmt.Println()

		password, err := readPassword("Enter password to unlock NoorSigner daemon: ")
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			return
		}

		// Test password first
		nsec, err = decryptNsec(encryptedKey, password)
		if err != nil {
			fmt.Println("❌ Invalid password!")
			return
		}

		// Create and save trust session with cached nsec
		session, err := createTrustSession(nsec)
		if err != nil {
			fmt.Printf("Error creating trust session: %v\n", err)
			return
		}

		if err := saveAccountTrustSession(activeNpub, session); err != nil {
			fmt.Printf("Error saving trust session: %v\n", err)
			return
		}

		fmt.Printf("✅ Trust Mode activated until %s\n", session.ExpiresAt.Format("15:04:05"))
	}

	// Convert to private key and keep in memory
	privateKey, err := nsecToPrivateKey(nsec)
	if err != nil {
		fmt.Printf("Error with decrypted nsec: %v\n", err)
		return
	}

	// Clear nsec from memory for security
	for i := range nsec {
		nsec = nsec[:i] + "x" + nsec[i+1:]
	}

	// Get pubkey
	pubkey, err := npubToPubkey(activeNpub)
	if err != nil {
		fmt.Printf("Error getting pubkey: %v\n", err)
		return
	}

	// Create daemon instance
	daemon := &Daemon{
		privateKey: privateKey,
		npub:       activeNpub,
		pubkey:     pubkey,
		shutdown:   make(chan bool, 1),
	}

	socketPath, err := getSocketPath()
	if err != nil {
		fmt.Printf("Error getting socket path: %v\n", err)
		return
	}

	fmt.Printf("✅ Daemon unlocked for: %s\n", activeNpub)
	fmt.Printf("📡 Listening on: %s\n", socketPath)
	fmt.Println()

	// Fork to background (Trust Mode is always active)
	shouldFork := os.Getenv("NOORSIGNER_FORKED") != "1"

	if shouldFork {
		// Fork to background by re-executing ourselves
		// Use absolute path to avoid Windows security restrictions
		exePath, err := os.Executable()
		if err != nil {
			fmt.Printf("Failed to get executable path: %v\n", err)
			return
		}
		cmd := exec.Command(exePath, os.Args[1:]...)
		cmd.Env = append(os.Environ(), "NOORSIGNER_FORKED=1")

		// Detach from terminal (Unix only)
		cmd.SysProcAttr = getSysProcAttr()

		if err := cmd.Start(); err != nil {
			fmt.Printf("Failed to fork daemon: %v\n", err)
			return
		}

		// Parent process - show success and exit
		fmt.Println("✨ NoorSigner daemon is running in background!")
		fmt.Printf("   (PID: %d)\n", cmd.Process.Pid)
		fmt.Println()
		fmt.Println("   You can close this window now.")
		os.Exit(0)
	}

	// Start server (in background for Trust Mode, foreground for Normal Mode)
	if err := daemon.serve(); err != nil {
		fmt.Printf("Daemon error: %v\n", err)
		os.Exit(1)
	}
}

// serve starts the IPC server (Unix socket or Windows Named Pipe)
func (d *Daemon) serve() error {
	// Create platform-specific listener
	listener, err := createListener()
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	d.listener = listener

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n🔒 Shutting down daemon...")
		d.shutdownDaemon()
		os.Exit(0)
	}()

	fmt.Println("Daemon ready for signing requests")

	// Accept connections
	for {
		select {
		case <-d.shutdown:
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				// Check if we're shutting down
				select {
				case <-d.shutdown:
					return nil
				default:
					fmt.Printf("Accept error: %v\n", err)
					continue
				}
			}

			// Handle connection in goroutine
			go d.handleConnection(conn)
		}
	}
}

// handleConnection handles a single client connection
func (d *Daemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req SignRequest
	if err := decoder.Decode(&req); err != nil {
		response := SignResponse{
			ID:    req.ID,
			Error: fmt.Sprintf("Invalid request format: %v", err),
		}
		encoder.Encode(response)
		return
	}

	// Handle requests
	switch req.Method {
	case "sign_event":
		d.mu.RLock()
		signature, err := d.signEvent(req.EventJSON)
		d.mu.RUnlock()

		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			response = SignResponse{
				ID:        req.ID,
				Signature: signature,
			}
		}
		encoder.Encode(response)

	case "get_npub":
		// Return current user's npub
		d.mu.RLock()
		npub := d.npub
		d.mu.RUnlock()

		response := SignResponse{
			ID:        req.ID,
			Signature: npub, // Using Signature field for npub response
		}
		encoder.Encode(response)

	case "enable_autostart":
		// Enable autostart for daemon
		err := enableAutostart()
		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			response = SignResponse{
				ID:        req.ID,
				Signature: "success",
			}
		}
		encoder.Encode(response)

	case "disable_autostart":
		// Disable autostart for daemon
		err := disableAutostart()
		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			response = SignResponse{
				ID:        req.ID,
				Signature: "success",
			}
		}
		encoder.Encode(response)

	case "get_autostart_status":
		// Get autostart status
		enabled, err := getAutostartStatus()
		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			status := "disabled"
			if enabled {
				status = "enabled"
			}
			response = SignResponse{
				ID:        req.ID,
				Signature: status,
			}
		}
		encoder.Encode(response)

	case "nip44_encrypt":
		// Encrypt plaintext using NIP-44
		if req.Plaintext == "" || req.RecipientPubkey == "" {
			response := SignResponse{
				ID:    req.ID,
				Error: "plaintext and recipient_pubkey required",
			}
			encoder.Encode(response)
			return
		}

		d.mu.RLock()
		encrypted, err := nip44Encrypt(req.Plaintext, req.RecipientPubkey, d.privateKey)
		d.mu.RUnlock()

		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			response = SignResponse{
				ID:        req.ID,
				Signature: encrypted, // Using Signature field for encrypted payload
			}
		}
		encoder.Encode(response)

	case "nip44_decrypt":
		// Decrypt NIP-44 payload
		if req.Payload == "" || req.SenderPubkey == "" {
			response := SignResponse{
				ID:    req.ID,
				Error: "payload and sender_pubkey required",
			}
			encoder.Encode(response)
			return
		}

		d.mu.RLock()
		plaintext, err := nip44Decrypt(req.Payload, req.SenderPubkey, d.privateKey)
		d.mu.RUnlock()

		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			response = SignResponse{
				ID:        req.ID,
				Signature: plaintext, // Using Signature field for decrypted plaintext
			}
		}
		encoder.Encode(response)

	case "nip04_encrypt":
		// Encrypt plaintext using NIP-04 (deprecated but widely compatible)
		if req.Plaintext == "" || req.RecipientPubkey == "" {
			response := SignResponse{
				ID:    req.ID,
				Error: "plaintext and recipient_pubkey required",
			}
			encoder.Encode(response)
			return
		}

		d.mu.RLock()
		encrypted, err := nip04Encrypt(req.Plaintext, req.RecipientPubkey, d.privateKey)
		d.mu.RUnlock()

		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			response = SignResponse{
				ID:        req.ID,
				Signature: encrypted, // Using Signature field for encrypted payload
			}
		}
		encoder.Encode(response)

	case "nip04_decrypt":
		// Decrypt NIP-04 payload (deprecated but widely compatible)
		if req.Payload == "" || req.SenderPubkey == "" {
			response := SignResponse{
				ID:    req.ID,
				Error: "payload and sender_pubkey required",
			}
			encoder.Encode(response)
			return
		}

		d.mu.RLock()
		plaintext, err := nip04Decrypt(req.Payload, req.SenderPubkey, d.privateKey)
		d.mu.RUnlock()

		var response SignResponse
		if err != nil {
			response = SignResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
		} else {
			response = SignResponse{
				ID:        req.ID,
				Signature: plaintext, // Using Signature field for decrypted plaintext
			}
		}
		encoder.Encode(response)

	case "shutdown_daemon":
		// Shutdown daemon gracefully
		response := SignResponse{
			ID:        req.ID,
			Signature: "success",
		}
		encoder.Encode(response)

		// Trigger shutdown after response is sent
		go func() {
			fmt.Println("\n🔒 Shutdown requested by client...")
			d.shutdownDaemon()
			os.Exit(0)
		}()

	// ========== Multi-Account API Endpoints ==========

	case "list_accounts":
		accounts, err := listAccounts()
		if err != nil {
			response := ListAccountsResponse{
				ID:    req.ID,
				Error: err.Error(),
			}
			encoder.Encode(response)
			return
		}

		activeNpub, _ := loadActiveAccount()
		activePubkey := ""
		if activeNpub != "" {
			activePubkey, _ = npubToPubkey(activeNpub)
		}

		var accountResponses []AccountResponse
		for _, acc := range accounts {
			accountResponses = append(accountResponses, AccountResponse{
				Pubkey:    acc.Pubkey,
				Npub:      acc.Npub,
				CreatedAt: acc.CreatedAt.Unix(),
			})
		}

		response := ListAccountsResponse{
			ID:           req.ID,
			Accounts:     accountResponses,
			ActivePubkey: activePubkey,
		}
		encoder.Encode(response)

	case "add_account":
		if req.Nsec == "" || req.Password == "" {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "nsec and password required",
			}
			encoder.Encode(response)
			return
		}

		// Validate nsec and get npub
		privateKey, err := nsecToPrivateKey(req.Nsec)
		if err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: fmt.Sprintf("invalid nsec: %v", err),
			}
			encoder.Encode(response)
			return
		}
		npub := privateKeyToNpub(privateKey)

		// Check if account already exists
		if accountExists(npub) {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "account already exists",
			}
			encoder.Encode(response)
			return
		}

		// Encrypt nsec
		encryptedKey, err := encryptNsec(req.Nsec, req.Password)
		if err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: fmt.Sprintf("encryption failed: %v", err),
			}
			encoder.Encode(response)
			return
		}

		// Save account
		if err := saveAccountEncryptedKey(npub, encryptedKey); err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: fmt.Sprintf("failed to save account: %v", err),
			}
			encoder.Encode(response)
			return
		}

		// Set as active if requested
		if req.SetActive {
			saveActiveAccount(npub)
		}

		pubkey, _ := npubToPubkey(npub)
		response := AccountActionResponse{
			ID:      req.ID,
			Success: true,
			Pubkey:  pubkey,
			Npub:    npub,
		}
		encoder.Encode(response)

	case "switch_account":
		// Accept either pubkey or npub
		targetNpub := req.Npub
		if targetNpub == "" && req.Pubkey != "" {
			// Find npub by pubkey
			accounts, _ := listAccounts()
			for _, acc := range accounts {
				if acc.Pubkey == req.Pubkey {
					targetNpub = acc.Npub
					break
				}
			}
		}

		if targetNpub == "" {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "pubkey or npub required",
			}
			encoder.Encode(response)
			return
		}

		if req.Password == "" {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "password required",
			}
			encoder.Encode(response)
			return
		}

		// Check if account exists
		if !accountExists(targetNpub) {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "account not found",
			}
			encoder.Encode(response)
			return
		}

		// Load and verify password
		encKey, err := loadAccountEncryptedKey(targetNpub)
		if err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: fmt.Sprintf("failed to load account: %v", err),
			}
			encoder.Encode(response)
			return
		}

		nsec, err := decryptNsec(encKey, req.Password)
		if err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "invalid password",
			}
			encoder.Encode(response)
			return
		}

		// Convert to private key
		newPrivateKey, err := nsecToPrivateKey(nsec)
		if err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "corrupted key file",
			}
			encoder.Encode(response)
			return
		}

		newPubkey, _ := npubToPubkey(targetNpub)

		// Create trust session for new account
		session, err := createTrustSession(nsec)
		if err == nil {
			saveAccountTrustSession(targetNpub, session)
		}

		// Clear nsec from memory
		for i := range nsec {
			nsec = nsec[:i] + "x" + nsec[i+1:]
		}

		// Update daemon state
		d.mu.Lock()
		// Clear old private key from memory
		if d.privateKey != nil {
			keyBytes := d.privateKey.Serialize()
			for i := range keyBytes {
				keyBytes[i] = 0
			}
		}
		d.privateKey = newPrivateKey
		d.npub = targetNpub
		d.pubkey = newPubkey
		d.mu.Unlock()

		// Update active account file
		saveActiveAccount(targetNpub)

		response := AccountActionResponse{
			ID:      req.ID,
			Success: true,
			Pubkey:  newPubkey,
			Npub:    targetNpub,
		}
		encoder.Encode(response)

	case "remove_account":
		// Accept either pubkey or npub
		targetNpub := req.Npub
		if targetNpub == "" && req.Pubkey != "" {
			// Find npub by pubkey
			accounts, _ := listAccounts()
			for _, acc := range accounts {
				if acc.Pubkey == req.Pubkey {
					targetNpub = acc.Npub
					break
				}
			}
		}

		if targetNpub == "" {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "pubkey or npub required",
			}
			encoder.Encode(response)
			return
		}

		if req.Password == "" {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "password required",
			}
			encoder.Encode(response)
			return
		}

		// Check if account exists
		if !accountExists(targetNpub) {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "account not found",
			}
			encoder.Encode(response)
			return
		}

		// Verify password
		encKey, err := loadAccountEncryptedKey(targetNpub)
		if err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: fmt.Sprintf("failed to load account: %v", err),
			}
			encoder.Encode(response)
			return
		}

		_, err = decryptNsec(encKey, req.Password)
		if err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "invalid password",
			}
			encoder.Encode(response)
			return
		}

		// Check if this is the current active account
		d.mu.RLock()
		isCurrentAccount := d.npub == targetNpub
		d.mu.RUnlock()

		if isCurrentAccount {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: "cannot remove active account - switch to another account first",
			}
			encoder.Encode(response)
			return
		}

		// Remove account
		if err := removeAccount(targetNpub); err != nil {
			response := AccountActionResponse{
				ID:    req.ID,
				Error: fmt.Sprintf("failed to remove account: %v", err),
			}
			encoder.Encode(response)
			return
		}

		response := AccountActionResponse{
			ID:      req.ID,
			Success: true,
		}
		encoder.Encode(response)

	case "get_active_account":
		d.mu.RLock()
		npub := d.npub
		pubkey := d.pubkey
		isUnlocked := d.privateKey != nil
		d.mu.RUnlock()

		response := ActiveAccountResponse{
			ID:         req.ID,
			Pubkey:     pubkey,
			Npub:       npub,
			IsUnlocked: isUnlocked,
		}
		encoder.Encode(response)

	default:
		response := SignResponse{
			ID:    req.ID,
			Error: "Unknown method: " + req.Method,
		}
		encoder.Encode(response)
	}
}

// signEvent signs a Nostr event JSON
func (d *Daemon) signEvent(eventJSON string) (string, error) {
	// Create hash of the event per NIP-01
	eventHash, err := createEventHash(eventJSON)
	if err != nil {
		return "", fmt.Errorf("failed to hash event: %v", err)
	}

	// Sign with stored private key
	return signNostrEvent(d.privateKey, eventHash)
}

// shutdownDaemon cleans up daemon resources
func (d *Daemon) shutdownDaemon() {
	// Signal shutdown to main loop
	select {
	case d.shutdown <- true:
	default:
	}

	if d.listener != nil {
		d.listener.Close()
	}

	// Platform-specific cleanup (removes Unix socket file, no-op on Windows)
	cleanupListener()

	// Clear private key from memory (security)
	d.mu.Lock()
	if d.privateKey != nil {
		// Zero out private key bytes
		keyBytes := d.privateKey.Serialize()
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}
	d.mu.Unlock()

	fmt.Println("Daemon shutdown complete")
}
