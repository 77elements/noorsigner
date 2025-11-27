package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
)

func getSocketPath() (string, error) {
	storageDir, err := getStorageDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(storageDir, "noorsigner.sock"), nil
}

// SignRequest represents a signing request via IPC
type SignRequest struct {
	ID             string `json:"id"`
	Method         string `json:"method"`
	EventJSON      string `json:"event_json,omitempty"`
	Plaintext      string `json:"plaintext,omitempty"`
	RecipientPubkey string `json:"recipient_pubkey,omitempty"`
	Payload        string `json:"payload,omitempty"`
	SenderPubkey   string `json:"sender_pubkey,omitempty"`
}

// SignResponse represents a signing response
type SignResponse struct {
	ID        string `json:"id"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Daemon holds the daemon state
type Daemon struct {
	privateKey *btcec.PrivateKey
	npub       string
	listener   net.Listener
	shutdown   chan bool
}

// startDaemon starts the key signing daemon
func startDaemon() {
	fmt.Println("🔐 Starting NoorSigner Daemon")

	// Load and decrypt key
	encryptedKey, err := loadEncryptedKey()
	if err != nil {
		// No encrypted key found - run init first
		fmt.Println("⚠️  No encrypted key found - initializing...")
		fmt.Println()
		success := initKeySigner()
		if !success {
			fmt.Println()
			fmt.Println("❌ Initialization failed. Please try again.")
			return
		}
		fmt.Println()
		fmt.Println("✅ Initialization complete! Starting daemon...")
		fmt.Println()

		// Load the newly created key
		encryptedKey, err = loadEncryptedKey()
		if err != nil {
			fmt.Printf("Error loading newly created key: %v\n", err)
			return
		}
	}

	// Check for existing trust session first
	var nsec string
	fmt.Println("🔍 Checking for existing Trust Mode session...")
	trustSession, err := loadTrustSession()
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
			clearTrustSession()
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

		if err := saveTrustSession(session); err != nil {
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
	
	// Generate npub for display
	npub := privateKeyToNpub(privateKey)
	
	// Create daemon instance
	daemon := &Daemon{
		privateKey: privateKey,
		npub:       npub,
		shutdown:   make(chan bool, 1),
	}
	
	socketPath, err := getSocketPath()
	if err != nil {
		fmt.Printf("Error getting socket path: %v\n", err)
		return
	}

	fmt.Printf("✅ Daemon unlocked for: %s\n", npub)
	fmt.Printf("📡 Listening on: %s\n", socketPath)
	fmt.Println()

	// Fork to background (Trust Mode is always active)
	shouldFork := os.Getenv("NOORSIGNER_FORKED") != "1"

	if shouldFork {
		// Fork to background by re-executing ourselves
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = append(os.Environ(), "NOORSIGNER_FORKED=1")

		// Detach from terminal (Unix only)
		cmd.SysProcAttr = getSysProcAttr()

		err := cmd.Start()
		if err != nil {
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

// serve starts the Unix Domain Socket server
func (d *Daemon) serve() error {
	socketPath, err := getSocketPath()
	if err != nil {
		return fmt.Errorf("failed to get socket path: %v", err)
	}

	// Remove existing socket if it exists
	os.Remove(socketPath)

	// Create Unix Domain Socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}
	d.listener = listener
	
	// Set socket permissions (only user can access)
	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %v", err)
	}
	
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
		signature, err := d.signEvent(req.EventJSON)
		
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
		response := SignResponse{
			ID:        req.ID,
			Signature: d.npub, // Using Signature field for npub response
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

		encrypted, err := nip44Encrypt(req.Plaintext, req.RecipientPubkey, d.privateKey)
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

		plaintext, err := nip44Decrypt(req.Payload, req.SenderPubkey, d.privateKey)
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

		encrypted, err := nip04Encrypt(req.Plaintext, req.RecipientPubkey, d.privateKey)
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

		plaintext, err := nip04Decrypt(req.Payload, req.SenderPubkey, d.privateKey)
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
	
	// Remove socket file
	if socketPath, err := getSocketPath(); err == nil {
		os.Remove(socketPath)
	}
	
	// Clear private key from memory (security)
	if d.privateKey != nil {
		// Zero out private key bytes
		keyBytes := d.privateKey.Serialize()
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}
	
	fmt.Println("Daemon shutdown complete")
}