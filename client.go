package main

import (
	"encoding/json"
	"fmt"
)

// signEventViaSocket sends signing request to daemon via IPC
func signEventViaSocket(eventJSON string) (string, error) {
	// Connect to daemon (Unix socket or Windows Named Pipe)
	conn, err := dialConnection()
	if err != nil {
		return "", fmt.Errorf("failed to connect to daemon: %v\nIs the daemon running? Try: noorsigner daemon", err)
	}
	defer conn.Close()
	
	// Create signing request
	request := SignRequest{
		ID:        "test-001",
		Method:    "sign_event",
		EventJSON: eventJSON,
	}
	
	// Send request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(request); err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	
	// Read response
	decoder := json.NewDecoder(conn)
	var response SignResponse
	if err := decoder.Decode(&response); err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}
	
	// Check for errors
	if response.Error != "" {
		return "", fmt.Errorf("daemon error: %s", response.Error)
	}
	
	return response.Signature, nil
}

// testDaemonSigning tests signing via daemon
func testDaemonSigning() {
	fmt.Println("🔗 Testing daemon signing...")

	// Create test event JSON
	testEventJSON := `{"content":"test event","kind":1,"tags":[],"created_at":1694198400}`

	// Sign via daemon
	signature, err := signEventViaSocket(testEventJSON)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("✅ Daemon signature: %s\n", signature)
	fmt.Println("Daemon signing working correctly!")
}

// isDaemonRunning checks if daemon is running by trying to connect
func isDaemonRunning() bool {
	conn, err := dialConnection()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// switchAccountViaDaemon tells the running daemon to switch accounts
func switchAccountViaDaemon(npub, password string) error {
	conn, err := dialConnection()
	if err != nil {
		return fmt.Errorf("daemon not running: %v", err)
	}
	defer conn.Close()

	// Create switch request
	request := SignRequest{
		ID:       "switch-001",
		Method:   "switch_account",
		Npub:     npub,
		Password: password,
	}

	// Send request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(request); err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var response AccountActionResponse
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if response.Error != "" {
		return fmt.Errorf("%s", response.Error)
	}

	return nil
}