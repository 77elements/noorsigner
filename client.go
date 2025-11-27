package main

import (
	"encoding/json"
	"fmt"
	"net"
)

// signEventViaSocket sends signing request to daemon via Unix socket
func signEventViaSocket(eventJSON string) (string, error) {
	socketPath, err := getSocketPath()
	if err != nil {
		return "", fmt.Errorf("failed to get socket path: %v", err)
	}

	// Connect to daemon socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("failed to connect to daemon: %v\nIs the daemon running? Try: key-signer daemon", err)
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