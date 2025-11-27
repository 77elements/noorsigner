package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// readPassword reads password from terminal without echo
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	
	// Read password without echoing to terminal
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("error reading password: %v", err)
	}
	
	fmt.Println() // Print newline after password input
	return string(bytePassword), nil
}

// readInput reads normal input with prompt
func readInput(prompt string) (string, error) {
	fmt.Print(prompt)
	
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading input: %v", err)
	}
	
	return strings.TrimSpace(input), nil
}

// readPasswordWithTrustMode reads password with trust mode indication
func readPasswordWithTrustMode(prompt string) (string, error) {
	return readPassword(prompt)
}