//go:build !windows

package main

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}

// getSocketPath returns the path to the Unix domain socket
func getSocketPath() (string, error) {
	storageDir, err := getStorageDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(storageDir, "noorsigner.sock"), nil
}

// createListener creates a Unix domain socket listener
func createListener() (net.Listener, error) {
	socketPath, err := getSocketPath()
	if err != nil {
		return nil, err
	}

	// Remove existing socket if it exists
	os.Remove(socketPath)

	// Create Unix Domain Socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	// Set socket permissions (only user can access)
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return nil, err
	}

	return listener, nil
}

// cleanupListener removes the Unix socket file
func cleanupListener() {
	if socketPath, err := getSocketPath(); err == nil {
		os.Remove(socketPath)
	}
}

// dialConnection connects to the daemon via Unix socket
func dialConnection() (net.Conn, error) {
	socketPath, err := getSocketPath()
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", socketPath)
}
