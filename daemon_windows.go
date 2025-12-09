//go:build windows

package main

import (
	"net"
	"syscall"

	"github.com/Microsoft/go-winio"
)

// DETACHED_PROCESS - process is not attached to a console
const DETACHED_PROCESS = 0x00000008

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
	}
}

// getSocketPath returns the named pipe path for Windows
func getSocketPath() (string, error) {
	return `\\.\pipe\noorsigner`, nil
}

// createListener creates a Named Pipe listener
func createListener() (net.Listener, error) {
	pipePath := `\\.\pipe\noorsigner`
	// Default security allows only the current user to connect
	return winio.ListenPipe(pipePath, nil)
}

// cleanupListener - Named Pipes don't need cleanup on Windows
func cleanupListener() {
	// Windows Named Pipes are automatically cleaned up when the process exits
}

// dialConnection connects to the daemon via Named Pipe
func dialConnection() (net.Conn, error) {
	pipePath := `\\.\pipe\noorsigner`
	return winio.DialPipe(pipePath, nil)
}
