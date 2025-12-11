package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// getAutostartStatus checks if autostart is currently enabled
func getAutostartStatus() (bool, error) {
	switch runtime.GOOS {
	case "darwin":
		return getAutostartStatusMac()
	case "linux":
		return getAutostartStatusLinux()
	default:
		return false, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// enableAutostart installs autostart for the current platform
func enableAutostart() error {
	switch runtime.GOOS {
	case "darwin":
		return enableAutostartMac()
	case "linux":
		return enableAutostartLinux()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// disableAutostart removes autostart for the current platform
func disableAutostart() error {
	switch runtime.GOOS {
	case "darwin":
		return disableAutostartMac()
	case "linux":
		return disableAutostartLinux()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// macOS: LaunchAgent plist
func getAutostartStatusMac() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.noorsigner.daemon.plist")
	_, err = os.Stat(plistPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func enableAutostartMac() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Get path to current executable
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	plistPath := filepath.Join(plistDir, "com.noorsigner.daemon.plist")

	// Ensure LaunchAgents directory exists
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return err
	}

	// Create plist content
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.noorsigner.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>%s/Library/Logs/noorsigner-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>%s/Library/Logs/noorsigner-stderr.log</string>
</dict>
</plist>`, exePath, home, home)

	// Write plist file
	return os.WriteFile(plistPath, []byte(plist), 0644)
}

func disableAutostartMac() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.noorsigner.daemon.plist")

	// Remove file (ignore if doesn't exist)
	err = os.Remove(plistPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Linux: XDG autostart
func getAutostartStatusLinux() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}

	desktopPath := filepath.Join(home, ".config", "autostart", "noorsigner.desktop")
	_, err = os.Stat(desktopPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func enableAutostartLinux() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Get path to current executable
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	autostartDir := filepath.Join(home, ".config", "autostart")
	desktopPath := filepath.Join(autostartDir, "noorsigner.desktop")

	// Ensure autostart directory exists
	if err := os.MkdirAll(autostartDir, 0755); err != nil {
		return err
	}

	// Create desktop entry
	desktop := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=NoorSigner Daemon
Comment=Nostr Key Signing Daemon
Exec=%s daemon
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true`, exePath)

	// Write desktop file
	return os.WriteFile(desktopPath, []byte(desktop), 0644)
}

func disableAutostartLinux() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	desktopPath := filepath.Join(home, ".config", "autostart", "noorsigner.desktop")

	// Remove file (ignore if doesn't exist)
	err = os.Remove(desktopPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
