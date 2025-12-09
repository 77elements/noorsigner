package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// AccountInfo represents metadata about a stored account
type AccountInfo struct {
	Npub      string    `json:"npub"`
	Pubkey    string    `json:"pubkey"`
	CreatedAt time.Time `json:"created_at"`
}

// getAccountsDir returns ~/.noorsigner/accounts/ directory
func getAccountsDir() (string, error) {
	storageDir, err := getStorageDir()
	if err != nil {
		return "", err
	}

	accountsDir := filepath.Join(storageDir, "accounts")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(accountsDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create accounts directory: %v", err)
	}

	return accountsDir, nil
}

// getAccountDir returns ~/.noorsigner/accounts/<npub>/ directory for a specific account
func getAccountDir(npub string) (string, error) {
	accountsDir, err := getAccountsDir()
	if err != nil {
		return "", err
	}

	// Sanitize npub for filesystem (npub1... is safe, but just in case)
	safeNpub := sanitizeNpubForPath(npub)
	accountDir := filepath.Join(accountsDir, safeNpub)

	return accountDir, nil
}

// sanitizeNpubForPath ensures npub is safe for filesystem path
func sanitizeNpubForPath(npub string) string {
	// npub1... format is already safe, but truncate to reasonable length
	// Full npub is ~63 chars, which is fine for most filesystems
	if len(npub) > 70 {
		return npub[:70]
	}
	return npub
}

// getAccountKeyFilePath returns path to encrypted key file for an account
func getAccountKeyFilePath(npub string) (string, error) {
	accountDir, err := getAccountDir(npub)
	if err != nil {
		return "", err
	}

	return filepath.Join(accountDir, "keys.encrypted"), nil
}

// getAccountTrustSessionFilePath returns path to trust session file for an account
func getAccountTrustSessionFilePath(npub string) (string, error) {
	accountDir, err := getAccountDir(npub)
	if err != nil {
		return "", err
	}

	return filepath.Join(accountDir, "trust_session"), nil
}

// getActiveAccountFilePath returns path to active_account file
func getActiveAccountFilePath() (string, error) {
	storageDir, err := getStorageDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(storageDir, "active_account"), nil
}

// saveActiveAccount saves the active account npub to file
func saveActiveAccount(npub string) error {
	filePath, err := getActiveAccountFilePath()
	if err != nil {
		return err
	}

	if err := os.WriteFile(filePath, []byte(npub), 0600); err != nil {
		return fmt.Errorf("cannot write active account file: %v", err)
	}

	return nil
}

// loadActiveAccount loads the active account npub from file
func loadActiveAccount() (string, error) {
	filePath, err := getActiveAccountFilePath()
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("no active account set")
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot read active account file: %v", err)
	}

	return strings.TrimSpace(string(content)), nil
}

// listAccounts returns all stored accounts
func listAccounts() ([]AccountInfo, error) {
	accountsDir, err := getAccountsDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(accountsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []AccountInfo{}, nil
		}
		return nil, fmt.Errorf("cannot read accounts directory: %v", err)
	}

	var accounts []AccountInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		npub := entry.Name()
		if !strings.HasPrefix(npub, "npub1") {
			continue // Skip non-npub directories
		}

		// Get creation time from directory
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Derive pubkey from npub
		pubkey, err := npubToPubkey(npub)
		if err != nil {
			continue
		}

		accounts = append(accounts, AccountInfo{
			Npub:      npub,
			Pubkey:    pubkey,
			CreatedAt: info.ModTime(),
		})
	}

	return accounts, nil
}

// accountExists checks if an account exists
func accountExists(npub string) bool {
	accountDir, err := getAccountDir(npub)
	if err != nil {
		return false
	}

	keyFile := filepath.Join(accountDir, "keys.encrypted")
	_, err = os.Stat(keyFile)
	return err == nil
}

// saveAccountEncryptedKey saves encrypted key for an account
func saveAccountEncryptedKey(npub string, encKey *EncryptedKey) error {
	accountDir, err := getAccountDir(npub)
	if err != nil {
		return err
	}

	// Create account directory
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return fmt.Errorf("cannot create account directory: %v", err)
	}

	keyFile := filepath.Join(accountDir, "keys.encrypted")

	// Simple hex encoding for storage
	saltHex := encodeHex(encKey.Salt)
	encryptedHex := encodeHex(encKey.EncryptedNsec)

	content := fmt.Sprintf("%s:%s", saltHex, encryptedHex)

	if err := os.WriteFile(keyFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("cannot write account key file: %v", err)
	}

	return nil
}

// loadAccountEncryptedKey loads encrypted key for an account
func loadAccountEncryptedKey(npub string) (*EncryptedKey, error) {
	keyFile, err := getAccountKeyFilePath(npub)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("account not found: %s", npub)
	}

	content, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read account key file: %v", err)
	}

	// Parse hex encoded content
	parts := strings.SplitN(string(content), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid account key file format")
	}

	salt, err := decodeHex(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid salt in account key file: %v", err)
	}

	encrypted, err := decodeHex(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted data in account key file: %v", err)
	}

	return &EncryptedKey{
		Salt:          salt,
		EncryptedNsec: encrypted,
	}, nil
}

// saveAccountTrustSession saves trust session for an account
func saveAccountTrustSession(npub string, session *TrustSession) error {
	sessionFile, err := getAccountTrustSessionFilePath(npub)
	if err != nil {
		return err
	}

	// Format: token:expires_unix:created_unix:encrypted_nsec_hex
	encryptedHex := encodeHex(session.EncryptedNsec)
	content := fmt.Sprintf("%s:%d:%d:%s",
		session.SessionToken,
		session.ExpiresAt.Unix(),
		session.CreatedAt.Unix(),
		encryptedHex)

	if err := os.WriteFile(sessionFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("cannot write account trust session file: %v", err)
	}

	return nil
}

// loadAccountTrustSession loads trust session for an account
func loadAccountTrustSession(npub string) (*TrustSession, error) {
	sessionFile, err := getAccountTrustSessionFilePath(npub)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("no trust session for account: %s", npub)
	}

	content, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read account trust session file: %v", err)
	}

	// Parse format: token:expires_unix:created_unix:encrypted_nsec_hex
	parts := strings.Split(string(content), ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid account trust session format")
	}

	expiresUnix, err := parseInt64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid expiry timestamp: %v", err)
	}

	createdUnix, err := parseInt64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid created timestamp: %v", err)
	}

	encryptedNsec, err := decodeHex(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted nsec: %v", err)
	}

	return &TrustSession{
		SessionToken:  parts[0],
		ExpiresAt:     time.Unix(expiresUnix, 0),
		CreatedAt:     time.Unix(createdUnix, 0),
		EncryptedNsec: encryptedNsec,
	}, nil
}

// clearAccountTrustSession removes trust session for an account
func clearAccountTrustSession(npub string) error {
	sessionFile, err := getAccountTrustSessionFilePath(npub)
	if err != nil {
		return err
	}

	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		return nil // Already cleared
	}

	return os.Remove(sessionFile)
}

// removeAccount removes an account and all its data
func removeAccount(npub string) error {
	accountDir, err := getAccountDir(npub)
	if err != nil {
		return err
	}

	if _, err := os.Stat(accountDir); os.IsNotExist(err) {
		return fmt.Errorf("account not found: %s", npub)
	}

	// Remove entire account directory
	if err := os.RemoveAll(accountDir); err != nil {
		return fmt.Errorf("cannot remove account: %v", err)
	}

	// If this was the active account, clear active_account file
	activeNpub, err := loadActiveAccount()
	if err == nil && activeNpub == npub {
		activeFile, _ := getActiveAccountFilePath()
		os.Remove(activeFile)
	}

	return nil
}

// migrateToMultiAccount migrates from old single-account format to new multi-account format
func migrateToMultiAccount() error {
	storageDir, err := getStorageDir()
	if err != nil {
		return err
	}

	oldKeyFile := filepath.Join(storageDir, "keys.encrypted")
	oldTrustFile := filepath.Join(storageDir, "trust_session")

	// Check if old format exists
	if _, err := os.Stat(oldKeyFile); os.IsNotExist(err) {
		// No old format, nothing to migrate
		return nil
	}

	// Check if already migrated (accounts dir exists with content)
	accounts, _ := listAccounts()
	if len(accounts) > 0 {
		// Already migrated, clean up old files if they exist
		os.Remove(oldKeyFile)
		os.Remove(oldTrustFile)
		return nil
	}

	fmt.Println("🔄 Migrating to multi-account format...")

	// Load old encrypted key
	encKey, err := loadEncryptedKey()
	if err != nil {
		return fmt.Errorf("cannot load old key for migration: %v", err)
	}

	// We need to decrypt to get the npub
	// Ask for password
	password, err := readPassword("Enter password to migrate existing key: ")
	if err != nil {
		return fmt.Errorf("cannot read password: %v", err)
	}

	nsec, err := decryptNsec(encKey, password)
	if err != nil {
		return fmt.Errorf("invalid password or corrupted key: %v", err)
	}

	// Get npub from nsec
	privateKey, err := nsecToPrivateKey(nsec)
	if err != nil {
		return fmt.Errorf("invalid nsec: %v", err)
	}
	npub := privateKeyToNpub(privateKey)

	// Save to new location
	if err := saveAccountEncryptedKey(npub, encKey); err != nil {
		return fmt.Errorf("cannot save migrated key: %v", err)
	}

	// Migrate trust session if exists
	if _, err := os.Stat(oldTrustFile); err == nil {
		oldSession, err := loadTrustSession()
		if err == nil {
			saveAccountTrustSession(npub, oldSession)
		}
	}

	// Set as active account
	if err := saveActiveAccount(npub); err != nil {
		return fmt.Errorf("cannot set active account: %v", err)
	}

	// Remove old files
	os.Remove(oldKeyFile)
	os.Remove(oldTrustFile)

	fmt.Printf("✅ Migrated account: %s\n", npub)
	return nil
}

// Helper functions

func encodeHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex string")
	}

	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high, err := hexCharToNibble(s[i])
		if err != nil {
			return nil, err
		}
		low, err := hexCharToNibble(s[i+1])
		if err != nil {
			return nil, err
		}
		result[i/2] = (high << 4) | low
	}
	return result, nil
}

func hexCharToNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character: %c", c)
	}
}

func parseInt64(s string) (int64, error) {
	var result int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid digit: %c", c)
		}
		result = result*10 + int64(c-'0')
	}
	return result, nil
}

// npubToPubkey converts npub to hex pubkey
func npubToPubkey(npub string) (string, error) {
	if !strings.HasPrefix(npub, "npub1") {
		return "", fmt.Errorf("invalid npub format")
	}

	// Decode bech32 using btcutil/bech32
	_, data, err := bech32.Decode(npub)
	if err != nil {
		return "", fmt.Errorf("invalid bech32: %v", err)
	}

	// Convert 5-bit to 8-bit
	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", fmt.Errorf("bit conversion failed: %v", err)
	}

	return encodeHex(converted), nil
}
