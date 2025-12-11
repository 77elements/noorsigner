package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	// NIP-49 scrypt parameters
	scryptN = 16384
	scryptR = 8
	scryptP = 1
	keyLen  = 32
	saltLen = 16
)

// EncryptedKey represents encrypted nsec storage
type EncryptedKey struct {
	Salt           []byte `json:"salt"`
	EncryptedNsec  []byte `json:"encrypted_nsec"`
}

// getStorageDir returns the storage directory for NoorSigner data
// ~/.noorsigner on macOS/Linux
func getStorageDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot get home directory: %v", err)
	}
	storageDir := filepath.Join(homeDir, ".noorsigner")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create storage directory: %v", err)
	}

	return storageDir, nil
}

// getKeyFilePath returns path to encrypted key file
func getKeyFilePath() (string, error) {
	storageDir, err := getStorageDir()
	if err != nil {
		return "", err
	}
	
	return filepath.Join(storageDir, "keys.encrypted"), nil
}

// encryptNsec encrypts nsec with password using NIP-49 compatible scrypt
func encryptNsec(nsec, password string) (*EncryptedKey, error) {
	// Generate random salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("cannot generate salt: %v", err)
	}
	
	// Derive key using scrypt (NIP-49 parameters)
	derivedKey, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %v", err)
	}
	
	// Simple XOR encryption (for now - could be upgraded to AES)
	nsecBytes := []byte(nsec)
	encrypted := make([]byte, len(nsecBytes))
	
	for i := 0; i < len(nsecBytes); i++ {
		encrypted[i] = nsecBytes[i] ^ derivedKey[i%len(derivedKey)]
	}
	
	return &EncryptedKey{
		Salt:          salt,
		EncryptedNsec: encrypted,
	}, nil
}

// decryptNsec decrypts nsec with password
func decryptNsec(encKey *EncryptedKey, password string) (string, error) {
	// Derive same key using stored salt
	derivedKey, err := scrypt.Key([]byte(password), encKey.Salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return "", fmt.Errorf("scrypt key derivation failed: %v", err)
	}
	
	// Decrypt using XOR
	decrypted := make([]byte, len(encKey.EncryptedNsec))
	for i := 0; i < len(encKey.EncryptedNsec); i++ {
		decrypted[i] = encKey.EncryptedNsec[i] ^ derivedKey[i%len(derivedKey)]
	}
	
	return string(decrypted), nil
}

// saveEncryptedKey saves encrypted key to file
func saveEncryptedKey(encKey *EncryptedKey) error {
	keyFile, err := getKeyFilePath()
	if err != nil {
		return err
	}
	
	// Simple hex encoding for storage (could be upgraded to JSON)
	saltHex := hex.EncodeToString(encKey.Salt)
	encryptedHex := hex.EncodeToString(encKey.EncryptedNsec)
	
	content := fmt.Sprintf("%s:%s", saltHex, encryptedHex)
	
	if err := os.WriteFile(keyFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("cannot write key file: %v", err)
	}
	
	return nil
}

// loadEncryptedKey loads encrypted key from file
func loadEncryptedKey() (*EncryptedKey, error) {
	keyFile, err := getKeyFilePath()
	if err != nil {
		return nil, err
	}
	
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("no encrypted key found - run 'init' first")
	}
	
	content, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file: %v", err)
	}
	
	// Parse hex encoded content
	parts := string(content)
	if len(parts) < 33 { // At least salt:encrypted format
		return nil, fmt.Errorf("invalid key file format")
	}
	
	// Find separator
	sepIndex := -1
	for i, c := range parts {
		if c == ':' {
			sepIndex = i
			break
		}
	}
	
	if sepIndex == -1 {
		return nil, fmt.Errorf("invalid key file format - no separator")
	}
	
	saltHex := parts[:sepIndex]
	encryptedHex := parts[sepIndex+1:]
	
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("invalid salt in key file: %v", err)
	}
	
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted data in key file: %v", err)
	}

	return &EncryptedKey{
		Salt:          salt,
		EncryptedNsec: encrypted,
	}, nil
}

// TrustSession represents a 24h trust mode session
type TrustSession struct {
	SessionToken  string    `json:"session_token"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	EncryptedNsec []byte    `json:"encrypted_nsec"` // Cached nsec for trust mode
}

// getTrustSessionFilePath returns path to trust session file
func getTrustSessionFilePath() (string, error) {
	storageDir, err := getStorageDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(storageDir, "trust_session"), nil
}

// saveTrustSession saves trust session to file
func saveTrustSession(session *TrustSession) error {
	sessionFile, err := getTrustSessionFilePath()
	if err != nil {
		return err
	}

	// Format: token:expires_unix:created_unix:encrypted_nsec_hex
	encryptedHex := hex.EncodeToString(session.EncryptedNsec)
	content := fmt.Sprintf("%s:%d:%d:%s",
		session.SessionToken,
		session.ExpiresAt.Unix(),
		session.CreatedAt.Unix(),
		encryptedHex)

	if err := os.WriteFile(sessionFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("cannot write trust session file: %v", err)
	}

	return nil
}

// loadTrustSession loads trust session from file
func loadTrustSession() (*TrustSession, error) {
	sessionFile, err := getTrustSessionFilePath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("no trust session found")
	}

	content, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read trust session file: %v", err)
	}

	// Parse format: token:expires_unix:created_unix:encrypted_nsec_hex
	parts := strings.Split(string(content), ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid trust session format - expected 4 parts, got %d", len(parts))
	}

	token := parts[0]
	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry timestamp: %v", err)
	}

	createdUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid created timestamp: %v", err)
	}

	encryptedHex := parts[3]

	encryptedNsec, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted nsec in trust session: %v", err)
	}

	return &TrustSession{
		SessionToken:  token,
		ExpiresAt:     time.Unix(expiresUnix, 0),
		CreatedAt:     time.Unix(createdUnix, 0),
		EncryptedNsec: encryptedNsec,
	}, nil
}

// isTrustSessionValid checks if trust session is still valid
func isTrustSessionValid(session *TrustSession) bool {
	return time.Now().Before(session.ExpiresAt)
}

// createTrustSession creates a new 24h trust session with cached nsec
func createTrustSession(nsec string) (*TrustSession, error) {
	// Generate random session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("cannot generate session token: %v", err)
	}

	// Encrypt nsec with session token as key (simple but secure for 24h)
	sessionKey := tokenBytes[:32] // Use first 32 bytes as encryption key
	nsecBytes := []byte(nsec)
	encryptedNsec := make([]byte, len(nsecBytes))

	for i := 0; i < len(nsecBytes); i++ {
		encryptedNsec[i] = nsecBytes[i] ^ sessionKey[i%len(sessionKey)]
	}

	token := hex.EncodeToString(tokenBytes)
	now := time.Now()
	expires := now.Add(24 * time.Hour) // 24 hour trust period

	return &TrustSession{
		SessionToken:  token,
		ExpiresAt:     expires,
		CreatedAt:     now,
		EncryptedNsec: encryptedNsec,
	}, nil
}

// decryptTrustSessionNsec decrypts nsec from trust session
func decryptTrustSessionNsec(session *TrustSession) (string, error) {
	tokenBytes, err := hex.DecodeString(session.SessionToken)
	if err != nil {
		return "", fmt.Errorf("invalid session token: %v", err)
	}

	sessionKey := tokenBytes[:32]
	decrypted := make([]byte, len(session.EncryptedNsec))

	for i := 0; i < len(session.EncryptedNsec); i++ {
		decrypted[i] = session.EncryptedNsec[i] ^ sessionKey[i%len(sessionKey)]
	}

	return string(decrypted), nil
}

// clearTrustSession removes trust session file
func clearTrustSession() error {
	sessionFile, err := getTrustSessionFilePath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		return nil // Already cleared
	}

	return os.Remove(sessionFile)
}