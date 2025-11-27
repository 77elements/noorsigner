package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// nsecToPrivateKey converts nsec (hex or bech32) to private key
func nsecToPrivateKey(nsec string) (*btcec.PrivateKey, error) {
	var keyBytes []byte
	var err error
	
	if strings.HasPrefix(nsec, "nsec1") {
		// Decode bech32 nsec format
		_, data, err := bech32.Decode(nsec)
		if err != nil {
			return nil, fmt.Errorf("invalid bech32 nsec: %v", err)
		}
		
		// Convert from 5-bit to 8-bit encoding
		keyBytes, err = bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, fmt.Errorf("bech32 conversion failed: %v", err)
		}
	} else {
		// Decode hex format
		keyBytes, err = hex.DecodeString(nsec)
		if err != nil {
			return nil, fmt.Errorf("invalid hex nsec: %v", err)
		}
	}
	
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("nsec must be 32 bytes, got %d", len(keyBytes))
	}
	
	privateKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	return privateKey, nil
}

// privateKeyToNpub converts private key to npub (bech32 format)
func privateKeyToNpub(privateKey *btcec.PrivateKey) string {
	pubKeyBytes := schnorr.SerializePubKey(privateKey.PubKey())
	
	// Convert to 5-bit encoding for bech32
	converted, err := bech32.ConvertBits(pubKeyBytes, 8, 5, true)
	if err != nil {
		// Fallback to hex if conversion fails
		return hex.EncodeToString(pubKeyBytes)
	}
	
	// Encode as bech32 with "npub" prefix
	npub, err := bech32.Encode("npub", converted)
	if err != nil {
		// Fallback to hex if encoding fails
		return hex.EncodeToString(pubKeyBytes)
	}
	
	return npub
}

// signNostrEvent signs a Nostr event with Schnorr signature
func signNostrEvent(privateKey *btcec.PrivateKey, eventHash []byte) (string, error) {
	signature, err := schnorr.Sign(privateKey, eventHash)
	if err != nil {
		return "", fmt.Errorf("schnorr signing failed: %v", err)
	}
	
	return hex.EncodeToString(signature.Serialize()), nil
}

// createEventHash creates SHA256 hash of serialized Nostr event per NIP-01
// NIP-01 specifies: hash = SHA256(serialize([0, pubkey, created_at, kind, tags, content]))
func createEventHash(eventJSON string) ([]byte, error) {
	// Parse the event JSON
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return nil, fmt.Errorf("invalid event JSON: %v", err)
	}

	// Extract fields (per NIP-01 specification)
	pubkey, ok := event["pubkey"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid pubkey field")
	}

	createdAt, ok := event["created_at"].(float64) // JSON numbers are float64
	if !ok {
		return nil, fmt.Errorf("missing or invalid created_at field")
	}

	kind, ok := event["kind"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing or invalid kind field")
	}

	tags, ok := event["tags"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid tags field")
	}

	content, ok := event["content"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid content field")
	}

	// Build serialization array per NIP-01: [0, pubkey, created_at, kind, tags, content]
	serialization := []interface{}{
		0,
		pubkey,
		int64(createdAt),
		int64(kind),
		tags,
		content,
	}

	// Marshal to compact JSON (no whitespace, no HTML escaping)
	// IMPORTANT: Use encoder with SetEscapeHTML(false) to match JavaScript's JSON.stringify
	// Go's json.Marshal() escapes <, >, & as \u003c, \u003e, \u0026 by default
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(serialization); err != nil {
		return nil, fmt.Errorf("serialization failed: %v", err)
	}

	// Remove trailing newline added by Encode()
	serialized := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	// SHA-256 hash of serialized array
	hash := sha256.Sum256(serialized)
	return hash[:], nil
}

// generateTestEventHash creates a test hash for signing verification
func generateTestEventHash() []byte {
	testData := "test event data for signing"
	hash := sha256.Sum256([]byte(testData))
	return hash[:]
}

// nip44Encrypt encrypts plaintext for a recipient using NIP-44
func nip44Encrypt(plaintext string, recipientPubkey string, senderPrivateKey *btcec.PrivateKey) (string, error) {
	// Get sender private key as hex
	senderPrivateKeyHex := hex.EncodeToString(senderPrivateKey.Serialize())

	// Generate conversation key (shared secret)
	conversationKey, err := nip44.GenerateConversationKey(recipientPubkey, senderPrivateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to generate conversation key: %v", err)
	}

	// Encrypt plaintext
	encrypted, err := nip44.Encrypt(plaintext, conversationKey)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %v", err)
	}

	return encrypted, nil
}

// nip44Decrypt decrypts NIP-44 encrypted payload from a sender
func nip44Decrypt(payload string, senderPubkey string, recipientPrivateKey *btcec.PrivateKey) (string, error) {
	// Get recipient private key as hex
	recipientPrivateKeyHex := hex.EncodeToString(recipientPrivateKey.Serialize())

	// Generate conversation key (shared secret)
	conversationKey, err := nip44.GenerateConversationKey(senderPubkey, recipientPrivateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to generate conversation key: %v", err)
	}

	// Decrypt payload
	plaintext, err := nip44.Decrypt(payload, conversationKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, nil
}

// nip04Encrypt encrypts plaintext for a recipient using NIP-04 (AES-256-CBC)
func nip04Encrypt(plaintext string, recipientPubkey string, senderPrivateKey *btcec.PrivateKey) (string, error) {
	// Get sender private key as hex
	senderPrivateKeyHex := hex.EncodeToString(senderPrivateKey.Serialize())

	// Compute shared secret (ECDH)
	sharedSecret, err := nip04.ComputeSharedSecret(recipientPubkey, senderPrivateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %v", err)
	}

	// Encrypt plaintext with AES-256-CBC
	encrypted, err := nip04.Encrypt(plaintext, sharedSecret)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %v", err)
	}

	return encrypted, nil
}

// nip04Decrypt decrypts NIP-04 encrypted payload from a sender
func nip04Decrypt(payload string, senderPubkey string, recipientPrivateKey *btcec.PrivateKey) (string, error) {
	// Get recipient private key as hex
	recipientPrivateKeyHex := hex.EncodeToString(recipientPrivateKey.Serialize())

	// Compute shared secret (ECDH)
	sharedSecret, err := nip04.ComputeSharedSecret(senderPubkey, recipientPrivateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %v", err)
	}

	// Decrypt payload with AES-256-CBC
	plaintext, err := nip04.Decrypt(payload, sharedSecret)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, nil
}