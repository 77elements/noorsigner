# NoorSigner - Secure Key Signer for Nostr

NoorSigner keeps your Nostr private keys safe. It runs in the background and signs messages for your Nostr apps - your keys never leave your computer.

---

## User Guide

### First Time Setup

**Step 1: Add your first account**

```bash
./noorsigner add-account
```

You'll be asked for:
1. Your nsec (private key) - input is hidden for security
2. A password (8+ characters) - used to encrypt your key

That's it! Your key is now safely stored.

**Step 2: Start the daemon**

```bash
./noorsigner daemon
```

Enter your password when asked. The daemon will run in the background - you can close the terminal.

Your Nostr app can now use NoorSigner for signing!

---

### Adding More Accounts

Want to use multiple Nostr identities? Just add more accounts:

```bash
./noorsigner add-account
```

Each account has its own password.

---

### Switching Between Accounts

See all your accounts:

```bash
./noorsigner list-accounts
```

Output shows which account is active (*):

```
Stored accounts:

* npub1abc...  (active)
  npub1def...

Total: 2 account(s)
```

Switch to a different account:

```bash
./noorsigner switch npub1def...
```

Enter the password for that account. If the daemon is running, restart it to use the new account.

---

### Removing an Account

```bash
./noorsigner remove-account npub1def...
```

You'll need to enter the account's password to confirm.

---

### Daily Usage

Once set up, just start the daemon:

```bash
./noorsigner daemon
```

- If you used NoorSigner in the last 24 hours: No password needed!
- After 24 hours or a reboot: Enter your password once

The daemon stays running in the background. Your Nostr app handles the rest.

---

### Commands Overview

| Command | What it does |
|---------|--------------|
| `add-account` | Add a new Nostr account |
| `list-accounts` | Show all accounts |
| `switch <npub>` | Switch to another account |
| `remove-account <npub>` | Delete an account |
| `daemon` | Start the background signer |

---
---

# Technical Documentation

*The following sections are for developers and advanced users.*

---

## Features

- 🔐 **Secure Key Storage**: NIP-49 compatible scrypt encryption
- 👥 **Multi-Account Support**: Manage multiple Nostr identities
- 🛡️ **Trust Mode**: 24-hour authentication caching per account
- 🔑 **NIP-44 & NIP-04**: Encryption/decryption for DMs
- 🔌 **Unix Socket IPC**: Fast, secure local communication
- 🖥️ **Cross-Platform**: macOS, Linux, Windows support
- 🔒 **Memory Safety**: Keys cleared from memory after use
- 🔄 **Background Daemon**: Fork-based process isolation
- 🚀 **Live Account Switching**: Switch accounts without restarting daemon

---

## Quick Start (Developer)

### 1. Add First Account

```bash
./noorsigner add-account
```

This will:
- Prompt for your nsec (private key, hidden input)
- Ask for an encryption password (8+ characters)
- Save encrypted key to `~/.noorsigner/accounts/<npub>/keys.encrypted`
- Set this as the active account

**Note**: `noorsigner init` is an alias for `add-account` when no accounts exist.

### 2. Start Daemon

```bash
./noorsigner daemon
```

This will:
- Prompt for your encryption password (if Trust Mode expired)
- Create a Trust Mode session (24 hours)
- Fork to background
- Create Unix socket at `~/.noorsigner/noorsigner.sock`

### 3. Connect from Client

Your Nostr client can now communicate with the daemon via the Unix socket.

---

## CLI Commands

### Account Management

```bash
# Add a new account
noorsigner add-account

# List all accounts (* = active)
noorsigner list-accounts

# Switch to a different account
noorsigner switch <npub>

# Remove an account (requires password confirmation)
noorsigner remove-account <npub>

# Initialize (alias for add-account, first account only)
noorsigner init
```

### Daemon

```bash
# Start the signing daemon
noorsigner daemon
```

### Testing & Debugging

```bash
# Sign event with stored key (requires password)
noorsigner sign

# Test signing via daemon
noorsigner test-daemon

# Test signing with direct nsec input
noorsigner test <nsec>
```

---

## Multi-Account System

### File Structure

```
~/.noorsigner/
├── accounts/
│   ├── npub1abc.../
│   │   ├── keys.encrypted    # Encrypted nsec
│   │   └── trust_session     # 24h password cache
│   └── npub1def.../
│       ├── keys.encrypted
│       └── trust_session
├── active_account            # Currently active npub
└── noorsigner.sock           # Daemon socket (shared)
```

### How It Works

1. Each account has its own directory under `accounts/`
2. Each account has separate encryption password
3. Each account has its own Trust Mode session
4. One daemon instance serves all accounts
5. Live account switching via API (password required)

### Migration from Single-Account

When upgrading from an older single-account NoorSigner:
- Run any command (e.g., `noorsigner daemon`)
- Enter your password when prompted
- Old key is migrated to new structure automatically
- Old files are removed after successful migration

---

## API Documentation

### Protocol

**Transport**: Unix Domain Socket (JSON newline-delimited)

**Socket Paths**:
- **macOS/Linux**: `~/.noorsigner/noorsigner.sock`
- **Windows**: `\\.\pipe\noorsigner` (Named Pipe)

**Request Format**:
```json
{
  "id": "unique-request-id",
  "method": "method_name",
  ...additional fields per method
}
```

---

### Core Methods

#### `get_npub`

Get the public key (npub) of the currently active account.

**Request**:
```json
{
  "id": "req-001",
  "method": "get_npub"
}
```

**Response**:
```json
{
  "id": "req-001",
  "signature": "npub1..."
}
```

---

#### `sign_event`

Sign a Nostr event (NIP-01).

**Request**:
```json
{
  "id": "req-002",
  "method": "sign_event",
  "event_json": "{\"content\":\"Hello\",\"kind\":1,\"tags\":[],\"created_at\":1234567890}"
}
```

**Response**:
```json
{
  "id": "req-002",
  "signature": "hex-schnorr-signature"
}
```

---

### Encryption Methods

#### `nip44_encrypt`

Encrypt plaintext using NIP-44 (modern encryption).

**Request**:
```json
{
  "id": "req-003",
  "method": "nip44_encrypt",
  "plaintext": "Secret message",
  "recipient_pubkey": "hex-pubkey-of-recipient"
}
```

**Response**:
```json
{
  "id": "req-003",
  "signature": "encrypted-payload"
}
```

---

#### `nip44_decrypt`

Decrypt NIP-44 encrypted payload.

**Request**:
```json
{
  "id": "req-004",
  "method": "nip44_decrypt",
  "payload": "encrypted-payload",
  "sender_pubkey": "hex-pubkey-of-sender"
}
```

**Response**:
```json
{
  "id": "req-004",
  "signature": "Decrypted message"
}
```

---

#### `nip04_encrypt`

Encrypt plaintext using NIP-04 (deprecated but widely compatible).

**Request**:
```json
{
  "id": "req-005",
  "method": "nip04_encrypt",
  "plaintext": "Secret message",
  "recipient_pubkey": "hex-pubkey-of-recipient"
}
```

**Response**:
```json
{
  "id": "req-005",
  "signature": "encrypted-payload"
}
```

---

#### `nip04_decrypt`

Decrypt NIP-04 encrypted payload.

**Request**:
```json
{
  "id": "req-006",
  "method": "nip04_decrypt",
  "payload": "encrypted-payload",
  "sender_pubkey": "hex-pubkey-of-sender"
}
```

**Response**:
```json
{
  "id": "req-006",
  "signature": "Decrypted message"
}
```

---

### Multi-Account Methods

#### `list_accounts`

List all stored accounts with their metadata.

**Request**:
```json
{
  "id": "req-010",
  "method": "list_accounts"
}
```

**Response**:
```json
{
  "id": "req-010",
  "accounts": [
    {
      "pubkey": "abc123...",
      "npub": "npub1abc...",
      "created_at": 1234567890
    },
    {
      "pubkey": "def456...",
      "npub": "npub1def...",
      "created_at": 1234567891
    }
  ],
  "active_pubkey": "abc123..."
}
```

---

#### `add_account`

Add a new account to the daemon.

**Request**:
```json
{
  "id": "req-011",
  "method": "add_account",
  "nsec": "nsec1...",
  "password": "encryption-password",
  "set_active": true
}
```

**Response**:
```json
{
  "id": "req-011",
  "success": true,
  "pubkey": "abc123...",
  "npub": "npub1abc..."
}
```

**Error Response**:
```json
{
  "id": "req-011",
  "success": false,
  "error": "account already exists"
}
```

---

#### `switch_account`

Switch to a different account (loads new key into memory).

**Request** (by pubkey):
```json
{
  "id": "req-012",
  "method": "switch_account",
  "pubkey": "def456...",
  "password": "password-for-target-account"
}
```

**Request** (by npub):
```json
{
  "id": "req-012",
  "method": "switch_account",
  "npub": "npub1def...",
  "password": "password-for-target-account"
}
```

**Response**:
```json
{
  "id": "req-012",
  "success": true,
  "pubkey": "def456...",
  "npub": "npub1def..."
}
```

---

#### `remove_account`

Remove an account from storage.

**Request**:
```json
{
  "id": "req-013",
  "method": "remove_account",
  "pubkey": "def456...",
  "password": "password-for-this-account"
}
```

**Response**:
```json
{
  "id": "req-013",
  "success": true
}
```

**Error** (cannot remove active account):
```json
{
  "id": "req-013",
  "error": "cannot remove active account - switch to another account first"
}
```

---

#### `get_active_account`

Get currently active account info.

**Request**:
```json
{
  "id": "req-014",
  "method": "get_active_account"
}
```

**Response**:
```json
{
  "id": "req-014",
  "pubkey": "abc123...",
  "npub": "npub1abc...",
  "is_unlocked": true
}
```

---

### Daemon Control Methods

#### `shutdown_daemon`

Gracefully shutdown the daemon.

**Request**:
```json
{
  "id": "req-020",
  "method": "shutdown_daemon"
}
```

**Response**:
```json
{
  "id": "req-020",
  "signature": "success"
}
```

---

#### `enable_autostart`

Enable daemon autostart on system boot.

**Request**:
```json
{
  "id": "req-021",
  "method": "enable_autostart"
}
```

**Response**:
```json
{
  "id": "req-021",
  "signature": "success"
}
```

---

#### `disable_autostart`

Disable daemon autostart.

**Request**:
```json
{
  "id": "req-022",
  "method": "disable_autostart"
}
```

**Response**:
```json
{
  "id": "req-022",
  "signature": "success"
}
```

---

#### `get_autostart_status`

Check if autostart is enabled.

**Request**:
```json
{
  "id": "req-023",
  "method": "get_autostart_status"
}
```

**Response**:
```json
{
  "id": "req-023",
  "signature": "enabled"
}
```

or

```json
{
  "id": "req-023",
  "signature": "disabled"
}
```

---

## Client Integration Guide

### JavaScript/TypeScript Example

```typescript
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';

const socketPath = path.join(os.homedir(), '.noorsigner', 'noorsigner.sock');

function sendRequest(method: string, params: Record<string, any> = {}): Promise<any> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath);

    const request = {
      id: `req-${Date.now()}`,
      method,
      ...params
    };

    client.on('connect', () => {
      client.write(JSON.stringify(request) + '\n');
    });

    client.on('data', (data) => {
      const response = JSON.parse(data.toString());
      client.end();

      if (response.error) {
        reject(new Error(response.error));
      } else {
        resolve(response);
      }
    });

    client.on('error', reject);
  });
}

// Get current account
const active = await sendRequest('get_active_account');
console.log('Active account:', active.npub);

// List all accounts
const list = await sendRequest('list_accounts');
console.log('Accounts:', list.accounts.length);

// Switch account
const switched = await sendRequest('switch_account', {
  pubkey: 'target-pubkey-hex',
  password: 'password-for-target'
});

// Sign event
const signed = await sendRequest('sign_event', {
  event_json: JSON.stringify({
    content: 'Hello Nostr',
    kind: 1,
    tags: [],
    created_at: Math.floor(Date.now() / 1000)
  })
});
console.log('Signature:', signed.signature);
```

---

## Security Model

### Encryption

- **Key Storage**: NIP-49 compatible scrypt encryption (N=16384, r=8, p=1)
- **Per-Account Passwords**: Each account has its own encryption password
- **Trust Mode**: Session token encrypted with random 32-byte key
- **Memory Safety**: Keys zeroed out after use and on account switch

### Trust Mode (24 Hours)

When daemon starts or switches accounts:
- Caches the decrypted nsec encrypted with a random session token
- Expires after 24 hours from creation
- Stored in account-specific `trust_session` file
- Allows daemon to restart without password re-entry (within 24h)

**Security Trade-off**: Trust Mode trades security for convenience. Only use on devices you trust.

### Socket Permissions

The Unix socket is created with `0600` permissions (owner read/write only), preventing other users from accessing it.

### Account Switch Security

- Old private key is zeroed from memory before loading new key
- New account requires password verification
- New Trust Mode session created for switched account

---

## Platform-Specific Notes

### macOS
- Socket path: `~/.noorsigner/noorsigner.sock`
- Autostart: LaunchAgent (`~/Library/LaunchAgents/com.noorsigner.daemon.plist`)
- Daemon launches via Terminal.app when called from GUI

### Linux
- Socket path: `~/.noorsigner/noorsigner.sock`
- Autostart: XDG Autostart (`~/.config/autostart/noorsigner.desktop`)
- Same daemon behavior as macOS

### Windows
- Named Pipe: `\\.\pipe\noorsigner`
- Storage: `%APPDATA%\NoorSigner\`
- Daemon runs in background with `DETACHED_PROCESS` flag
- Autostart: Not yet implemented

#### Windows Named Pipe Example

```powershell
# PowerShell example to connect to NoorSigner
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "noorsigner", [System.IO.Pipes.PipeDirection]::InOut)
$pipe.Connect(5000)

$writer = New-Object System.IO.StreamWriter($pipe)
$reader = New-Object System.IO.StreamReader($pipe)

# Send request
$request = '{"id":"req-1","method":"get_npub"}'
$writer.WriteLine($request)
$writer.Flush()

# Read response
$response = $reader.ReadLine()
Write-Host $response

$pipe.Close()
```

---

## Building from Source

```bash
# Clone repository
git clone https://gitlab.com/77elements/noorsigner.git
cd noorsigner

# Build for current platform
go build -o noorsigner .

# Or build all platforms
./build.sh

# Binaries will be in ./bin/
```

---

## Troubleshooting

### Daemon not starting

1. Check if socket already exists: `ls -la ~/.noorsigner/noorsigner.sock`
2. Remove stale socket: `rm ~/.noorsigner/noorsigner.sock`
3. Check for running processes: `ps aux | grep noorsigner`
4. Kill existing daemon: `pkill noorsigner`

### "Failed to connect to daemon"

- Daemon might not be running
- Socket file might not exist
- Check socket path matches your platform
- Verify socket permissions: `ls -la ~/.noorsigner/`

### "Invalid password"

- Encryption password is wrong
- Key file might be corrupted
- Use correct password for the specific account

### "Account not found"

- Account was removed or never created
- Use `list-accounts` to see available accounts
- Use `add-account` to create a new account

### Trust Mode not working after reboot

- This is expected! Trust Mode sessions expire after 24 hours OR system reboot
- Simply restart daemon and enter password again

---

## License

MIT License - See LICENSE file for details

---

## Contributing

Contributions welcome! Please:
1. Follow Go best practices
2. Maintain backwards compatibility with existing clients
3. Add tests for new features
4. Update this README with API changes

---

## Roadmap

- [x] Multi-account support
- [x] Live account switching via API
- [x] NIP-44 encryption/decryption
- [x] NIP-04 encryption/decryption
- [x] Auto-launch on system startup (macOS/Linux)
- [ ] NIP-46 Remote Signer support
- [ ] Hardware wallet integration
- [ ] Custom Trust Mode duration
- [ ] GUI password prompt option

---

## Support

For issues, feature requests, or questions:
- GitLab Issues: [Project Issues](https://gitlab.com/77elements/noorsigner/-/issues)
- Nostr: Contact the maintainers on Nostr

---

**Made with ⚡ for the Nostr ecosystem**
