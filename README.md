# NoorSigner - Secure Key Signer for Nostr

NoorSigner is a standalone CLI key signer daemon for Nostr clients. It provides secure local key management with encrypted storage and background daemon operation.

## Features

- 🔐 **Secure Key Storage**: NIP-49 compatible scrypt encryption
- 🛡️ **Trust Mode**: 24-hour authentication caching
- 🔌 **Unix Socket IPC**: Fast, secure local communication
- 🖥️ **Cross-Platform**: macOS, Linux, Windows support
- 🔒 **Memory Safety**: Keys cleared from memory after use
- 🔄 **Background Daemon**: Fork-based process isolation

## Quick Start

### 1. Initialize (First Time)

```bash
./noorsigner init
```

This will:
- Prompt for your nsec (private key)
- Ask for an encryption password (8+ characters)
- Save encrypted key to `~/.noorsigner/keys.encrypted`

### 2. Start Daemon

```bash
./noorsigner daemon
```

This will:
- Prompt for your encryption password
- Create a Trust Mode session (24 hours)
- Fork to background
- Create Unix socket at `~/.noorsigner/noorsigner.sock`
- Terminal window can be closed after "You can close this window now"

### 3. Connect from Client

Your Nostr client can now communicate with the daemon via the Unix socket.

### 4. Enable Autostart (Optional)

To automatically start the daemon on system boot:

```bash
./noorsigner autostart enable
```

Check autostart status:

```bash
./noorsigner autostart status
```

Disable autostart:

```bash
./noorsigner autostart disable
```

**Platform Support:**
- ⚠️ **macOS**: LaunchAgent (~/Library/LaunchAgents/com.noorsigner.daemon.plist) - Not yet tested
- ⚠️ **Linux**: XDG Autostart (~/.config/autostart/noorsigner.desktop) - Not yet tested
- ⏳ **Windows**: Not yet implemented

**Note**: After enabling autostart, the daemon will launch automatically on next system boot. You'll still need to enter your password on first launch unless you have an active Trust Mode session.

**⚠️ Warning**: Autostart feature is implemented but not yet verified. Use with caution.

---

## API Documentation

### Protocol

**Transport**: Unix Domain Socket (JSON newline-delimited)

**Socket Paths**:
- **macOS/Linux**: `~/.noorsigner/noorsigner.sock`
- **Windows**: `\\.\pipe\noorsigner` (Named Pipe)

**Message Format**:
```json
{
  "id": "unique-request-id",
  "method": "method_name",
  "event_json": "optional-event-data"
}
```

---

### Methods

#### `get_npub`

Get the public key (npub) of the currently authenticated user.

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

**Note**: The `signature` field is reused for the npub response.

---

#### `sign_event`

Sign a Nostr event.

**Request**:
```json
{
  "id": "req-002",
  "method": "sign_event",
  "event_json": "{\"content\":\"Hello Nostr\",\"kind\":1,\"tags\":[],\"created_at\":1234567890}"
}
```

**Response**:
```json
{
  "id": "req-002",
  "signature": "3045022100abcdef..."
}
```

**Error Response**:
```json
{
  "id": "req-002",
  "error": "Error message here"
}
```

---

## Client Integration Guide

### Step 1: Check if Daemon is Running

**Method 1: Socket File Existence**
```javascript
const socketPath = `${process.env.HOME}/.noorsigner/noorsigner.sock`;
const fs = require('fs');

if (fs.existsSync(socketPath)) {
  console.log('Daemon is running');
}
```

**Method 2: Try Connection**
```javascript
const net = require('net');
const socketPath = `${process.env.HOME}/.noorsigner/noorsigner.sock`;

const client = net.createConnection(socketPath, () => {
  console.log('Daemon is running');
  client.end();
});

client.on('error', (err) => {
  console.log('Daemon not running:', err.message);
});
```

---

### Step 2: Wait for Daemon Startup

If you launch the daemon programmatically, poll the socket until it becomes available:

```javascript
async function waitForDaemon(maxWaitSeconds = 60) {
  const socketPath = `${process.env.HOME}/.noorsigner/noorsigner.sock`;
  const startTime = Date.now();

  while (Date.now() - startTime < maxWaitSeconds * 1000) {
    try {
      // Try to connect
      await new Promise((resolve, reject) => {
        const client = net.createConnection(socketPath, () => {
          client.end();
          resolve();
        });
        client.on('error', reject);
        client.setTimeout(1000);
      });

      console.log('Daemon is ready!');
      return true;
    } catch (err) {
      // Wait 1 second before retry
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }

  throw new Error('Daemon did not start within timeout');
}

// Usage
await waitForDaemon(60); // Wait up to 60 seconds
```

---

### Step 3: Send Requests

```javascript
const net = require('net');

function sendRequest(method, eventJson = null) {
  return new Promise((resolve, reject) => {
    const socketPath = `${process.env.HOME}/.noorsigner/noorsigner.sock`;
    const client = net.createConnection(socketPath);

    const request = {
      id: `req-${Date.now()}`,
      method,
      event_json: eventJson
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

// Get public key
const npubResponse = await sendRequest('get_npub');
console.log('Npub:', npubResponse.signature);

// Sign event
const eventJson = JSON.stringify({
  content: "Hello Nostr",
  kind: 1,
  tags: [],
  created_at: Math.floor(Date.now() / 1000)
});

const signResponse = await sendRequest('sign_event', eventJson);
console.log('Signature:', signResponse.signature);
```

---

## Security Model

### Encryption

- **Key Storage**: NIP-49 compatible scrypt encryption (N=16384, r=8, p=1)
- **Trust Mode**: Session token encrypted with random 32-byte key
- **Memory Safety**: Keys zeroed out after use

### Trust Mode (24 Hours)

When daemon starts, it creates a Trust Mode session that:
- Caches the decrypted nsec encrypted with a random session token
- Expires after 24 hours from creation
- Stored in `~/.noorsigner/trust_session`
- Allows daemon to restart without password re-entry (within 24h)

**Security Trade-off**: Trust Mode trades security for convenience. Only use on devices you trust.

### Socket Permissions

The Unix socket is created with `0600` permissions (owner read/write only), preventing other users from accessing it.

---

## File Locations

All NoorSigner files are stored in `~/.noorsigner/`:

```
~/.noorsigner/
├── keys.encrypted      # Encrypted nsec (NIP-49 compatible)
└── trust_session       # 24-hour trust mode session (if active)
```

---

## Platform-Specific Notes

### macOS
- Socket path: `~/.noorsigner/noorsigner.sock`
- Daemon launches via Terminal.app (when called from GUI)
- Process detachment via `Setsid: true`

### Linux
- Socket path: `~/.noorsigner/noorsigner.sock`
- Same daemon behavior as macOS

### Windows
- Named Pipe: `\\.\pipe\noorsigner`
- **Note**: Windows implementation is basic, lacks process forking

---

## Building from Source

```bash
# Clone repository
git clone https://gitlab.com/77elements/noorsigner.git
cd noorsigner

# Build all platforms
./build.sh

# Binaries will be in ./bin/
# - noorsigner-macos-arm64
# - noorsigner-macos-amd64
# - noorsigner-linux-amd64
# - noorsigner-linux-arm64
# - noorsigner-windows-amd64.exe
```

---

## Example Integrations

### Tauri Desktop App

See `src-tauri/src/key_signer.rs` in the Noornote repository for a complete Tauri integration example.

**Key points**:
- Launch daemon via Tauri command: `invoke('launch_key_signer', { mode: 'daemon' })`
- Communicate via Tauri command: `invoke('key_signer_request', { request: jsonString })`
- Rust backend handles Unix socket communication

### Web App (Not Supported)

NoorSigner requires Unix socket access, which browsers don't provide. Use a browser extension or Tauri/Electron wrapper.

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
- Re-initialize with `noorsigner init`

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

- [x] Auto-launch on system startup (macOS/Linux implemented but not verified, Windows pending)
- [ ] NIP-46 Remote Signer support
- [ ] Hardware wallet integration
- [ ] Multi-key support (switch between accounts)
- [ ] Custom Trust Mode duration
- [ ] GUI password prompt option

---

## Support

For issues, feature requests, or questions:
- GitLab Issues: [Project Issues](https://gitlab.com/77elements/noorsigner/-/issues)
- Nostr: Contact the maintainers on Nostr

---

**Made with ⚡ for the Nostr ecosystem**
