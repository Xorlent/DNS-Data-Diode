# DNSDiode - DNS-Based Data Diode Service for Windows
_Note: This project is experimental only and not intended for production use without significant validation.  A most of the code was generated using the provided prompt as a starting point, then fixing code issues by hand and via a LLM-based coding agent._  
**DNSDiode is a .NET 8.0 Windows Service that implements a secure, one-way data transfer mechanism using DNS TXT record queries. The service operates in two modes: Client (sender) and Server (receiver), enabling secure file transfer across network boundaries where traditional bidirectional communication is restricted.**   
In my tests, compressed data transfer speeds averaged 27kbps (dial-up speeds) which, for CSV and other text-based file formates, could translate to greater than 250kbps which is respectable.

## Overview

DNSDiode uses DNS queries as a covert channel for data transmission, making it useful in scenarios where:
- Network policies restrict direct file transfers
- One-way data diodes are required for security compliance
- DNS traffic is allowed but other protocols are blocked

The service processes files by:
1. Compressing data using GZip
2. Encrypting using AES-128-ECB (known weakness partially mitigated via compression)
3. Chunking data into 128-byte segments
4. Encoding chunks in BASE32
5. Transmitting via DNS TXT record queries
6. Reassembling and decrypting on the receiving end

## System Requirements

- Windows Server or Windows 10/11 (x64)
- .NET 8.0 Runtime
- Administrator privileges (for service installation and UDP port 53 binding)
- Registry access for configuration

## Installation

### 1. Build the Service

```cmd
dotnet build -c Release
```

The compiled executable will be located at: `bin\Release\net8.0\win-x64\DNSDiode.exe`

### 2. Configure Registry Settings

Before starting the service, configure all required registry values under:
```
HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode
```

**Required for both modes:**
- `Mode` - Set to `"Client"` or `"Server"` (REG_SZ)
- `EncryptionKey` - 32-character hexadecimal string (16 bytes) (REG_SZ)
- `DNSHostname` - DNS hostname for queries (e.g., `"diodein.local"`) (REG_SZ)
- `QueryDelayMs` - Delay in milliseconds between queries (default: 25) (REG_DWORD)
- `Retries` - Number of retry attempts for DNS queries (default: 5) (REG_DWORD)

**Required for Client mode:**
- `MonitorFolder` - Full path to folder to monitor for outbound files (REG_SZ)
- `DNSServer` - IPv4 address of the local DNS server (REG_SZ)

**Required for Server mode:**
- `DestinationFolder` - Full path where received files will be saved (REG_SZ)
- `AllowList` - Comma-separated list of allowed DNS forwarder source IP addresses (REG_SZ)

### 3. Install the Service

Run the following command from an **elevated** Command Prompt or PowerShell:

```cmd
sc create DNSDiode binPath= "C:\Path\To\DNSDiode.exe" DisplayName= "DNS Data Diode Service" start= auto
```

Replace `C:\Path\To\DNSDiode.exe` with the actual path to your compiled executable.  C:\Program Files\DNSDataDiode is recommended for security.

**Optional: Add service description:**
```cmd
sc description DNSDiode "DNS-based data diode service for secure file transfer"
```

### 4. Start the Service

```cmd
sc start DNSDiode
```

### 5. Verify Installation

Check the Windows Event Log (Application log) for entries from source "DNSDiode" to verify the service started successfully.

## Uninstallation

### 1. Stop the Service

```cmd
sc stop DNSDiode
```

### 2. Delete the Service

```cmd
sc delete DNSDiode
```

### 3. Remove Registry Configuration (Optional)

If you want to remove all configuration:
```
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /f
```

## Configuration Details

### Windows Firewall Configuration

Required for both the client and server so data can be processed
1. Open Windows Defender Firewall with Advanced Security
2. Click "Inbound Rules" → "New Rule..."
3. Select "Program" → Next
4. Browse to and select `DNSDiode.exe` → Next
5. Select "Allow the connection" → Next
6. Check all profiles (Domain, Private, Public) → Next
7. Name it "DNSDiode Service" → Finish

### Registry Configuration Reference

All configuration values are stored in `HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode`.

#### Mode (Required - Both Modes)
- **Type:** REG_SZ (String)
- **Values:** `"Client"` or `"Server"`
- **Description:** Determines whether the service operates as a sender (Client) or receiver (Server)

#### EncryptionKey (Required - Both Modes)
- **Type:** REG_SZ (String)
- **Format:** 32-character hexadecimal string (represents 16 bytes for AES-128)
- **Example:** `"0123456789ABCDEF0123456789ABCDEF"`
- **Description:** Encryption key used for AES-128-ECB encryption/decryption. Must be identical on both Client and Server.

#### DNSHostname (Required - Both Modes)
- **Type:** REG_SZ (String)
- **Example:** `"diodeserver.local"`
- **Description:** DNS hostname used in query construction. Server mode will only accept queries ending with this hostname.

#### QueryDelayMs (Optional - Both Modes)
- **Type:** REG_DWORD (Integer)
- **Default:** 25 (milliseconds)
- **Description:** Minimum delay between DNS queries. Helps prevent network congestion and port exhaustion.

#### Retries (Optional - Client Mode Only)
- **Type:** REG_DWORD (Integer)
- **Default:** 5
- **Description:** Number of retry attempts for DNS queries (both filename packets and data chunks). If a response is not received within the timeout period, the query will be retried up to this many times before failing.

#### MonitorFolder (Required - Client Mode Only)
- **Type:** REG_SZ (String)
- **Example:** `"C:\DNSDataDiode\Monitor"`
- **Description:** Folder to monitor for new files. Files dropped into this folder will be automatically processed and transmitted.

#### DNSServer (Required - Client Mode Only)
- **Type:** REG_SZ (String)
- **Format:** IPv4 address
- **Example:** `"192.168.1.100"`
- **Description:** IP address of the DNS server (Server mode instance) to send queries to.

#### DestinationFolder (Required - Server Mode Only)
- **Type:** REG_SZ (String)
- **Example:** `"C:\DNSDataDiode\Received"`
- **Description:** Folder where successfully received and decrypted files will be saved.

#### AllowList (Required - Server Mode Only)
- **Type:** REG_SZ (String)
- **Format:** Comma-separated IPv4 addresses
- **Example:** `"192.168.1.50,10.0.0.25"`
- **Description:** List of allowed source IP addresses. Only queries from these IPs will be processed.

### Example Registry Configuration Script

**Client Mode:**
```cmd
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v Mode /t REG_SZ /d "Client" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v MonitorFolder /t REG_SZ /d "C:\DNSDataDiode\Monitor" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v DNSServer /t REG_SZ /d "192.168.1.100" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v EncryptionKey /t REG_SZ /d "0123456789ABCDEF0123456789ABCDEF" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v DNSHostname /t REG_SZ /d "diodeserver.local" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v QueryDelayMs /t REG_DWORD /d 25 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v Retries /t REG_DWORD /d 5 /f
```

**Server Mode:**
```cmd
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v Mode /t REG_SZ /d "Server" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v DestinationFolder /t REG_SZ /d "C:\DNSDataDiode\Received" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v AllowList /t REG_SZ /d "192.168.1.50" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v EncryptionKey /t REG_SZ /d "0123456789ABCDEF0123456789ABCDEF" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v DNSHostname /t REG_SZ /d "diodeserver.local" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v QueryDelayMs /t REG_DWORD /d 25 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\DNSDataDiode" /v Retries /t REG_DWORD /d 5 /f
```

## How It Works

### Client Mode (Sender)

1. **File Monitoring**: The service monitors the configured `MonitorFolder` for new files using `FileSystemWatcher`.

2. **File Processing Queue**: Files are queued (FIFO, max 10,000 files) and processed one at a time.

3. **File Processing Pipeline**:
   - Read file in binary format
   - Compress using GZip (Optimal compression level)
   - Encrypt using AES-128-ECB with the configured encryption key
   - Calculate total chunks: `ceil(encryptedData.Length / 128)`
   - Validate: If total chunks > 65,535, file is rejected as too large

4. **Filename Packet Transmission**:
   - Convert filename to ASCII, then BASE32 encode
   - Build DNS query: `Chunk.TotalChunks.FilenameSegments.CRC-16.hostname`
   - If query length > 253 characters, trim filename (preserving extension)
   - Send DNS TXT query to configured DNS server
   - Wait for acknowledgment: `file=filename`
   - Retry up to 5 times with exponential backoff if no response

5. **Data Chunk Transmission**:
   - For each 128-byte encrypted chunk:
     - BASE32 encode chunk number and chunk data
     - Calculate CRC-16-CCITT over: `Chunk + TotalChunks + EncryptedChunk`
     - Build DNS query: `Chunk.TotalChunks.ChunkSegments.CRC-16.hostname`
     - Validate query length < 254 characters
     - Send DNS TXT query with configured delay between chunks
     - Wait for acknowledgment: `file=filename Chunk`
     - Retry up to 5 times if no response
   - Process chunks sequentially (chunk 1, 2, 3, ...)

6. **File Cleanup**: After successful transmission, delete the source file.

### Server Mode (Receiver)

1. **DNS Listener**: Listens on UDP port 53 for incoming DNS TXT record queries.

2. **Request Validation**:
   - Check source IP against `AllowList` (ignore if not allowed)
   - Verify query hostname matches configured `DNSHostname`
   - Only one file transfer session active at a time (ignore requests from other IPs during active transfer)

3. **Filename Packet Processing**:
   - Parse DNS query to extract chunk number (0 = filename packet)
   - Decode BASE32 filename segments
   - Verify CRC-16-CCITT checksum
   - Create new file session
   - Respond with: `file=filename`

4. **Data Chunk Processing**:
   - Parse DNS query to extract chunk number and data
   - Decode BASE32 chunk data
   - Verify CRC-16-CCITT checksum
   - Store chunk in session dictionary
   - Respond with: `file=filename Chunk`
   - Update last activity timestamp

5. **File Reassembly**:
   - When all chunks received (chunk count = total chunks):
     - Reassemble encrypted data in order
     - Decrypt using AES-128-ECB
     - Decompress using GZip
     - Save to `DestinationFolder` with original filename
     - Log success to Event Log
     - Release processing semaphore

6. **Session Management**:
   - Sessions expire after 1 minute of inactivity
   - Expired sessions are automatically cleaned up
   - Only one file transfer active at a time globally

## Protocol Specification

### DNS Query Format

**Filename Packet (Chunk 0):**
```
Chunk.TotalChunks.FilenameSegment1.FilenameSegment2...CRC-16.hostname
```

**Data Packet (Chunk 1+):**
```
Chunk.TotalChunks.ChunkSegment1.ChunkSegment2...CRC-16.hostname
```

Where:
- `Chunk`: BASE32-encoded ushort (0 for filename, 1+ for data)
- `TotalChunks`: BASE32-encoded ushort
- `FilenameSegment*` / `ChunkSegment*`: BASE32-encoded data split into 63-character labels (DNS label limit)
- `CRC-16`: BASE32-encoded CRC-16-CCITT checksum
- `hostname`: Configured DNS hostname

### Response Format

**Filename Acknowledgment:**
```
file=filename
```

**Chunk Acknowledgment:**
```
file=filename Chunk
```

### Encoding Standards

- **BASE32**: RFC 4648 Base32 encoding (no padding)
- **CRC-16**: CRC-16-CCITT (polynomial 0x1021, initial value 0xFFFF)
- **Encryption**: AES-128-ECB with PKCS7 padding
- **Compression**: GZip (Optimal level)

## Limitations

- **Maximum File Size**: Files resulting in more than 65,535 chunks (approximately 8.4 MB encrypted) are rejected
- **DNS Query Length**: Maximum 253 characters (enforced, queries exceeding this are rejected)
- **Concurrent Transfers**: Server mode processes only one file at a time
- **Port Requirements**: Server mode requires UDP port 53 (requires administrator privileges)
- **Queue Depth**: Maximum 10,000 files in processing queue

## Troubleshooting

### Service Won't Start

1. Check Windows Event Log for error messages
2. Verify all required registry values are configured
3. Ensure service account has permissions to:
   - Read registry keys
   - Access configured folders
   - Bind to UDP port 53 (Server mode)

### Files Not Processing (Client Mode)

1. Verify `MonitorFolder` exists and is accessible
2. Check `DNSServer` IP address is correct and reachable
3. Verify `EncryptionKey` matches Server configuration
4. Check Event Log for transmission errors
5. Verify DNS queries are not being blocked by firewall

### Files Not Received (Server Mode)

1. Verify `DestinationFolder` exists and is writable
2. Check `AllowList` includes Client IP address
3. Verify `DNSHostname` matches Client configuration
4. Check Event Log for reception errors
5. Ensure UDP port 53 is not blocked by firewall
6. Verify no other service is using UDP port 53

### CRC-16 Mismatch Errors

- Indicates data corruption during transmission
- Verify network stability
- Check for DNS query/response manipulation
- Ensure `EncryptionKey` matches on both sides

## Security Considerations

1. **Access Control**: 
   - Server mode uses an IP allowlist for access control
   - Ensure `AllowList` is properly configured
   - Monitor Event Log for unauthorized access attempts

2. **Port Security**: UDP port 53 binding requires administrator privileges.

## Event Log

All service activities are logged to the Windows Application Event Log with source "DNSDiode":

- **Information**: Service start/stop, file processing start/completion
- **Warning**: Session timeouts, expired transfers
- **Error**: Configuration errors, transmission failures, CRC mismatches
