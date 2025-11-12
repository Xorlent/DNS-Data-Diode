using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DNSDiode;

public class DnsServer
{
    private Socket? _udpListener;
    private CancellationTokenSource? _cancellationTokenSource;
    private readonly EventLogWriter _eventLog;
    private readonly ConcurrentDictionary<string, FileSession> _activeSessions = new();
    private const int MaxActiveSessions = 100; // Limit concurrent sessions to prevent memory exhaustion
    private readonly SemaphoreSlim _processingSemaphore = new(1, 1);
    private readonly Timer? _cleanupTimer;

    public DnsServer(EventLogWriter eventLog)
    {
        _eventLog = eventLog;
        _cleanupTimer = new Timer(CleanupExpiredSessions, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        
        try
        {
            _udpListener = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _udpListener.Bind(new IPEndPoint(IPAddress.Any, 53));
            _eventLog.WriteInfo("DNS Server started listening on UDP port 53");

            // DNS UDP packets are limited to 512 bytes (RFC 1035)
            const int MaxDnsPacketSize = 512;
            var buffer = new byte[MaxDnsPacketSize];
            var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0) as EndPoint;

            _eventLog.WriteInfo("DNS Server listening for incoming requests...");

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    var result = await _udpListener.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, remoteEndPoint);
                    if (result.ReceivedBytes > 0 && result.RemoteEndPoint is IPEndPoint ipEndPoint)
                    {
                        // Validate packet size
                        if (result.ReceivedBytes > MaxDnsPacketSize)
                        {
                            _eventLog.WriteWarning($"Received oversized DNS packet: {result.ReceivedBytes} bytes (max {MaxDnsPacketSize}) from {ipEndPoint.Address}");
                            continue;
                        }
                        
                        var requestBuffer = new byte[result.ReceivedBytes];
                        Array.Copy(buffer, requestBuffer, result.ReceivedBytes);
                        // _eventLog.WriteInfo($"Received {result.ReceivedBytes} bytes from {ipEndPoint.Address}:{ipEndPoint.Port}, processing...");
                        _ = Task.Run(() => ProcessDnsRequestAsync(requestBuffer, ipEndPoint), _cancellationTokenSource.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted || 
                                                  ex.SocketErrorCode == SocketError.OperationAborted)
                {
                    break;
                }
                catch (Exception ex) when (ex.Message.Contains("I/O operation has been aborted") || 
                                          ex.Message.Contains("operation has been aborted"))
                {
                    // Expected when service is stopping
                    break;
                }
                catch (Exception ex)
                {
                    _eventLog.WriteError($"Error receiving DNS request: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            _eventLog.WriteError($"Failed to start DNS server: {ex.Message}");
            throw;
        }
    }

    public void Stop()
    {
        _cancellationTokenSource?.Cancel();
        try
        {
            _udpListener?.Close();
        }
        catch { }
        _udpListener?.Dispose();
        _cleanupTimer?.Dispose();
        _processingSemaphore?.Dispose();
        _eventLog.WriteInfo("DNS Server stopped");
    }

    private async Task ProcessDnsRequestAsync(byte[] requestPacket, IPEndPoint remoteEndPoint)
    {
        try
        {
            // _eventLog.WriteInfo($"Received DNS request from {remoteEndPoint.Address}:{remoteEndPoint.Port} ({requestPacket.Length} bytes)");

            // Check allowlist
            string? allowList = ConfigurationManager.GetAllowList();
            if (!string.IsNullOrEmpty(allowList))
            {
                string[] allowedIps = allowList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                string clientIp = remoteEndPoint.Address.ToString();
                if (!allowedIps.Contains(clientIp))
                {
                    _eventLog.WriteWarning($"Request rejected - IP {clientIp} not in AllowList. Allowed IPs: {allowList}");
                    return; // Ignore request
                }
                // _eventLog.WriteInfo($"IP {clientIp} is in AllowList");
            }

            // Parse DNS packet
            var (queryName, _) = DnsPacketBuilder.ParseDnsPacket(requestPacket);
            if (string.IsNullOrEmpty(queryName))
            {
                _eventLog.WriteWarning($"Request rejected - Could not parse DNS query name from {remoteEndPoint.Address}");
                return;
            }

            // _eventLog.WriteInfo($"Parsed DNS query: {queryName} from {remoteEndPoint.Address}");

            // Check hostname
            string? dnsHostname = ConfigurationManager.GetDNSHostname();
            if (string.IsNullOrEmpty(dnsHostname))
            {
                _eventLog.WriteError("DNSHostname not configured - rejecting all requests");
                return; // Ignore request
            }

            // Check if query ends with hostname (with or without trailing dot)
            string hostnameCheck = "." + dnsHostname;
            if (!queryName.EndsWith(hostnameCheck, StringComparison.OrdinalIgnoreCase) && 
                !queryName.EndsWith(hostnameCheck + ".", StringComparison.OrdinalIgnoreCase) &&
                !queryName.Equals(dnsHostname, StringComparison.OrdinalIgnoreCase) &&
                !queryName.Equals(dnsHostname + ".", StringComparison.OrdinalIgnoreCase))
            {
                _eventLog.WriteWarning($"Request rejected - Query '{queryName}' does not match configured hostname '{dnsHostname}' from {remoteEndPoint.Address}");
                return; // Ignore request
            }

            // _eventLog.WriteInfo($"Query hostname matches configured hostname: {dnsHostname}");

            // Parse query components for label count check (FIRST CHECK after hostname validation)
            var parts = queryName.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3)
            {
                _eventLog.WriteWarning($"Request rejected - Query has too few parts ({parts.Length}) from {remoteEndPoint.Address}. Query parts: [{string.Join(", ", parts)}]");
                return;
            }

            // Find hostname start index for label count validation
            int hostnameStartIndex = -1;
            for (int i = parts.Length - 1; i >= 0; i--)
            {
                // Check if this part or combination of parts matches the hostname
                string testHostname = string.Join(".", parts.Skip(i));
                if (testHostname.Equals(dnsHostname, StringComparison.OrdinalIgnoreCase) ||
                    testHostname.Equals(dnsHostname + ".", StringComparison.OrdinalIgnoreCase))
                {
                    hostnameStartIndex = i;
                    break;
                }
            }

            if (hostnameStartIndex < 0)
            {
                // Try simple case-insensitive search
                hostnameStartIndex = Array.FindIndex(parts, p => p.Equals(dnsHostname, StringComparison.OrdinalIgnoreCase));
                if (hostnameStartIndex < 0)
                {
                    // Try finding the last part that matches
                    string lastPart = parts[parts.Length - 1];
                    if (dnsHostname.EndsWith("." + lastPart, StringComparison.OrdinalIgnoreCase) ||
                        dnsHostname.Equals(lastPart, StringComparison.OrdinalIgnoreCase))
                    {
                        hostnameStartIndex = parts.Length - 1;
                    }
                }
            }

            if (hostnameStartIndex < 2)
            {
                _eventLog.WriteWarning($"Request rejected - Could not find hostname '{dnsHostname}' in query parts or insufficient parts. Parts: [{string.Join(", ", parts)}] from {remoteEndPoint.Address}");
                return;
            }

            // LABEL COUNT CHECK - First validation after hostname/IP checks
            // Parse label count (second to last before hostname)
            int labelCountIndex = hostnameStartIndex - 1;
            if (labelCountIndex < 0 || labelCountIndex >= parts.Length)
            {
                _eventLog.WriteWarning($"Request rejected - Label count index is invalid ({labelCountIndex}) from {remoteEndPoint.Address}");
                return;
            }

            string labelCountStr = parts[labelCountIndex];
            if (string.IsNullOrEmpty(labelCountStr) || labelCountStr.Length != 1)
            {
                _eventLog.WriteWarning($"Request rejected - Invalid label count format: '{labelCountStr}' from {remoteEndPoint.Address}");
                return;
            }

            int expectedLabelCount;
            try
            {
                expectedLabelCount = Base32Encoder.DecodeLabelCount(labelCountStr[0]);
            }
            catch (ArgumentException ex)
            {
                _eventLog.WriteWarning($"Request rejected - Invalid label count character: '{labelCountStr}' from {remoteEndPoint.Address}. {ex.Message}");
                return;
            }

            // Validate label count matches actual count (excluding hostname)
            int actualLabelCount = hostnameStartIndex;
            if (actualLabelCount != expectedLabelCount)
            {
                // If actual count is less than expected, send NXDOMAIN response (no logging)
                if (actualLabelCount < expectedLabelCount)
                {
                    try
                    {
                        byte[] nxDomainResponse = DnsPacketBuilder.BuildNxDomainResponse(requestPacket);
                        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                        await socket.SendToAsync(new ArraySegment<byte>(nxDomainResponse), SocketFlags.None, remoteEndPoint);
                    }
                    catch (Exception ex)
                    {
                        _eventLog.WriteError($"Error sending NXDOMAIN response: {ex.Message}");
                    }
                }
                else
                {
                    _eventLog.WriteWarning($"Request rejected - Label count mismatch: expected {expectedLabelCount}, actual {actualLabelCount} from {remoteEndPoint.Address}");
                }
                return;
            }

            // Continue with other validations after label count check
            // _eventLog.WriteInfo($"Query split into {parts.Length} parts: [{string.Join(", ", parts)}]");

            string chunkBase32 = parts[0];
            string totalChunksBase32 = parts[1];

            // Decode chunk number
            ushort chunk = Base32Encoder.DecodeUInt16(chunkBase32);

            // Decode total chunks with validation
            ushort totalChunks = Base32Encoder.DecodeUInt16(totalChunksBase32);
            
            // Validate totalChunks to prevent memory exhaustion (max 65535, but use reasonable limit)
            const ushort MaxTotalChunks = 65535;
            const ushort MinTotalChunks = 1;
            if (totalChunks < MinTotalChunks || totalChunks > MaxTotalChunks)
            {
                _eventLog.WriteWarning($"Request rejected - Invalid totalChunks value: {totalChunks} (must be 1-65535) from {remoteEndPoint.Address}");
                return;
            }

            // _eventLog.WriteInfo($"Processing packet - Chunk: {chunk}, TotalChunks: {totalChunks} from {remoteEndPoint.Address}");

            // Find CRC-16 (third to last before hostname, now that label count is inserted)
            int crcIndex = hostnameStartIndex - 2;
            if (crcIndex < 0)
            {
                _eventLog.WriteWarning($"Request rejected - CRC-16 index is invalid ({crcIndex}) from {remoteEndPoint.Address}");
                return;
            }

            string crc16Base32 = parts[crcIndex];
            // _eventLog.WriteInfo($"Found CRC-16 at index {crcIndex}: {crc16Base32}, label count at index {labelCountIndex}: {labelCountStr}, hostname starts at index {hostnameStartIndex}");

            if (chunk == 0)
            {
                // Filename packet - try to acquire semaphore (only one file at a time)
                if (!await _processingSemaphore.WaitAsync(0))
                {
                    _eventLog.WriteWarning($"Filename packet rejected - Another file is being processed from {remoteEndPoint.Address}");
                    return;
                }
                _eventLog.WriteInfo($"Processing filename packet from {remoteEndPoint.Address}");
                // Filename packet
                await ProcessFilenamePacketAsync(requestPacket, remoteEndPoint, parts, crc16Base32, totalChunks);
            }
            else
            {
                // Data chunk packet - check if we have an active session for this IP
                string sessionKey = remoteEndPoint.Address.ToString();
                if (!_activeSessions.ContainsKey(sessionKey))
                {
                    _eventLog.WriteWarning($"Data chunk {chunk} rejected - No active session for IP {sessionKey}");
                    return; // No active session for this IP
                }
                // _eventLog.WriteInfo($"Processing data chunk {chunk}/{totalChunks} from {remoteEndPoint.Address}");
                // Data chunk packet
                await ProcessDataChunkAsync(requestPacket, remoteEndPoint, parts, chunkBase32, totalChunksBase32, crc16Base32, chunk, totalChunks);
            }
        }
        catch (Exception ex)
        {
            _eventLog.WriteError($"Error processing DNS request: {ex.Message}");
        }
    }

    private async Task ProcessFilenamePacketAsync(byte[] requestPacket, IPEndPoint remoteEndPoint, string[] parts, string crc16Base32, ushort totalChunks)
    {
        try
        {
            string? dnsHostname = ConfigurationManager.GetDNSHostname();
            if (string.IsNullOrEmpty(dnsHostname))
            {
                _processingSemaphore.Release();
                return;
            }

            // Extract filename segments (between totalChunks and CRC-16)
            // Find hostname index (same logic as in ProcessDnsRequestAsync)
            int hostnameIndex = -1;
            for (int i = parts.Length - 1; i >= 0; i--)
            {
                string testHostname = string.Join(".", parts.Skip(i));
                if (testHostname.Equals(dnsHostname, StringComparison.OrdinalIgnoreCase) ||
                    testHostname.Equals(dnsHostname + ".", StringComparison.OrdinalIgnoreCase))
                {
                    hostnameIndex = i;
                    break;
                }
            }

            if (hostnameIndex < 0)
            {
                hostnameIndex = Array.FindIndex(parts, p => p.Equals(dnsHostname, StringComparison.OrdinalIgnoreCase));
            }

            if (hostnameIndex < 4)
            {
                _eventLog.WriteError($"Invalid hostname index {hostnameIndex} for filename packet from {remoteEndPoint.Address}");
                _processingSemaphore.Release();
                return;
            }

            // Extract filename segments (between totalChunks and CRC-16, skipping label count)
            // Structure: chunk.totalChunks.segments...crc16.labelCount.hostname
            var filenameSegments = new List<string>();
            for (int i = 2; i < hostnameIndex - 2; i++) // -2 to skip CRC-16 and label count
            {
                filenameSegments.Add(parts[i]);
            }

            string filenameBase32 = string.Join("", filenameSegments);
            byte[] filenameBytes = Base32Encoder.Decode(filenameBase32);
            string filename = Encoding.ASCII.GetString(filenameBytes);

            // Verify CRC-16
            string chunkBase32 = Base32Encoder.Encode((ushort)0);
            string totalChunksBase32 = Base32Encoder.Encode(totalChunks);
            string crcData = chunkBase32 + totalChunksBase32 + filenameBase32;
            ushort calculatedCrc = Crc16Ccitt.Calculate(Encoding.ASCII.GetBytes(crcData));
            ushort receivedCrc = Base32Encoder.DecodeUInt16(crc16Base32);

            if (calculatedCrc != receivedCrc)
            {
                _eventLog.WriteError($"CRC-16 mismatch for filename packet: {filename}");
                _processingSemaphore.Release();
                return;
            }

            // Check session limit
            if (_activeSessions.Count >= MaxActiveSessions)
            {
                _eventLog.WriteWarning($"Maximum active sessions ({MaxActiveSessions}) reached. Rejecting new session from {remoteEndPoint.Address}");
                _processingSemaphore.Release();
                return;
            }

            // Create new session
            string sessionKey = remoteEndPoint.Address.ToString();
            var session = new FileSession
            {
                Filename = filename,
                RemoteEndPoint = remoteEndPoint,
                TotalChunks = totalChunks,
                Chunks = new ConcurrentDictionary<ushort, byte[]>(),
                LastActivity = DateTime.UtcNow
            };

            _activeSessions[sessionKey] = session;
            _eventLog.WriteInfo($"Starting file session: {filename} ({totalChunks} chunks) from {remoteEndPoint.Address}");

            // Send response
            string response = $"file={filename}";
            string queryName = string.Join(".", parts);
            byte[] responsePacket = DnsPacketBuilder.BuildTxtResponse(queryName, response);
            
            // Copy transaction ID from request
            responsePacket[0] = requestPacket[0];
            responsePacket[1] = requestPacket[1];

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            await socket.SendToAsync(new ArraySegment<byte>(responsePacket), SocketFlags.None, remoteEndPoint);
        }
        catch (Exception ex)
        {
            _eventLog.WriteError($"Error processing filename packet: {ex.Message}");
            _processingSemaphore.Release();
        }
    }

    private async Task ProcessDataChunkAsync(byte[] requestPacket, IPEndPoint remoteEndPoint, string[] parts, string chunkBase32, string totalChunksBase32, string crc16Base32, ushort chunk, ushort totalChunks)
    {
        string sessionKey = remoteEndPoint.Address.ToString();
        if (!_activeSessions.TryGetValue(sessionKey, out FileSession? session))
        {
            return; // No active session
        }

        session.LastActivity = DateTime.UtcNow;

        // Extract chunk data segments
        string? dnsHostname = ConfigurationManager.GetDNSHostname();
        if (string.IsNullOrEmpty(dnsHostname))
            return;

        // Find hostname index (same logic as in ProcessDnsRequestAsync)
        int hostnameIndex = -1;
        for (int i = parts.Length - 1; i >= 0; i--)
        {
            string testHostname = string.Join(".", parts.Skip(i));
            if (testHostname.Equals(dnsHostname, StringComparison.OrdinalIgnoreCase) ||
                testHostname.Equals(dnsHostname + ".", StringComparison.OrdinalIgnoreCase))
            {
                hostnameIndex = i;
                break;
            }
        }

        if (hostnameIndex < 0)
        {
            hostnameIndex = Array.FindIndex(parts, p => p.Equals(dnsHostname, StringComparison.OrdinalIgnoreCase));
        }

        if (hostnameIndex < 4)
        {
            _eventLog.WriteError($"Invalid hostname index {hostnameIndex} for data chunk {chunk} from {remoteEndPoint.Address}");
            return;
        }

        // Extract chunk data segments (between totalChunks and CRC-16, skipping label count)
        // Structure: chunk.totalChunks.segments...crc16.labelCount.hostname
        var chunkSegments = new List<string>();
        for (int i = 2; i < hostnameIndex - 2; i++) // -2 to skip CRC-16 and label count
        {
            chunkSegments.Add(parts[i]);
        }

        string chunkDataBase32 = string.Join("", chunkSegments);
        byte[] chunkData = Base32Encoder.Decode(chunkDataBase32);

        // Verify CRC-16
        string crcData = chunkBase32 + totalChunksBase32 + chunkDataBase32;
        ushort calculatedCrc = Crc16Ccitt.Calculate(Encoding.ASCII.GetBytes(crcData));
        ushort receivedCrc = Base32Encoder.DecodeUInt16(crc16Base32);

        if (calculatedCrc != receivedCrc)
        {
            _eventLog.WriteError($"CRC-16 mismatch for chunk {chunk} of {session.Filename}");
            return;
        }

        // Store chunk
        session.Chunks[chunk] = chunkData;

        // Send response
        string response = $"file={session.Filename} {chunk}";
        byte[] responsePacket = DnsPacketBuilder.BuildTxtResponse(string.Join(".", parts), response);
        
        // Copy transaction ID from request
        responsePacket[0] = requestPacket[0];
        responsePacket[1] = requestPacket[1];

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        await socket.SendToAsync(new ArraySegment<byte>(responsePacket), SocketFlags.None, remoteEndPoint);

        // Check if all chunks received
        if (session.Chunks.Count == totalChunks)
        {
            await CompleteFileSessionAsync(session);
        }
    }

    private async Task CompleteFileSessionAsync(FileSession session)
    {
        try
        {
            _eventLog.WriteInfo($"All chunks received for: {session.Filename}. Reassembling file...");

            // Validate total file size to prevent memory exhaustion
            // Max chunks (65535) * 128 bytes = ~8.4 MB, but set a more conservative limit
            const long MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB limit
            long estimatedSize = (long)session.TotalChunks * 128;
            if (estimatedSize > MaxFileSizeBytes)
            {
                _eventLog.WriteError($"File too large: {session.Filename} (estimated {estimatedSize} bytes, max {MaxFileSizeBytes} bytes)");
                _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
                return;
            }

            // Reassemble encrypted data
            var encryptedData = new List<byte>();
            for (ushort i = 1; i <= session.TotalChunks; i++)
            {
                if (!session.Chunks.TryGetValue(i, out byte[]? chunkData))
                {
                    _eventLog.WriteError($"Missing chunk {i} for {session.Filename}");
                    _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
                    return;
                }
                
                // Validate chunk size (should be <= 128 bytes)
                if (chunkData.Length > 128)
                {
                    _eventLog.WriteError($"Invalid chunk size: {chunkData.Length} bytes for chunk {i} of {session.Filename}");
                    _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
                    return;
                }
                
                encryptedData.AddRange(chunkData);
                
                // Check actual size during reassembly to prevent memory exhaustion
                if (encryptedData.Count > MaxFileSizeBytes)
                {
                    _eventLog.WriteError($"File size exceeded limit during reassembly: {session.Filename}");
                    _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
                    return;
                }
            }

            byte[] encryptedBytes = encryptedData.ToArray();

            // Decrypt
            string? encryptionKey = ConfigurationManager.GetEncryptionKey();
            if (string.IsNullOrEmpty(encryptionKey))
            {
                _eventLog.WriteError("Encryption key not configured");
                _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
                return;
            }

            byte[] compressedData = CryptoHelper.DecryptAes128Ecb(encryptedBytes, encryptionKey);

            // Decompress
            byte[] fileData = CryptoHelper.DecompressGZip(compressedData);

            // Save file
            string? destinationFolder = ConfigurationManager.GetDestinationFolder();
            if (string.IsNullOrEmpty(destinationFolder))
            {
                _eventLog.WriteError("Destination folder not configured");
                _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
                return;
            }

            if (!Directory.Exists(destinationFolder))
            {
                Directory.CreateDirectory(destinationFolder);
            }

            string destinationPath = Path.Combine(destinationFolder, session.Filename);
            await File.WriteAllBytesAsync(destinationPath, fileData);

            _eventLog.WriteInfo($"File successfully saved: {session.Filename} to {destinationPath}");

            // Remove session
            _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
        }
        catch (System.Security.Cryptography.CryptographicException ex) when (ex.Message.Contains("Padding is invalid"))
        {
            _eventLog.WriteError($"Error completing file session {session.Filename}: {ex.Message}. Possible cause: Invalid encryption key - verify EncryptionKey matches between Client and Server.");
            _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
        }
        catch (Exception ex)
        {
            _eventLog.WriteError($"Error completing file session {session.Filename}: {ex.Message}");
            _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
        }
        finally
        {
            _processingSemaphore.Release();
        }
    }

    private void CleanupExpiredSessions(object? state)
    {
        var expiredSessions = _activeSessions.Values
            .Where(s => (DateTime.UtcNow - s.LastActivity).TotalMinutes >= 1)
            .ToList();

        foreach (var session in expiredSessions)
        {
            _eventLog.WriteWarning($"File session expired and cancelled: {session.Filename}");
            _activeSessions.TryRemove(session.RemoteEndPoint.Address.ToString(), out _);
            // Release semaphore if this was the active session
            try
            {
                _processingSemaphore.Release();
            }
            catch
            {
                // Semaphore might already be released, ignore
            }
        }
    }

    private class FileSession
    {
        public string Filename { get; set; } = string.Empty;
        public IPEndPoint RemoteEndPoint { get; set; } = null!;
        public ushort TotalChunks { get; set; }
        public ConcurrentDictionary<ushort, byte[]> Chunks { get; set; } = new();
        public DateTime LastActivity { get; set; }
    }
}

