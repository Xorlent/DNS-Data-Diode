using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DNSDiode;

public class FileProcessor
{
    private readonly ConcurrentQueue<string> _fileQueue = new();
    private readonly SemaphoreSlim _processingSemaphore = new(1, 1);
    private readonly EventLogWriter _eventLog;
    private readonly int _maxQueueDepth = 10000;

    public FileProcessor(EventLogWriter eventLog)
    {
        _eventLog = eventLog;
    }

    public bool TryEnqueueFile(string filePath)
    {
        if (_fileQueue.Count >= _maxQueueDepth)
        {
            _eventLog.WriteError($"File queue is full (max {_maxQueueDepth}). Cannot enqueue: {filePath}");
            return false;
        }

        _fileQueue.Enqueue(filePath);
        _eventLog.WriteInfo($"File enqueued: {filePath} (Queue depth: {_fileQueue.Count})");
        _ = Task.Run(ProcessQueueAsync);
        return true;
    }

    private async Task ProcessQueueAsync()
    {
        if (!await _processingSemaphore.WaitAsync(0))
            return; // Already processing

        try
        {
            while (_fileQueue.TryDequeue(out string? filePath))
            {
                if (filePath == null || !File.Exists(filePath))
                    continue;

                await ProcessFileAsync(filePath);
            }
        }
        finally
        {
            _processingSemaphore.Release();
        }
    }

    private async Task<byte[]> ReadFileWithRetryAsync(string filePath, string filename)
    {
        const int maxRetries = 10;
        const int retryDelayMs = 500;

        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                // Try to open file with shared read access (non-exclusive)
                using var fileStream = new FileStream(
                    filePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read | FileShare.Write | FileShare.Delete,
                    bufferSize: 4096,
                    useAsync: true);

                // Read file content
                var fileData = new List<byte>();
                var buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    fileData.AddRange(buffer.Take(bytesRead));
                }

                return fileData.ToArray();
            }
            catch (IOException ex) when (attempt < maxRetries - 1)
            {
                // File might be locked by antivirus or still being written
                _eventLog.WriteInfo($"File {filename} not accessible (attempt {attempt + 1}/{maxRetries}), retrying in {retryDelayMs}ms: {ex.Message}");
                await Task.Delay(retryDelayMs);
            }
            catch (UnauthorizedAccessException ex) when (attempt < maxRetries - 1)
            {
                // File might be locked by antivirus
                _eventLog.WriteInfo($"File {filename} access denied (attempt {attempt + 1}/{maxRetries}), retrying in {retryDelayMs}ms: {ex.Message}");
                await Task.Delay(retryDelayMs);
            }
        }

        // Final attempt - if this fails, throw the exception
        using var finalStream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Write | FileShare.Delete,
            bufferSize: 4096,
            useAsync: true);

        var finalData = new List<byte>();
        var finalBuffer = new byte[4096];
        int finalBytesRead;

        while ((finalBytesRead = await finalStream.ReadAsync(finalBuffer, 0, finalBuffer.Length)) > 0)
        {
            finalData.AddRange(finalBuffer.Take(finalBytesRead));
        }

        return finalData.ToArray();
    }

    private async Task ProcessFileAsync(string filePath)
    {
        string filename = Path.GetFileName(filePath);
        _eventLog.WriteInfo($"Starting file processing: {filename}");

        try
        {
            // Read file with retry logic for antivirus/file lock scenarios
            _eventLog.WriteInfo($"Reading file: {filename}");
            byte[] fileData = await ReadFileWithRetryAsync(filePath, filename);
            _eventLog.WriteInfo($"File read: {filename} ({fileData.Length} bytes)");

            // Compress
            _eventLog.WriteInfo($"Compressing: {filename}");
            byte[] compressedData = CryptoHelper.CompressGZip(fileData);
            _eventLog.WriteInfo($"Compressed: {filename} ({compressedData.Length} bytes)");

            // Encrypt
            string? encryptionKey = ConfigurationManager.GetEncryptionKey();
            if (string.IsNullOrEmpty(encryptionKey))
            {
                _eventLog.WriteError($"Encryption key not configured. Cannot process: {filename}");
                return;
            }

            _eventLog.WriteInfo($"Encrypting: {filename}");
            byte[] encryptedData = CryptoHelper.EncryptAes128Ecb(compressedData, encryptionKey);
            _eventLog.WriteInfo($"Encrypted: {filename} ({encryptedData.Length} bytes)");

            // Calculate total chunks
            int totalChunks = (int)Math.Ceiling(encryptedData.Length / 128.0);
            if (totalChunks > 65535)
            {
                _eventLog.WriteError($"File too large: {filename} ({totalChunks} chunks, max 65535)");
                return;
            }

            _eventLog.WriteInfo($"File will be split into {totalChunks} chunks: {filename}");
            string totalChunksBase32 = Base32Encoder.Encode((ushort)totalChunks);

            // Convert filename to ASCII then BASE32
            byte[] filenameAscii = Encoding.ASCII.GetBytes(filename);
            string filenameBase32 = Base32Encoder.Encode(filenameAscii);

            // Build and send filename packet
            _eventLog.WriteInfo($"Sending filename packet: {filename}");
            string? processedFilename = await SendFilenamePacketAsync(filename, filenameBase32, totalChunksBase32);
            if (string.IsNullOrEmpty(processedFilename))
            {
                _eventLog.WriteError($"Failed to send filename packet for: {filename}");
                return;
            }

            // Send data chunks
            _eventLog.WriteInfo($"Starting data chunk transmission: {processedFilename} ({totalChunks} chunks)");
            bool success = await SendDataChunksAsync(processedFilename, encryptedData, totalChunks, totalChunksBase32);
            if (!success)
            {
                _eventLog.WriteError($"Failed to send all data chunks for: {filename}");
                return;
            }

            // Delete processed file
            try
            {
                File.Delete(filePath);
                _eventLog.WriteInfo($"File processing completed and deleted: {filename}");
            }
            catch (Exception ex)
            {
                _eventLog.WriteError($"Failed to delete processed file: {filename}. Error: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            _eventLog.WriteError($"Error processing file {filename}: {ex.Message}");
        }
    }

    private async Task<string?> SendFilenamePacketAsync(string originalFilename, string filenameBase32, string totalChunksBase32)
    {
        string? dnsHostname = ConfigurationManager.GetDNSHostname();
        string? dnsServer = ConfigurationManager.GetDNSServer();
        int queryDelayMs = ConfigurationManager.GetQueryDelayMs();
        int maxRetries = ConfigurationManager.GetRetries();

        if (string.IsNullOrEmpty(dnsHostname) || string.IsNullOrEmpty(dnsServer))
        {
            _eventLog.WriteError("DNS hostname or server not configured");
            return null;
        }

        if (!IPAddress.TryParse(dnsServer, out IPAddress? serverIp))
        {
            _eventLog.WriteError($"Invalid DNS server IP address: {dnsServer}");
            return null;
        }

        string processedFilename = originalFilename;
        int chunk = 0;
        string chunkBase32 = Base32Encoder.Encode((ushort)chunk);

        // Split filename into 63-char segments
        var filenameSegments = DnsPacketBuilder.SplitIntoLabels(filenameBase32, 63);

        // Calculate CRC-16
        string crcData = chunkBase32 + totalChunksBase32 + filenameBase32;
            ushort crc16 = Crc16Ccitt.Calculate(Encoding.ASCII.GetBytes(crcData));
            string crc16Base32 = Base32Encoder.Encode(crc16);

        // Build query and check length
        var queryName = DnsPacketBuilder.BuildQueryName(chunkBase32, totalChunksBase32, filenameSegments, crc16Base32, dnsHostname);
        int queryLength = queryName.Length;

        // Trim filename if needed
        if (queryLength > DnsPacketBuilder.MaxDnsQueryLength)
        {
            int charsToTrim = (int)Math.Ceiling((queryLength - DnsPacketBuilder.MaxDnsQueryLength) * 1.6);
            processedFilename = DnsPacketBuilder.TrimFilename(originalFilename, charsToTrim);
            
            // Recalculate with trimmed filename
            byte[] trimmedAscii = Encoding.ASCII.GetBytes(processedFilename);
            string trimmedBase32 = Base32Encoder.Encode(trimmedAscii);
            filenameSegments = DnsPacketBuilder.SplitIntoLabels(trimmedBase32, 63);
            crcData = chunkBase32 + totalChunksBase32 + trimmedBase32;
            crc16 = Crc16Ccitt.Calculate(Encoding.ASCII.GetBytes(crcData));
            crc16Base32 = Base32Encoder.Encode(BitConverter.GetBytes(crc16));
            queryName = DnsPacketBuilder.BuildQueryName(chunkBase32, totalChunksBase32, filenameSegments, crc16Base32, dnsHostname);
        }

        // Send filename packet with retries
        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            _eventLog.WriteInfo($"Filename packet attempt {attempt + 1}/{maxRetries}: {processedFilename}");
            
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                byte[] queryPacket = DnsPacketBuilder.BuildTxtQuery(queryName);
                _eventLog.WriteInfo($"Sending DNS query to {serverIp}:53 (query length: {queryName.Length})");
                
                await socket.SendToAsync(new ArraySegment<byte>(queryPacket), SocketFlags.None, new IPEndPoint(serverIp, 53));
                _eventLog.WriteInfo($"DNS query sent, waiting for response (timeout: {5 * queryDelayMs}ms)");

                // Wait for response with timeout
                // DNS UDP packets are limited to 512 bytes (RFC 1035)
                const int MaxDnsPacketSize = 512;
                var buffer = new byte[MaxDnsPacketSize];
                var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0) as EndPoint;
                
                var receiveTask = socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, remoteEndPoint);
                var timeoutTask = Task.Delay(TimeSpan.FromMilliseconds(5 * queryDelayMs));
                
                var completedTask = await Task.WhenAny(receiveTask, timeoutTask);
                
                if (completedTask == timeoutTask)
                {
                    _eventLog.WriteWarning($"Filename packet timeout on attempt {attempt + 1}/{maxRetries}: {processedFilename}");
                    socket.Close();
                    if (attempt < maxRetries - 1)
                    {
                        await Task.Delay(5 * queryDelayMs);
                    }
                    continue;
                }

                var result = await receiveTask;
                if (result.ReceivedBytes > 0 && result.RemoteEndPoint is IPEndPoint ipEndPoint)
                {
                    _eventLog.WriteInfo($"Received response from {ipEndPoint.Address} ({result.ReceivedBytes} bytes)");
                    var (responseQueryName, txtData) = DnsPacketBuilder.ParseDnsPacket(buffer);

                    if (txtData != null && txtData.StartsWith($"file={processedFilename}", StringComparison.OrdinalIgnoreCase))
                    {
                        _eventLog.WriteInfo($"Filename packet acknowledged for: {processedFilename}");
                        return processedFilename;
                    }
                    else
                    {
                        _eventLog.WriteWarning($"Unexpected response: {txtData}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _eventLog.WriteWarning($"Filename packet timeout on attempt {attempt + 1}/{maxRetries}: {processedFilename}");
            }
            catch (SocketException ex)
            {
                _eventLog.WriteError($"Socket error on attempt {attempt + 1}/{maxRetries}: {ex.Message}");
            }
            catch (Exception ex)
            {
                _eventLog.WriteError($"Error on attempt {attempt + 1}/{maxRetries}: {ex.Message}");
            }

            if (attempt < maxRetries - 1)
            {
                await Task.Delay(5 * queryDelayMs);
            }
        }

        _eventLog.WriteError($"Failed to send filename packet after {maxRetries} attempts: {processedFilename}");
        return null;
    }

    private async Task<bool> SendDataChunksAsync(string filename, byte[] encryptedData, int totalChunks, string totalChunksBase32)
    {
        string? dnsHostname = ConfigurationManager.GetDNSHostname();
        string? dnsServer = ConfigurationManager.GetDNSServer();
        int queryDelayMs = ConfigurationManager.GetQueryDelayMs();
        int maxRetries = ConfigurationManager.GetRetries();

        if (string.IsNullOrEmpty(dnsHostname) || string.IsNullOrEmpty(dnsServer))
            return false;

        if (!IPAddress.TryParse(dnsServer, out IPAddress? serverIp))
            return false;

        for (int chunkIndex = 1; chunkIndex <= totalChunks; chunkIndex++)
        {
            int chunkStart = (chunkIndex - 1) * 128;
            int chunkLength = Math.Min(128, encryptedData.Length - chunkStart);
            byte[] chunkData = new byte[chunkLength];
            Array.Copy(encryptedData, chunkStart, chunkData, 0, chunkLength);

            string chunkBase32 = Base32Encoder.Encode((ushort)chunkIndex);
            string chunkDataBase32 = Base32Encoder.Encode(chunkData);

            // Calculate CRC-16
            string crcData = chunkBase32 + totalChunksBase32 + chunkDataBase32;
            ushort crc16 = Crc16Ccitt.Calculate(Encoding.ASCII.GetBytes(crcData));
            string crc16Base32 = Base32Encoder.Encode(crc16);

            // Split chunk data into 63-char segments
            var chunkSegments = DnsPacketBuilder.SplitIntoLabels(chunkDataBase32, 63);

            // Build query
            var queryName = DnsPacketBuilder.BuildQueryName(chunkBase32, totalChunksBase32, chunkSegments, crc16Base32, dnsHostname);
            
            // Check query length
            if (queryName.Length >= 254)
            {
                _eventLog.WriteError($"DNS query too long ({queryName.Length} chars) for chunk {chunkIndex} of {filename}. Query: {queryName.Substring(0, Math.Min(100, queryName.Length))}...");
                return false;
            }

            // Send with retries
            bool success = false;
            for (int attempt = 0; attempt < maxRetries; attempt++)
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(5 * queryDelayMs));

                try
                {
                    byte[] queryPacket = DnsPacketBuilder.BuildTxtQuery(queryName);
                    await socket.SendToAsync(new ArraySegment<byte>(queryPacket), SocketFlags.None, new IPEndPoint(serverIp, 53));

                    // Wait for response with timeout
                    // DNS UDP packets are limited to 512 bytes (RFC 1035)
                    const int MaxDnsPacketSize = 512;
                    var buffer = new byte[MaxDnsPacketSize];
                    var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0) as EndPoint;
                    
                    var receiveTask = socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, remoteEndPoint);
                    var timeoutTask = Task.Delay(TimeSpan.FromMilliseconds(5 * queryDelayMs));
                    
                    var completedTask = await Task.WhenAny(receiveTask, timeoutTask);
                    
                    if (completedTask == timeoutTask)
                    {
                        socket.Close();
                        if (attempt < maxRetries - 1)
                        {
                            await Task.Delay(5 * queryDelayMs);
                        }
                        continue;
                    }

                    var result = await receiveTask;
                    if (result.ReceivedBytes > 0 && result.RemoteEndPoint is IPEndPoint ipEndPoint)
                    {
                        var (responseQueryName, txtData) = DnsPacketBuilder.ParseDnsPacket(buffer);

                        if (txtData != null)
                        {
                            string expectedResponse = $"file={filename} {chunkIndex}";
                            if (txtData.Equals(expectedResponse, StringComparison.OrdinalIgnoreCase))
                            {
                                success = true;
                                break;
                            }
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    // Timeout - will retry
                }
                catch (SocketException ex)
                {
                    _eventLog.WriteError($"Socket error sending chunk {chunkIndex} attempt {attempt + 1}/{maxRetries}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    _eventLog.WriteError($"Error sending chunk {chunkIndex} attempt {attempt + 1}/{maxRetries}: {ex.Message}");
                }

                if (attempt < maxRetries - 1)
                {
                    await Task.Delay(5 * queryDelayMs);
                }
            }

            if (!success)
            {
                _eventLog.WriteError($"Failed to send chunk {chunkIndex}/{totalChunks} after {maxRetries} attempts: {filename}");
                return false;
            }

            // Delay between chunks
            if (chunkIndex < totalChunks)
            {
                await Task.Delay(queryDelayMs);
            }
        }

        _eventLog.WriteInfo($"All {totalChunks} chunks sent successfully for: {filename}");
        return true;
    }
}

