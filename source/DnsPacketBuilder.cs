using System.Net;
using System.Text;

namespace DNSDiode;

public static class DnsPacketBuilder
{
    public const int MaxDnsQueryLength = 253;
    private const int MaxLabelLength = 63;

    public static byte[] BuildTxtQuery(string queryName)
    {
        var packet = new List<byte>();

        // DNS Header
        // Transaction ID (2 bytes) - random
        var random = new Random();
        ushort transactionId = (ushort)random.Next(0, 65536);
        packet.AddRange(BitConverter.GetBytes(transactionId).Reverse());

        // Flags (2 bytes) - Standard query
        packet.AddRange(new byte[] { 0x01, 0x00 });

        // Questions (2 bytes) - 1 question
        packet.AddRange(new byte[] { 0x00, 0x01 });

        // Answer RRs (2 bytes) - 0
        packet.AddRange(new byte[] { 0x00, 0x00 });

        // Authority RRs (2 bytes) - 0
        packet.AddRange(new byte[] { 0x00, 0x00 });

        // Additional RRs (2 bytes) - 0
        packet.AddRange(new byte[] { 0x00, 0x00 });

        // Question Section
        // QNAME - domain name
        var labels = queryName.Split('.');
        int totalNameLength = 0;
        foreach (var label in labels)
        {
            if (string.IsNullOrEmpty(label))
                continue; // Skip empty labels
            
            var labelBytes = Encoding.ASCII.GetBytes(label);
            
            // Validate label length (RFC 1035: max 63 bytes)
            if (labelBytes.Length > 63)
                throw new ArgumentException($"Label too long: {label.Length} bytes (max 63)", nameof(queryName));
            
            totalNameLength += labelBytes.Length + 1; // +1 for length byte
            if (totalNameLength > 255)
                throw new ArgumentException($"Domain name too long: {totalNameLength} bytes (max 255)", nameof(queryName));
            
            packet.Add((byte)labelBytes.Length);
            packet.AddRange(labelBytes);
        }
        packet.Add(0); // Null terminator

        // QTYPE (2 bytes) - TXT = 16
        packet.AddRange(new byte[] { 0x00, 0x10 });

        // QCLASS (2 bytes) - IN = 1
        packet.AddRange(new byte[] { 0x00, 0x01 });

        return packet.ToArray();
    }

    public static byte[] BuildTxtResponse(string queryName, string txtData)
    {
        var packet = new List<byte>();

        // DNS Header
        // Transaction ID (2 bytes) - will be set by caller
        packet.AddRange(new byte[] { 0x00, 0x00 });

        // Flags (2 bytes) - Response, Authoritative Answer
        packet.AddRange(new byte[] { 0x81, 0x80 });

        // Questions (2 bytes) - 1 question
        packet.AddRange(new byte[] { 0x00, 0x01 });

        // Answer RRs (2 bytes) - 1 answer
        packet.AddRange(new byte[] { 0x00, 0x01 });

        // Authority RRs (2 bytes) - 0
        packet.AddRange(new byte[] { 0x00, 0x00 });

        // Additional RRs (2 bytes) - 0
        packet.AddRange(new byte[] { 0x00, 0x00 });

        // Question Section
        var labels = queryName.Split('.');
        int totalNameLength = 0;
        foreach (var label in labels)
        {
            if (string.IsNullOrEmpty(label))
                continue; // Skip empty labels
            
            var labelBytes = Encoding.ASCII.GetBytes(label);
            
            // Validate label length (RFC 1035: max 63 bytes)
            if (labelBytes.Length > 63)
                throw new ArgumentException($"Label too long: {label.Length} bytes (max 63)", nameof(queryName));
            
            totalNameLength += labelBytes.Length + 1; // +1 for length byte
            if (totalNameLength > 255)
                throw new ArgumentException($"Domain name too long: {totalNameLength} bytes (max 255)", nameof(queryName));
            
            packet.Add((byte)labelBytes.Length);
            packet.AddRange(labelBytes);
        }
        packet.Add(0); // Null terminator

        // QTYPE (2 bytes) - TXT = 16
        packet.AddRange(new byte[] { 0x00, 0x10 });

        // QCLASS (2 bytes) - IN = 1
        packet.AddRange(new byte[] { 0x00, 0x01 });

        // Answer Section
        // NAME - pointer to question (0xC0 0x0C)
        packet.AddRange(new byte[] { 0xC0, 0x0C });

        // TYPE (2 bytes) - TXT = 16
        packet.AddRange(new byte[] { 0x00, 0x10 });

        // CLASS (2 bytes) - IN = 1
        packet.AddRange(new byte[] { 0x00, 0x01 });

        // TTL (4 bytes) - 0 seconds (no caching)
        packet.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });

        // RDLENGTH (2 bytes) - length of TXT data
        var txtBytes = Encoding.ASCII.GetBytes(txtData);
        ushort rdLength = (ushort)(txtBytes.Length + 1); // +1 for length byte
        packet.AddRange(BitConverter.GetBytes(rdLength).Reverse());

        // RDATA - TXT record
        packet.Add((byte)txtBytes.Length); // Length of first string
        packet.AddRange(txtBytes);

        return packet.ToArray();
    }

    public static (string QueryName, string? TxtData) ParseDnsPacket(byte[] packet)
    {
        if (packet.Length < 12)
            return (string.Empty, null);

        // Check if it's a response
        bool isResponse = (packet[2] & 0x80) != 0;

        // Parse question section
        int offset = 12;
        string queryName = ParseDomainName(packet, ref offset);
        
        if (offset + 4 > packet.Length)
            return (queryName, null);

        offset += 4; // Skip QTYPE and QCLASS

        if (!isResponse)
            return (queryName, null);

        // Parse answer section
        if (offset >= packet.Length)
            return (queryName, null);

        // Check for pointer
        if (packet[offset] == 0xC0)
        {
            offset += 2; // Skip pointer
        }
        else
        {
            // Parse name
            ParseDomainName(packet, ref offset);
        }

        if (offset + 10 > packet.Length)
            return (queryName, null);

        offset += 8; // Skip TYPE, CLASS, TTL

        // Read RDLENGTH with validation
        if (offset + 2 > packet.Length)
            return (queryName, null);

        ushort rdLength = (ushort)((packet[offset] << 8) | packet[offset + 1]);
        offset += 2;

        // Validate RDLENGTH is reasonable (max 512 bytes for DNS packet, minus headers)
        const int MaxRDLength = 450; // Conservative limit
        if (rdLength > MaxRDLength || offset + rdLength > packet.Length)
            return (queryName, null);

        // Read TXT data with validation
        if (offset >= packet.Length)
            return (queryName, null);

        int txtLength = packet[offset];
        offset++;

        // Validate TXT length (RFC 1035: character-string max 255 bytes)
        const int MaxTxtLength = 255;
        if (txtLength > MaxTxtLength || txtLength > rdLength - 1 || offset + txtLength > packet.Length)
            return (queryName, null);

        string txtData = Encoding.ASCII.GetString(packet, offset, txtLength);
        return (queryName, txtData);
    }

    private static string ParseDomainName(byte[] packet, ref int offset)
    {
        return ParseDomainName(packet, ref offset, new HashSet<int>(), 0);
    }

    private static string ParseDomainName(byte[] packet, ref int offset, HashSet<int> visitedOffsets, int depth)
    {
        const int MaxRecursionDepth = 10;
        const int MaxDomainNameLength = 255;
        const int MaxLabelLength = 63;

        if (depth > MaxRecursionDepth)
            return string.Empty; // Prevent infinite recursion

        var labels = new List<string>();
        int startOffset = offset;
        int totalLength = 0;

        while (offset < packet.Length && totalLength < MaxDomainNameLength)
        {
            if (offset >= packet.Length)
                break;

            byte length = packet[offset];
            offset++;

            if (length == 0)
                break;

            if ((length & 0xC0) == 0xC0)
            {
                // Compression pointer
                if (offset >= packet.Length)
                    break;

                int pointer = ((length & 0x3F) << 8) | packet[offset];
                offset++;

                // Validate pointer is within packet bounds
                if (pointer < 0 || pointer >= packet.Length || pointer >= offset - 2)
                    break; // Invalid pointer

                // Prevent cycles - check if we've visited this offset
                if (visitedOffsets.Contains(pointer))
                    break; // Cycle detected

                visitedOffsets.Add(pointer);
                int savedOffset = offset;
                offset = pointer;
                var compressedName = ParseDomainName(packet, ref offset, visitedOffsets, depth + 1);
                offset = savedOffset;
                labels.AddRange(compressedName.Split('.'));
                break;
            }

            // Validate label length (RFC 1035: max 63 bytes)
            if (length > MaxLabelLength)
                break; // Invalid label length

            if (offset + length > packet.Length)
                break; // Label extends beyond packet

            string label = Encoding.ASCII.GetString(packet, offset, length);
            labels.Add(label);
            offset += length;
            totalLength += length + 1; // +1 for the length byte or dot
        }

        return string.Join(".", labels);
    }

    public static string BuildQueryName(string chunk, string totalChunks, List<string> segments, string crc16, string hostname)
    {
        var parts = new List<string> { chunk, totalChunks };
        parts.AddRange(segments);
        parts.Add(crc16);
        parts.Add(hostname);
        return string.Join(".", parts);
    }

    public static List<string> SplitIntoLabels(string data, int maxLabelLength = MaxLabelLength)
    {
        var labels = new List<string>();
        for (int i = 0; i < data.Length; i += maxLabelLength)
        {
            int length = Math.Min(maxLabelLength, data.Length - i);
            labels.Add(data.Substring(i, length));
        }
        return labels;
    }

    public static string TrimFilename(string filename, int charsToTrim)
    {
        if (charsToTrim <= 0)
            return filename;

        int lastDot = filename.LastIndexOf('.');
        if (lastDot < 0)
        {
            // No extension, trim from end
            if (filename.Length <= charsToTrim)
                return filename;
            return filename.Substring(0, filename.Length - charsToTrim);
        }

        string nameWithoutExt = filename.Substring(0, lastDot);
        string extension = filename.Substring(lastDot);

        if (nameWithoutExt.Length <= charsToTrim)
            return extension.TrimStart('.');

        return nameWithoutExt.Substring(0, nameWithoutExt.Length - charsToTrim) + extension;
    }

    public static int CalculateQueryLength(string chunk, string totalChunks, List<string> segments, string crc16, string hostname)
    {
        // Calculate: chunk.totalChunks.segment1.segment2...crc16.hostname
        int length = chunk.Length + 1; // chunk + dot
        length += totalChunks.Length + 1; // totalChunks + dot
        foreach (var segment in segments)
        {
            length += segment.Length + 1; // segment + dot
        }
        length += crc16.Length + 1; // crc16 + dot
        length += hostname.Length; // hostname (no trailing dot)
        return length;
    }
}

