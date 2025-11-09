namespace DNSDiode;

/// <summary>
/// RFC 4648 Base32 encoding implementation
/// </summary>
public static class Base32Encoder
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ushort value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }
        return Encode(bytes);
    }

    public static string Encode(byte[] data)
    {
        if (data == null || data.Length == 0)
            return string.Empty;

        var output = new System.Text.StringBuilder();
        int bits = 0;
        int value = 0;

        foreach (byte b in data)
        {
            value = (value << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                output.Append(Base32Alphabet[(value >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output.Append(Base32Alphabet[(value << (5 - bits)) & 0x1F]);
        }

        return output.ToString();
    }

    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            return Array.Empty<byte>();

        // Limit input size to prevent memory exhaustion
        // BASE32 encoding: 5 bits per character, so max ~1.6MB output for 2MB input
        const int MaxEncodedLength = 2 * 1024 * 1024; // 2 MB
        if (encoded.Length > MaxEncodedLength)
            throw new ArgumentException($"Encoded string too long: {encoded.Length} characters (max {MaxEncodedLength})", nameof(encoded));

        encoded = encoded.ToUpperInvariant();
        var output = new List<byte>();
        int bits = 0;
        int value = 0;

        foreach (char c in encoded)
        {
            int index = Base32Alphabet.IndexOf(c);
            if (index < 0)
                continue; // Skip invalid characters

            value = (value << 5) | index;
            bits += 5;

            if (bits >= 8)
            {
                output.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
            
            // Limit output size to prevent memory exhaustion
            const int MaxDecodedLength = 10 * 1024 * 1024; // 10 MB
            if (output.Count > MaxDecodedLength)
                throw new ArgumentException($"Decoded data too large: {output.Count} bytes (max {MaxDecodedLength})", nameof(encoded));
        }

        return output.ToArray();
    }

    public static ushort DecodeUInt16(string encoded)
    {
        byte[] bytes = Decode(encoded);
        if (bytes.Length < 2)
            return 0;
        
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes, 0, 2);
        }
        return BitConverter.ToUInt16(bytes, 0);
    }
}

