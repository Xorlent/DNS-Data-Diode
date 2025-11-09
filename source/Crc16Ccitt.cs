namespace DNSDiode;

/// <summary>
/// CRC-16-CCITT calculator
/// </summary>
public static class Crc16Ccitt
{
    private const ushort Polynomial = 0x1021;
    private static readonly ushort[] Table = new ushort[256];

    static Crc16Ccitt()
    {
        for (int i = 0; i < 256; i++)
        {
            ushort crc = 0;
            ushort c = (ushort)(i << 8);
            for (int j = 0; j < 8; j++)
            {
                if ((crc ^ c) >> 15 != 0)
                {
                    crc = (ushort)((crc << 1) ^ Polynomial);
                }
                else
                {
                    crc = (ushort)(crc << 1);
                }
                c = (ushort)(c << 1);
            }
            Table[i] = crc;
        }
    }

    public static ushort Calculate(byte[] data)
    {
        if (data == null || data.Length == 0)
            return 0;

        ushort crc = 0xFFFF;
        foreach (byte b in data)
        {
            crc = (ushort)((crc << 8) ^ Table[(crc >> 8) ^ b]);
        }
        return crc;
    }

    public static ushort Calculate(string data)
    {
        if (string.IsNullOrEmpty(data))
            return 0;
        return Calculate(System.Text.Encoding.ASCII.GetBytes(data));
    }
}

