using System.Security.Cryptography;
using System.Text;

namespace DNSDiode;

public static class CryptoHelper
{
    public static byte[] CompressGZip(byte[] data)
    {
        using var inputStream = new MemoryStream(data);
        using var outputStream = new MemoryStream();
        using (var gzipStream = new System.IO.Compression.GZipStream(outputStream, System.IO.Compression.CompressionLevel.Optimal))
        {
            inputStream.CopyTo(gzipStream);
        }
        return outputStream.ToArray();
    }

    public static byte[] DecompressGZip(byte[] compressedData)
    {
        using var inputStream = new MemoryStream(compressedData);
        using var outputStream = new MemoryStream();
        using (var gzipStream = new System.IO.Compression.GZipStream(inputStream, System.IO.Compression.CompressionMode.Decompress))
        {
            gzipStream.CopyTo(outputStream);
        }
        return outputStream.ToArray();
    }

    public static byte[] EncryptAes128Ecb(byte[] data, string hexKey)
    {
        if (string.IsNullOrEmpty(hexKey) || hexKey.Length != 32)
            throw new ArgumentException("Encryption key must be a 32-character hex string (16 bytes)", nameof(hexKey));

        byte[] keyBytes = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            keyBytes[i] = Convert.ToByte(hexKey.Substring(i * 2, 2), 16);
        }

        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }

    public static byte[] DecryptAes128Ecb(byte[] encryptedData, string hexKey)
    {
        if (string.IsNullOrEmpty(hexKey) || hexKey.Length != 32)
            throw new ArgumentException("Encryption key must be a 32-character hex string (16 bytes)", nameof(hexKey));

        byte[] keyBytes = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            keyBytes[i] = Convert.ToByte(hexKey.Substring(i * 2, 2), 16);
        }

        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
    }
}

