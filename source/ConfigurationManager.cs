using Microsoft.Win32;

namespace DNSDiode;

public class ConfigurationManager
{
    private const string RegistryPath = @"SOFTWARE\DNSDataDiode";

    public static string? GetMode()
    {
        return GetRegistryValue("Mode") as string;
    }

    public static string? GetMonitorFolder()
    {
        return GetRegistryValue("MonitorFolder") as string;
    }

    public static string? GetEncryptionKey()
    {
        return GetRegistryValue("EncryptionKey") as string;
    }

    public static string? GetDNSHostname()
    {
        return GetRegistryValue("DNSHostname") as string;
    }

    public static string? GetDNSServer()
    {
        return GetRegistryValue("DNSServer") as string;
    }

    public static int GetQueryDelayMs()
    {
        var value = GetRegistryValue("QueryDelayMs");
        if (value is int intValue)
            return intValue;
        if (value is string strValue && int.TryParse(strValue, out var parsed))
            return parsed;
        return 25; // Default 25ms
    }

    public static int GetRetries()
    {
        var value = GetRegistryValue("Retries");
        if (value is int intValue)
            return intValue;
        if (value is string strValue && int.TryParse(strValue, out var parsed))
            return parsed;
        return 5; // Default 5 retries
    }

    public static string? GetDestinationFolder()
    {
        return GetRegistryValue("DestinationFolder") as string;
    }

    public static string? GetAllowList()
    {
        return GetRegistryValue("AllowList") as string;
    }

    private static object? GetRegistryValue(string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);
            return key?.GetValue(valueName);
        }
        catch
        {
            return null;
        }
    }

    public static bool IsClientMode()
    {
        return GetMode()?.Equals("Client", StringComparison.OrdinalIgnoreCase) == true;
    }

    public static bool IsServerMode()
    {
        return GetMode()?.Equals("Server", StringComparison.OrdinalIgnoreCase) == true;
    }
}

