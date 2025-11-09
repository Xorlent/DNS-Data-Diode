using System.IO;
using Microsoft.Extensions.Hosting;

namespace DNSDiode;

public class DNSDiodeService : BackgroundService
{
    private readonly EventLogWriter _eventLog;
    private FileSystemWatcher? _fileWatcher;
    private FileProcessor? _fileProcessor;
    private DnsServer? _dnsServer;

    public DNSDiodeService()
    {
        _eventLog = new EventLogWriter();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _eventLog.WriteInfo("DNSDiode Service starting...");

        try
        {
            if (ConfigurationManager.IsClientMode())
            {
                await StartClientModeAsync(stoppingToken);
            }
            else if (ConfigurationManager.IsServerMode())
            {
                await StartServerModeAsync(stoppingToken);
            }
            else
            {
                _eventLog.WriteError("Invalid or missing Mode configuration. Must be 'Client' or 'Server'.");
                return;
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when service is stopping
        }
        catch (Exception ex)
        {
            _eventLog.WriteError($"Service error: {ex.Message}");
            throw;
        }
    }

    private async Task StartClientModeAsync(CancellationToken stoppingToken)
    {
        _eventLog.WriteInfo("Starting in Client mode...");

        string? monitorFolder = ConfigurationManager.GetMonitorFolder();
        if (string.IsNullOrEmpty(monitorFolder))
        {
            _eventLog.WriteError("MonitorFolder not configured");
            return;
        }

        if (!Directory.Exists(monitorFolder))
        {
            try
            {
                Directory.CreateDirectory(monitorFolder);
                _eventLog.WriteInfo($"Created monitor folder: {monitorFolder}");
            }
            catch (Exception ex)
            {
                _eventLog.WriteError($"Failed to create monitor folder: {monitorFolder}. Error: {ex.Message}");
                return;
            }
        }

        _fileProcessor = new FileProcessor(_eventLog);

        _fileWatcher = new FileSystemWatcher(monitorFolder)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };

        _fileWatcher.Created += async (sender, e) =>
        {
            // Wait a short delay to allow file to be fully written and released by the copying process
            await Task.Delay(500);
            
            if (File.Exists(e.FullPath))
            {
                _fileProcessor.TryEnqueueFile(e.FullPath);
            }
        };

        // Process existing files
        try
        {
            var existingFiles = Directory.GetFiles(monitorFolder);
            foreach (var file in existingFiles)
            {
                if (File.Exists(file))
                {
                    _fileProcessor.TryEnqueueFile(file);
                }
            }
        }
        catch (Exception ex)
        {
            _eventLog.WriteError($"Error processing existing files: {ex.Message}");
        }

        _eventLog.WriteInfo($"Client mode started. Monitoring folder: {monitorFolder}");

        // Keep service running
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(1000, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when service is stopping
        }
    }

    private async Task StartServerModeAsync(CancellationToken stoppingToken)
    {
        _eventLog.WriteInfo("Starting in Server mode...");

        string? destinationFolder = ConfigurationManager.GetDestinationFolder();
        if (string.IsNullOrEmpty(destinationFolder))
        {
            _eventLog.WriteError("DestinationFolder not configured");
            return;
        }

        if (!Directory.Exists(destinationFolder))
        {
            try
            {
                Directory.CreateDirectory(destinationFolder);
                _eventLog.WriteInfo($"Created destination folder: {destinationFolder}");
            }
            catch (Exception ex)
            {
                _eventLog.WriteError($"Failed to create destination folder: {destinationFolder}. Error: {ex.Message}");
                return;
            }
        }

        _dnsServer = new DnsServer(_eventLog);
        _eventLog.WriteInfo($"Server mode started. Destination folder: {destinationFolder}");
        await _dnsServer.StartAsync(stoppingToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _eventLog.WriteInfo("DNSDiode Service stopping...");

        _fileWatcher?.Dispose();
        _dnsServer?.Stop();

        await base.StopAsync(cancellationToken);
    }

    public override void Dispose()
    {
        _fileWatcher?.Dispose();
        _dnsServer?.Stop();
        base.Dispose();
    }
}

