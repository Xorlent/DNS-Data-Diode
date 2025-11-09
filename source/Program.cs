using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DNSDiode;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "DNSDiode";
        });
        builder.Services.AddHostedService<DNSDiodeService>();

        var host = builder.Build();
        host.Run();
    }
}

