using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using NcAclAgent.Api.Middleware;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;
using NcAclAgent.Core.Services;

var builder = WebApplication.CreateBuilder(args);

// UseWindowsService регистрируется при публикации с пакетом
// Microsoft.Extensions.Hosting.WindowsServices (win-x64 publish)
// На Linux/CI этот вызов отсутствует

// ── Режим ─────────────────────────────────────────────────────────────
var modeStr = Environment.GetEnvironmentVariable("NCACL_MODE") ?? "Test";
var mode    = Enum.TryParse<AgentMode>(modeStr, ignoreCase: true, out var m) ? m : AgentMode.Test;

builder.Configuration
    .AddJsonFile("appsettings.json",         optional: false, reloadOnChange: false)
    .AddJsonFile($"appsettings.{mode}.json", optional: true,  reloadOnChange: false)
    .AddEnvironmentVariables("NCACL_");

builder.Services.Configure<AgentConfiguration>(builder.Configuration.GetSection("Agent"));

// ── Kestrel ───────────────────────────────────────────────────────────
builder.WebHost.ConfigureKestrel((ctx, options) =>
{
    var cfg = ctx.Configuration.GetSection("Agent").Get<AgentConfiguration>();
    if (cfg is null) return;

    if (!System.Net.IPAddress.TryParse(cfg.Listen.IpAddress, out var ip))
        ip = System.Net.IPAddress.Loopback;

    options.Listen(ip, cfg.Listen.Port, lo =>
    {
        lo.UseHttps(https =>
        {
            if (File.Exists(cfg.Listen.CertificatePath))
                https.ServerCertificate = new X509Certificate2(
                    cfg.Listen.CertificatePath, cfg.Listen.CertificatePassword);
            https.ClientCertificateMode       = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (_, _, _) => true;
        });
    });
});

// ── DI ────────────────────────────────────────────────────────────────
builder.Services.AddControllers();

builder.Services.AddSingleton<IEventLogWriter,    WindowsEventLogWriter>();
builder.Services.AddSingleton<IRateLimiter,       RateLimiter>();
builder.Services.AddSingleton<IPathValidator,     PathValidator>();
builder.Services.AddSingleton<IGroupNameService,  GroupNameService>();
builder.Services.AddSingleton<ISelfTestService,   SelfTestService>();

builder.Services.AddScoped<IAdGroupValidator,     AdGroupValidator>();
builder.Services.AddScoped<IAclService,           AclService>();
builder.Services.AddScoped<IAdUserService,        AdUserService>();
builder.Services.AddScoped<IAdGroupService,       AdGroupService>();
builder.Services.AddScoped<IOperationAuthService, OperationAuthService>();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
if (OperatingSystem.IsWindows())
    builder.Logging.AddEventLog(s => s.SourceName = "NextcloudAclAgent");

// ── Pipeline ──────────────────────────────────────────────────────────
var app = builder.Build();

app.UseMiddleware<SecurityMiddleware>();
app.UseRouting();
app.MapControllers();

// ── Self-Test при старте ──────────────────────────────────────────────
using (var scope = app.Services.CreateScope())
{
    var selfTest = scope.ServiceProvider.GetRequiredService<ISelfTestService>();
    var eventLog = scope.ServiceProvider.GetRequiredService<IEventLogWriter>();
    var result   = selfTest.Run();

    if (!result.Passed && mode == AgentMode.Prod)
    {
        eventLog.WriteError(EventIds.SelfTestFailed, "Агент остановлен: Self-test FAILED (Prod)");
        Environment.Exit(1);
    }

    eventLog.WriteInformation(EventIds.AgentStarted,
        $"NcAclAgent запущен | Mode={mode} | PID={Environment.ProcessId}");
}

app.Lifetime.ApplicationStopping.Register(() =>
{
    using var scope  = app.Services.CreateScope();
    var eventLog     = scope.ServiceProvider.GetRequiredService<IEventLogWriter>();
    eventLog.WriteInformation(EventIds.AgentStopped, $"NcAclAgent остановлен | Mode={mode}");
});

app.Run();
