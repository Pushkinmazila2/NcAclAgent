using System.Security.AccessControl;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

public class SelfTestService : ISelfTestService
{
    private readonly AgentConfiguration      _config;
    private readonly IEventLogWriter         _eventLog;
    private readonly ILogger<SelfTestService> _logger;

    public SelfTestService(
        IOptions<AgentConfiguration> config,
        IEventLogWriter eventLog,
        ILogger<SelfTestService> logger)
    {
        _config   = config.Value;
        _eventLog = eventLog;
        _logger   = logger;
    }

    public SelfTestResult Run()
    {
        _logger.LogInformation("Self-test запущен, режим: {Mode}", _config.Mode);
        var checks = new List<SelfTestCheck>();

        checks.Add(CheckEventLogAccess());
        checks.Add(CheckServiceAccount());
        checks.Add(CheckServerCertificate());
        checks.Add(CheckAllowedPathsAccessible());
        checks.Add(CheckAllowedPathsAclReadable());
        checks.Add(CheckConfigSanity());
        checks.Add(CheckShareOuMappings());

        if (_config.Mode == AgentMode.Prod)
            checks.Add(CheckProdSecretsFromEnv());

        var passed = checks.All(c => c.Passed);

        foreach (var check in checks)
        {
            var msg = $"Self-test [{check.Name}]: {(check.Passed ? "OK" : "FAIL")}" +
                      (check.Detail is not null ? $" | {check.Detail}" : "");
            if (check.Passed) _eventLog.WriteInformation(EventIds.SelfTestCheck, msg);
            else              _eventLog.WriteError(EventIds.SelfTestCheck, msg);
        }

        var summary = $"Self-test: {(passed ? "PASSED" : "FAILED")} | " +
                      $"Режим: {_config.Mode} | Провалено: {checks.Count(c => !c.Passed)}/{checks.Count}";

        if (passed) _eventLog.WriteInformation(EventIds.SelfTestPassed, summary);
        else        _eventLog.WriteError(EventIds.SelfTestFailed, summary);

        return new SelfTestResult
        {
            Passed = passed, Checks = checks,
            RanAt  = DateTimeOffset.UtcNow, Mode = _config.Mode
        };
    }

    // ── Проверки ──────────────────────────────────────────────────────

    private SelfTestCheck CheckEventLogAccess()
    {
        const string name = "EventLog.Write";
        try
        {
            _eventLog.WriteInformation(EventIds.SelfTestCheck, "[Self-test] EventLog доступен");
            return Pass(name);
        }
        catch (Exception ex) { return Fail(name, ex.Message); }
    }

    private SelfTestCheck CheckServiceAccount()
    {
        const string name = "ServiceAccount.NotSystem";
        try
        {
            var user = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            var forbidden = new[] { "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE" };
            foreach (var f in forbidden)
                if (user.StartsWith(f, StringComparison.OrdinalIgnoreCase))
                    return Fail(name, $"Запущен от запрещённого аккаунта: {user}");
            return Pass(name, $"Аккаунт: {user}");
        }
        catch (Exception ex) { return Fail(name, ex.Message); }
    }

    private SelfTestCheck CheckServerCertificate()
    {
        const string name = "Certificate.Server";
        try
        {
            var path = _config.Listen.CertificatePath;
            if (!File.Exists(path)) return Fail(name, $"Файл не найден: {path}");

            using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                path, _config.Listen.CertificatePassword);

            if (cert.NotAfter < DateTime.UtcNow)
                return Fail(name, $"Сертификат просрочен: {cert.NotAfter:O}");

            var days = (cert.NotAfter - DateTime.UtcNow).Days;
            return Pass(name, days < 30
                ? $"ВНИМАНИЕ: истекает через {days} дней"
                : $"Действителен до: {cert.NotAfter:O}");
        }
        catch (Exception ex) { return Fail(name, ex.Message); }
    }

    private SelfTestCheck CheckAllowedPathsAccessible()
    {
        const string name = "Paths.Accessible";
        var failures = _config.Paths.Allowed
            .Where(p => !Directory.Exists(p))
            .Select(p => $"{p} — не существует")
            .ToList();
        return failures.Count == 0
            ? Pass(name, $"Все {_config.Paths.Allowed.Count} путей доступны")
            : Fail(name, string.Join("; ", failures));
    }

    private SelfTestCheck CheckAllowedPathsAclReadable()
    {
        const string name = "Paths.AclReadable";
#if WINDOWS
        var failures = new List<string>();
        foreach (var path in _config.Paths.Allowed)
        {
            if (!Directory.Exists(path)) continue;
            try { new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access); }
            catch (UnauthorizedAccessException)
            { failures.Add($"{path} — нет прав читать ACL"); }
            catch (Exception ex)
            { failures.Add($"{path} — {ex.Message}"); }
        }
        return failures.Count == 0 ? Pass(name, "ACL читается на всех путях") : Fail(name, string.Join("; ", failures));
#else
        return Pass(name, "Пропущено (не Windows)");
#endif
    }

    private SelfTestCheck CheckConfigSanity()
    {
        const string name = "Config.Sanity";
        var issues = new List<string>();

        if (string.IsNullOrWhiteSpace(_config.Security.BearerToken))
            issues.Add("BearerToken не задан");
        if ((_config.Security.BearerToken?.Length ?? 0) < 32)
            issues.Add("BearerToken слишком короткий (минимум 32 символа)");
        if (string.IsNullOrWhiteSpace(_config.Security.ClientCertificate.TrustedCaThumbprint))
            issues.Add("TrustedCaThumbprint не задан");
        if (_config.Listen.IpAddress is "0.0.0.0" or "::")
            issues.Add("IpAddress = 0.0.0.0 запрещён");
        if (_config.Paths.Allowed.Count == 0)
            issues.Add("Список Allowed путей пуст");
        if (_config.NcAdminGroups.Groups.Count == 0)
            issues.Add("NcAdminGroups.Groups пуст — никто не сможет управлять правами");

        return issues.Count == 0 ? Pass(name) : Fail(name, string.Join("; ", issues));
    }

    private SelfTestCheck CheckShareOuMappings()
    {
        const string name = "AdGroupManagement.RootOUs";
        if (_config.AdGroupManagement.RootOUs.Count == 0)
            return Fail(name, "RootOUs пуст — невозможно создавать группы");

        var issues = new List<string>();
        foreach (var mapping in _config.AdGroupManagement.RootOUs)
        {
            // Проверяем что Share входит в Allowed пути
            var inAllowed = _config.Paths.Allowed.Any(a =>
                mapping.Share.StartsWith(a, StringComparison.OrdinalIgnoreCase) ||
                a.StartsWith(mapping.Share, StringComparison.OrdinalIgnoreCase));
            if (!inAllowed)
                issues.Add($"Share '{mapping.Share}' не пересекается с Paths.Allowed");
            if (string.IsNullOrWhiteSpace(mapping.OU))
                issues.Add($"OU пустой для Share '{mapping.Share}'");
        }
        return issues.Count == 0
            ? Pass(name, $"{_config.AdGroupManagement.RootOUs.Count} маппингов OK")
            : Fail(name, string.Join("; ", issues));
    }

    private SelfTestCheck CheckProdSecretsFromEnv()
    {
        const string name = "Prod.SecretsFromEnv";
        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("NCACL_AGENT__SECURITY__BEARERTOKEN")))
            missing.Add("NCACL_AGENT__SECURITY__BEARERTOKEN");
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("NCACL_AGENT__SECURITY__CLIENTCERTIFICATE__TRUSTEDCATHUMBPRINT")))
            missing.Add("NCACL_AGENT__SECURITY__CLIENTCERTIFICATE__TRUSTEDCATHUMBPRINT");
        return missing.Count == 0
            ? Pass(name, "Секреты заданы через env")
            : Fail(name, $"Не заданы env переменные: {string.Join(", ", missing)}");
    }

    private static SelfTestCheck Pass(string name, string? detail = null) =>
        new() { Name = name, Passed = true,  Detail = detail };
    private static SelfTestCheck Fail(string name, string? detail = null) =>
        new() { Name = name, Passed = false, Detail = detail };
}
