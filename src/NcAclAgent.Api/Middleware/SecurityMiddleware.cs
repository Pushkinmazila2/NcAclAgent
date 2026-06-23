using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Api.Middleware;

/// <summary>
/// Порядок проверок каждого запроса:
/// 1. Rate limit
/// 2. mTLS — CA thumbprint, EKU, срок действия, (опционально) листовой thumbprint
/// 3. Bearer токен
/// 4. Генерация RequestId
/// </summary>
public class SecurityMiddleware
{
    private readonly RequestDelegate              _next;
    private readonly AgentConfiguration          _config;
    private readonly IEventLogWriter             _eventLog;
    private readonly ILogger<SecurityMiddleware> _logger;

    public SecurityMiddleware(
        RequestDelegate next,
        IOptions<AgentConfiguration> config,
        IEventLogWriter eventLog,
        ILogger<SecurityMiddleware> logger)
    {
        _next     = next;
        _config   = config.Value;
        _eventLog = eventLog;
        _logger   = logger;
    }

    public async Task InvokeAsync(HttpContext context, IRateLimiter rateLimiter)
    {
        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // ── 1. Rate limit ─────────────────────────────────────────────
        var rateCheck = rateLimiter.CheckRequest(remoteIp);
        if (!rateCheck.Allowed)
        {
            _eventLog.WriteWarning(EventIds.RateLimitExceeded,
                $"Rate limit: IP={remoteIp} | {rateCheck.BlockReason}");
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            return;
        }

        // ── 2. mTLS ───────────────────────────────────────────────────
        var clientCert = await context.Connection.GetClientCertificateAsync();

        var certResult = ValidateClientCertificate(clientCert, remoteIp);
        if (!certResult.Valid)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        // ── 3. Bearer токен ───────────────────────────────────────────
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
        if (authHeader is null || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            _eventLog.WriteWarning(EventIds.AuthTokenInvalid,
                $"Нет Bearer токена | IP={remoteIp}");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var token = authHeader["Bearer ".Length..].Trim();
        if (!SecureCompare(token, _config.Security.BearerToken))
        {
            _eventLog.WriteWarning(EventIds.AuthTokenInvalid,
                $"Неверный Bearer токен | IP={remoteIp}");
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        // ── 4. RequestId — генерируем или берём из заголовка ──────────
        var requestId = context.Request.Headers["X-Request-Id"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(requestId))
            requestId = GenerateRequestId();

        context.Items["RemoteIp"]  = remoteIp;
        context.Items["RequestId"] = requestId;
        context.Response.Headers["X-Request-Id"] = requestId;

        await _next(context);
    }

    // ── Валидация клиентского сертификата ─────────────────────────────

    private CertValidationResult ValidateClientCertificate(X509Certificate2? cert, string remoteIp)
    {
        var certCfg = _config.Security.ClientCertificate;

        if (cert is null)
        {
            _eventLog.WriteWarning(EventIds.AuthCertInvalid,
                $"Клиентский сертификат отсутствует | IP={remoteIp}");
            return CertValidationResult.Fail;
        }

        // ── Срок действия ─────────────────────────────────────────────
        var now = DateTime.UtcNow;
        if (now < cert.NotBefore || now > cert.NotAfter)
        {
            var isExpired = now > cert.NotAfter;

            // В Test режиме просроченный сертификат можно разрешить явно в конфиге
            if (isExpired && _config.Mode == AgentMode.Test && certCfg.AllowExpiredInTestMode)
            {
                _logger.LogWarning(
                    "TEST режим: просроченный клиентский сертификат разрешён | Thumbprint={T} | IP={IP}",
                    cert.Thumbprint, remoteIp);
            }
            else
            {
                var reason = isExpired
                    ? $"Истёк: {cert.NotAfter:O}"
                    : $"Ещё не действителен с: {cert.NotBefore:O}";

                _eventLog.WriteWarning(EventIds.AuthCertExpired,
                    $"Недействительный период сертификата | {reason} | " +
                    $"Thumbprint={cert.Thumbprint} | IP={remoteIp}");
                return CertValidationResult.Fail;
            }
        }

        // ── EKU — Client Authentication ───────────────────────────────
        var hasRequiredEku = cert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Any(eku => eku.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(oid => oid.Value == certCfg.RequiredEku));

        if (!hasRequiredEku)
        {
            _eventLog.WriteWarning(EventIds.AuthCertEkuInvalid,
                $"Отсутствует требуемый EKU ({certCfg.RequiredEku}) | " +
                $"Thumbprint={cert.Thumbprint} | IP={remoteIp}");
            return CertValidationResult.Fail;
        }

        // ── CA thumbprint ─────────────────────────────────────────────
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.Build(cert);

        var caMatch = chain.ChainElements
            .Cast<X509ChainElement>()
            .Any(el => el.Certificate.Thumbprint.Equals(
                certCfg.TrustedCaThumbprint, StringComparison.OrdinalIgnoreCase));

        if (!caMatch)
        {
            _eventLog.WriteWarning(EventIds.AuthCertInvalid,
                $"CA thumbprint не совпадает | Ожидался: {certCfg.TrustedCaThumbprint} | " +
                $"Thumbprint сертификата: {cert.Thumbprint} | IP={remoteIp}");
            return CertValidationResult.Fail;
        }

        // ── Листовой thumbprint (опционально — дополнительное закрепление) ──
        if (!string.IsNullOrWhiteSpace(certCfg.Thumbprint))
        {
            if (!cert.Thumbprint.Equals(certCfg.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                _eventLog.WriteWarning(EventIds.AuthCertInvalid,
                    $"Листовой thumbprint не совпадает | " +
                    $"Ожидался: {certCfg.Thumbprint} | Получен: {cert.Thumbprint} | IP={remoteIp}");
                return CertValidationResult.Fail;
            }
        }

        return CertValidationResult.Ok;
    }

    // ── Утилиты ───────────────────────────────────────────────────────

    /// <summary>Сравнение за постоянное время — защита от timing attack</summary>
    private static bool SecureCompare(string a, string b)
    {
        var aBytes = System.Text.Encoding.UTF8.GetBytes(a);
        var bBytes = System.Text.Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    /// <summary>YYYYMMDD-HHmmss-{8 hex}</summary>
    private static string GenerateRequestId()
    {
        var now = DateTime.UtcNow;
        var rnd = RandomNumberGenerator.GetBytes(4);
        return $"{now:yyyyMMdd-HHmmss}-{Convert.ToHexString(rnd).ToLowerInvariant()}";
    }

    private record CertValidationResult(bool Valid)
    {
        public static readonly CertValidationResult Ok   = new(true);
        public static readonly CertValidationResult Fail = new(false);
    }
}
