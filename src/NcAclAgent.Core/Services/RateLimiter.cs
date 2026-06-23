using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

public class RateLimiter : IRateLimiter
{
    private readonly RateLimitConfig _config;
    private readonly IEventLogWriter _eventLog;

    private readonly ConcurrentDictionary<string, Queue<DateTime>> _requestWindows = new();
    private readonly ConcurrentDictionary<string, Queue<DateTime>> _aclChangeWindows = new();
    private readonly ConcurrentDictionary<string, DateTime>        _blockedIps = new();

    public RateLimiter(IOptions<AgentConfiguration> config, IEventLogWriter eventLog)
    {
        _config   = config.Value.RateLimit;
        _eventLog = eventLog;
    }

    public RateLimitResult CheckRequest(string ipAddress)
    {
        if (_blockedIps.TryGetValue(ipAddress, out var unblockAt))
        {
            if (DateTime.UtcNow < unblockAt)
                return new RateLimitResult
                    { Allowed = false, BlockReason = $"IP заблокирован до {unblockAt:HH:mm:ss} UTC" };

            _blockedIps.TryRemove(ipAddress, out _);
        }

        var window = _requestWindows.GetOrAdd(ipAddress, _ => new Queue<DateTime>());
        var now    = DateTime.UtcNow;

        lock (window)
        {
            while (window.Count > 0 && (now - window.Peek()).TotalSeconds > 1)
                window.Dequeue();

            if (window.Count >= _config.RequestsPerSecond)
            {
                BlockIp(ipAddress, "Превышен лимит запросов в секунду");
                return new RateLimitResult { Allowed = false, BlockReason = "Rate limit exceeded" };
            }

            window.Enqueue(now);
        }

        return new RateLimitResult { Allowed = true };
    }

    public void RecordAclChange(string ipAddress)
    {
        var window = _aclChangeWindows.GetOrAdd(ipAddress, _ => new Queue<DateTime>());
        var now    = DateTime.UtcNow;

        lock (window)
        {
            while (window.Count > 0 && (now - window.Peek()).TotalMinutes > 1)
                window.Dequeue();

            window.Enqueue(now);

            if (window.Count > _config.AclChangesPerMinute)
                BlockIp(ipAddress, "Превышен лимит изменений ACL в минуту");
        }
    }

    public bool IsBlocked(string ipAddress) =>
        _blockedIps.TryGetValue(ipAddress, out var until) && DateTime.UtcNow < until;

    private void BlockIp(string ipAddress, string reason)
    {
        var unblockAt = DateTime.UtcNow.AddMinutes(_config.BlockDurationMinutes);
        _blockedIps[ipAddress] = unblockAt;
        _eventLog.WriteWarning(EventIds.IpBlocked,
            $"IP заблокирован: {ipAddress} | Причина: {reason} | До: {unblockAt:O}");
    }
}
