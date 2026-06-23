#if WINDOWS
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

/// <summary>
/// Поиск пользователей в AD и построение цепочки руководителей.
/// Синхронная реализация — DirectoryServices не поддерживает async.
/// </summary>
public class AdUserService : IAdUserService
{
    private readonly IEventLogWriter        _eventLog;
    private readonly AdManagerDelegation    _delegationConfig;
    private readonly ILogger<AdUserService> _logger;

    public AdUserService(
        IOptions<AgentConfiguration> config,
        IEventLogWriter eventLog,
        ILogger<AdUserService> logger)
    {
        _eventLog         = eventLog;
        _delegationConfig = config.Value.AdManagerDelegation;
        _logger           = logger;
    }

    public SearchUsersResponse SearchUsers(SearchUsersRequest request)
    {
        if (request.Query.Length < 3)
            return new SearchUsersResponse { RequestId = request.RequestId, Users = [] };

        try
        {
            var rootDn = GetRootDn();

            using var searcher = new DirectorySearcher(new DirectoryEntry($"LDAP://{rootDn}"))
            {
                Filter    = BuildUserSearchFilter(request.Query),
                SizeLimit = Math.Min(request.MaxResults, 100),
                PageSize  = Math.Min(request.MaxResults, 100),
            };
            AddUserProperties(searcher);

            var users = searcher.FindAll()
                .Cast<SearchResult>()
                .Select(MapSearchResultToUser)
                .OfType<AdUser>()
                .ToList();

            _eventLog.WriteInformation(EventIds.UserSearched,
                $"[{request.RequestId}] Поиск: '{request.Query}' | Найдено: {users.Count}");

            return new SearchUsersResponse { RequestId = request.RequestId, Users = users };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{RequestId}] Ошибка поиска: {Query}", request.RequestId, request.Query);
            _eventLog.WriteError(EventIds.ManagerChainError,
                $"[{request.RequestId}] Ошибка поиска пользователей: {ex.Message}");
            throw;
        }
    }

    public AdUser? GetUser(string samAccountName)
    {
        try
        {
            using var ctx  = new PrincipalContext(ContextType.Domain);
            using var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, samAccountName);

            if (user is null) return null;

            using var entry = (DirectoryEntry)user.GetUnderlyingObject();
            return MapEntryToUser(entry);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка получения пользователя: {Sam}", samAccountName);
            return null;
        }
    }

    public ManagerChain GetManagerChain(GetManagerChainRequest request)
    {
        var maxDepth = request.MaxDepth ?? _delegationConfig.MaxDepth;
        var chain    = new List<AdUser>();

        try
        {
            var subject = GetUser(request.UserSam);
            if (subject is null)
            {
                _eventLog.WriteWarning(EventIds.UserNotFound,
                    $"[{request.RequestId}] Пользователь не найден: {request.UserSam}");
                return new ManagerChain { SubjectSam = request.UserSam, Chain = [], Depth = 0 };
            }

            // Защита от циклов в AD
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { subject.SamAccountName };

            var current = subject;
            var depth   = 0;

            while (current.ManagerDn is not null && depth < maxDepth)
            {
                var manager = GetUserByDn(current.ManagerDn);
                if (manager is null) break;

                if (visited.Contains(manager.SamAccountName))
                {
                    _logger.LogWarning("Цикл в manager цепочке AD для: {Sam}", request.UserSam);
                    break;
                }

                chain.Add(manager);
                visited.Add(manager.SamAccountName);
                current = manager;
                depth++;
            }

            _eventLog.WriteInformation(EventIds.ManagerChainResolved,
                $"[{request.RequestId}] Цепочка для {request.UserSam}: " +
                $"[{string.Join(" → ", chain.Select(u => u.SamAccountName))}] | Глубина: {depth}");

            return new ManagerChain { SubjectSam = request.UserSam, Chain = chain, Depth = depth };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{RequestId}] Ошибка цепочки для: {Sam}",
                request.RequestId, request.UserSam);
            _eventLog.WriteError(EventIds.ManagerChainError,
                $"[{request.RequestId}] Ошибка: {ex.Message}");
            throw;
        }
    }

    // ── Приватные методы ──────────────────────────────────────────────

    private AdUser? GetUserByDn(string dn)
    {
        try
        {
            using var entry = new DirectoryEntry($"LDAP://{dn}");
            return MapEntryToUser(entry);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Не удалось получить пользователя по DN: {Dn} | {Error}", dn, ex.Message);
            return null;
        }
    }

    private static string GetRootDn()
    {
        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        return rootDse.Properties["defaultNamingContext"].Value?.ToString()
               ?? throw new InvalidOperationException("Не удалось получить defaultNamingContext");
    }

    private static string BuildUserSearchFilter(string query)
    {
        var e = EscapeLdap(query);
        // Только активные пользователи (не отключённые)
        return $"(&(objectClass=user)(objectCategory=person)" +
               $"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
               $"(|(sAMAccountName=*{e}*)(displayName=*{e}*)(mail=*{e}*)))";
    }

    private static void AddUserProperties(DirectorySearcher searcher) =>
        searcher.PropertiesToLoad.AddRange([
            "sAMAccountName", "displayName", "distinguishedName",
            "mail", "department", "title", "manager"
        ]);

    private static AdUser? MapSearchResultToUser(SearchResult r)
    {
        var sam = r.Properties["sAMAccountName"].OfType<object>().FirstOrDefault()?.ToString();
        var dn  = r.Properties["distinguishedName"].OfType<object>().FirstOrDefault()?.ToString();
        if (string.IsNullOrEmpty(sam) || string.IsNullOrEmpty(dn)) return null;

        return new AdUser
        {
            SamAccountName    = sam,
            DisplayName       = GetProp(r, "displayName") ?? sam,
            DistinguishedName = dn,
            Email             = GetProp(r, "mail"),
            Department        = GetProp(r, "department"),
            Title             = GetProp(r, "title"),
            ManagerDn         = GetProp(r, "manager"),
        };
    }

    private static AdUser MapEntryToUser(DirectoryEntry e)
    {
        string Get(string n) => e.Properties[n].Value?.ToString() ?? string.Empty;
        return new AdUser
        {
            SamAccountName    = Get("sAMAccountName"),
            DisplayName       = Get("displayName"),
            DistinguishedName = Get("distinguishedName"),
            Email             = Get("mail").NullIfEmpty(),
            Department        = Get("department").NullIfEmpty(),
            Title             = Get("title").NullIfEmpty(),
            ManagerDn         = Get("manager").NullIfEmpty(),
        };
    }

    private static string? GetProp(SearchResult r, string name) =>
        r.Properties[name].OfType<object>().FirstOrDefault()?.ToString().NullIfEmpty();

    /// <summary>Экранирование спецсимволов LDAP фильтра (RFC 4515)</summary>
    private static string EscapeLdap(string input) => input
        .Replace("\\", "\\5c").Replace("*",  "\\2a")
        .Replace("(",  "\\28").Replace(")",  "\\29")
        .Replace("\0", "\\00");
}

internal static class StringExtensions
{
    public static string? NullIfEmpty(this string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s;
}

#else
// Stub для компиляции на Linux (CI)
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;
namespace NcAclAgent.Core.Services;
public class AdUserService : IAdUserService {
    public SearchUsersResponse SearchUsers(SearchUsersRequest r) =>
        new() { RequestId = r.RequestId, Users = [] };
    public AdUser? GetUser(string sam) => null;
    public ManagerChain GetManagerChain(GetManagerChainRequest r) =>
        new() { SubjectSam = r.UserSam, Chain = [], Depth = 0 };
}
#endif
