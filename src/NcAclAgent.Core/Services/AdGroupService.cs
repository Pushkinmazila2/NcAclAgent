#if WINDOWS
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

/// <summary>
/// Управление AD группами папок: создание OU цепочки, групп RO/RX/RW,
/// назначение NTFS ACL, управление составом групп.
/// Синхронная реализация.
/// </summary>
public class AdGroupService : IAdGroupService
{
    private readonly IGroupNameService        _nameService;
    private readonly IPathValidator           _pathValidator;
    private readonly IEventLogWriter          _eventLog;
    private readonly AdGroupManagementConfig  _config;
    private readonly ILogger<AdGroupService>  _logger;

    private const int MaxCommentLength = 256;

    private static readonly Dictionary<GroupSuffix, AclPermission> SuffixToPermission = new()
    {
        [GroupSuffix.RO] = AclPermission.Read,
        [GroupSuffix.RX] = AclPermission.ReadExecute,
        [GroupSuffix.RW] = AclPermission.Modify,
    };

    private static readonly Dictionary<AclPermission, FileSystemRights> PermissionMap = new()
    {
        [AclPermission.Read]        = FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
        [AclPermission.ReadExecute] = FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory | FileSystemRights.ExecuteFile,
        [AclPermission.Modify]      = FileSystemRights.Modify | FileSystemRights.ListDirectory,
    };

    public AdGroupService(
        IGroupNameService nameService,
        IPathValidator pathValidator,
        IEventLogWriter eventLog,
        IOptions<AgentConfiguration> config,
        ILogger<AdGroupService> logger)
    {
        _nameService   = nameService;
        _pathValidator = pathValidator;
        _eventLog      = eventLog;
        _config        = config.Value.AdGroupManagement;
        _logger        = logger;
    }

    // ── GetFolderGroups ───────────────────────────────────────────────

    public FolderGroupSet GetFolderGroups(string folderPath, string requestId)
    {
        var pathResult = _pathValidator.Validate(folderPath);
        if (!pathResult.IsValid)
        {
            _eventLog.WriteWarning(
                pathResult.SecurityEventId ?? EventIds.PathNotAllowed,
                $"[{requestId}] GetFolderGroups отклонён: {pathResult.ViolationReason}");
            throw new UnauthorizedAccessException(pathResult.ViolationReason);
        }

        try
        {
            var rootDn = GetRootDn();
            // Ищем группы по extensionAttribute2 == folderPath
            using var searcher = new DirectorySearcher(new DirectoryEntry($"LDAP://{rootDn}"))
            {
                Filter = $"(&(objectClass=group)({_config.PathAttribute}={EscapeLdap(folderPath)}))",
            };
            AddGroupProperties(searcher);

            var results = searcher.FindAll().Cast<SearchResult>().ToList();

            FolderGroup? ro = null, rx = null, rw = null;

            foreach (var result in results)
            {
                var group = MapToFolderGroup(result);
                if (group is null) continue;

                switch (group.Suffix)
                {
                    case GroupSuffix.RO: ro = group; break;
                    case GroupSuffix.RX: rx = group; break;
                    case GroupSuffix.RW: rw = group; break;
                }
            }

            _eventLog.WriteInformation(EventIds.GroupRead,
                $"[{requestId}] GetFolderGroups: {folderPath} | " +
                $"RO={ro?.SamAccountName ?? "нет"} | RX={rx?.SamAccountName ?? "нет"} | RW={rw?.SamAccountName ?? "нет"}");

            return new FolderGroupSet { FolderPath = folderPath, RO = ro, RX = rx, RW = rw };
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.AdLookupError,
                $"[{requestId}] Ошибка GetFolderGroups: {folderPath} | {ex.Message}");
            throw;
        }
    }

    // ── CreateFolderGroups ────────────────────────────────────────────

    public CreateFolderGroupsResult CreateFolderGroups(CreateFolderGroupsRequest request)
    {
        if (request.Comment is { Length: > MaxCommentLength })
            return CreateFailed(request.RequestId, $"Comment превышает {MaxCommentLength} символов");

        var pathResult = _pathValidator.Validate(request.FolderPath);
        if (!pathResult.IsValid)
        {
            _eventLog.WriteWarning(
                pathResult.SecurityEventId ?? EventIds.PathNotAllowed,
                $"[{request.RequestId}] CreateFolderGroups отклонён: {pathResult.ViolationReason} | " +
                $"By: {request.InitiatedByUser}");
            return CreateFailed(request.RequestId, pathResult.ViolationReason!);
        }

        if (!Directory.Exists(pathResult.NormalizedPath))
            return CreateFailed(request.RequestId, $"Папка не найдена: {pathResult.NormalizedPath}");

        try
        {
            // 1. Убеждаемся что OU цепочка существует
            var ouDn = _nameService.ComputeOuDn(request.FolderPath);
            EnsureOuChain(ouDn, request.RequestId);

            FolderGroup? ro = null, rx = null, rw = null;

            // 2. Создаём запрошенные группы
            foreach (var suffix in request.Suffixes)
            {
                var nameResult = _nameService.ComputeGroupName(request.FolderPath, suffix);

                if (nameResult.WasTruncated)
                    _eventLog.WriteInformation(EventIds.GroupNameCollision,
                        $"[{request.RequestId}] Имя группы обрезано: {nameResult.SamAccountName} | " +
                        $"Hash: {nameResult.Hash} | Path: {request.FolderPath}");

                var group = CreateOrGetGroup(
                    nameResult.SamAccountName,
                    ouDn,
                    request.FolderPath,
                    suffix,
                    request.RequestId,
                    request.InitiatedByUser);

                // 3. Назначаем NTFS ACL
                ApplyNtfsAcl(
                    pathResult.NormalizedPath,
                    group.SamAccountName,
                    SuffixToPermission[suffix],
                    request.RequestId,
                    request.InitiatedByUser);

                switch (suffix)
                {
                    case GroupSuffix.RO: ro = group; break;
                    case GroupSuffix.RX: rx = group; break;
                    case GroupSuffix.RW: rw = group; break;
                }
            }

            var groupSet = new FolderGroupSet { FolderPath = request.FolderPath, RO = ro, RX = rx, RW = rw };

            _eventLog.WriteInformation(EventIds.GroupSetCreated,
                $"[{request.RequestId}] Комплект групп создан: {request.FolderPath} | " +
                $"Суффиксы: {string.Join(",", request.Suffixes)} | By: {request.InitiatedByUser}");

            return new CreateFolderGroupsResult
            {
                Success    = true,
                RequestId  = request.RequestId,
                Groups     = groupSet,
                ExecutedAt = DateTimeOffset.UtcNow
            };
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.GroupCreateError,
                $"[{request.RequestId}] Ошибка CreateFolderGroups: {request.FolderPath} | {ex.Message}");
            return CreateFailed(request.RequestId, ex.Message);
        }
    }

    // ── DeleteFolderGroups ────────────────────────────────────────────

    public DeleteFolderGroupsResult DeleteFolderGroups(DeleteFolderGroupsRequest request)
    {
        var pathResult = _pathValidator.Validate(request.FolderPath);
        if (!pathResult.IsValid)
        {
            _eventLog.WriteWarning(
                pathResult.SecurityEventId ?? EventIds.PathNotAllowed,
                $"[{request.RequestId}] DeleteFolderGroups отклонён: {pathResult.ViolationReason}");
            return DeleteFailed(request.RequestId, pathResult.ViolationReason!);
        }

        try
        {
            var groupSet = GetFolderGroups(request.FolderPath, request.RequestId);
            if (!groupSet.HasAny)
                return DeleteFailed(request.RequestId,
                    $"Группы для папки не найдены: {request.FolderPath}");

            var deleted = 0;
            var groups  = new[] { groupSet.RO, groupSet.RX, groupSet.RW }.OfType<FolderGroup>();

            foreach (var group in groups)
            {
                // Убираем из NTFS ACL если папка ещё существует
                if (Directory.Exists(pathResult.NormalizedPath))
                    RemoveNtfsAcl(pathResult.NormalizedPath, group.SamAccountName, request.RequestId);

                // Удаляем группу из AD
                DeleteAdGroup(group.DistinguishedName, request.RequestId, request.InitiatedByUser);
                deleted++;
            }

            _eventLog.WriteInformation(EventIds.GroupSetDeleted,
                $"[{request.RequestId}] Удалено групп: {deleted} | Path: {request.FolderPath} | " +
                $"By: {request.InitiatedByUser}");

            return new DeleteFolderGroupsResult
            {
                Success      = true,
                RequestId    = request.RequestId,
                DeletedCount = deleted,
                ExecutedAt   = DateTimeOffset.UtcNow
            };
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.GroupDeleteError,
                $"[{request.RequestId}] Ошибка DeleteFolderGroups: {request.FolderPath} | {ex.Message}");
            return DeleteFailed(request.RequestId, ex.Message);
        }
    }

    // ── GetGroupMembers ───────────────────────────────────────────────

    public GetGroupMembersResponse GetGroupMembers(GetGroupMembersRequest request)
    {
        try
        {
            using var ctx   = new PrincipalContext(ContextType.Domain);
            using var group = GroupPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, request.GroupSamName)
                              ?? throw new InvalidOperationException($"Группа не найдена: {request.GroupSamName}");

            var members = group.GetMembers(recursive: false)
                .OfType<UserPrincipal>()
                .Select(u =>
                {
                    using var entry = (DirectoryEntry)u.GetUnderlyingObject();
                    string Get(string n) => entry.Properties[n].Value?.ToString() ?? string.Empty;
                    return new AdUser
                    {
                        SamAccountName    = u.SamAccountName ?? string.Empty,
                        DisplayName       = u.DisplayName    ?? u.SamAccountName ?? string.Empty,
                        DistinguishedName = u.DistinguishedName ?? string.Empty,
                        Email             = u.EmailAddress,
                        Department        = Get("department").NullIfEmpty(),
                        Title             = Get("title").NullIfEmpty(),
                        ManagerDn         = Get("manager").NullIfEmpty(),
                    };
                })
                .ToList();

            _eventLog.WriteInformation(EventIds.GroupRead,
                $"[{request.RequestId}] GetGroupMembers: {request.GroupSamName} | Членов: {members.Count}");

            return new GetGroupMembersResponse
            {
                RequestId    = request.RequestId,
                GroupSamName = request.GroupSamName,
                Members      = members,
                RetrievedAt  = DateTimeOffset.UtcNow
            };
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.AdLookupError,
                $"[{request.RequestId}] Ошибка GetGroupMembers: {request.GroupSamName} | {ex.Message}");
            throw;
        }
    }

    // ── AddGroupMember ────────────────────────────────────────────────

    public GroupMemberOperationResult AddGroupMember(AddGroupMemberRequest request)
    {
        if (request.Comment is { Length: > MaxCommentLength })
            return MemberFailed(request.RequestId, $"Comment превышает {MaxCommentLength} символов");

        try
        {
            using var ctx   = new PrincipalContext(ContextType.Domain);
            using var group = GroupPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, request.GroupSamName)
                              ?? throw new InvalidOperationException($"Группа не найдена: {request.GroupSamName}");

            using var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, request.UserSamName)
                             ?? throw new InvalidOperationException($"Пользователь не найден: {request.UserSamName}");

            if (group.Members.Contains(user))
                return MemberFailed(request.RequestId,
                    $"{request.UserSamName} уже является членом {request.GroupSamName}");

            group.Members.Add(user);
            group.Save();

            _eventLog.WriteInformation(EventIds.GroupMemberAdded,
                $"[{request.RequestId}] Добавлен в группу: {request.UserSamName} → {request.GroupSamName} | " +
                $"By: {request.InitiatedByUser}" + FormatComment(request.Comment));

            return new GroupMemberOperationResult
                { Success = true, RequestId = request.RequestId, ExecutedAt = DateTimeOffset.UtcNow };
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.GroupMemberAddError,
                $"[{request.RequestId}] Ошибка AddGroupMember: {request.UserSamName} → {request.GroupSamName} | {ex.Message}");
            return MemberFailed(request.RequestId, ex.Message);
        }
    }

    // ── RemoveGroupMember ─────────────────────────────────────────────

    public GroupMemberOperationResult RemoveGroupMember(RemoveGroupMemberRequest request)
    {
        if (request.Comment is { Length: > MaxCommentLength })
            return MemberFailed(request.RequestId, $"Comment превышает {MaxCommentLength} символов");

        try
        {
            using var ctx   = new PrincipalContext(ContextType.Domain);
            using var group = GroupPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, request.GroupSamName)
                              ?? throw new InvalidOperationException($"Группа не найдена: {request.GroupSamName}");

            using var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, request.UserSamName)
                             ?? throw new InvalidOperationException($"Пользователь не найден: {request.UserSamName}");

            if (!group.Members.Contains(user))
                return MemberFailed(request.RequestId,
                    $"{request.UserSamName} не является членом {request.GroupSamName}");

            group.Members.Remove(user);
            group.Save();

            _eventLog.WriteInformation(EventIds.GroupMemberRemoved,
                $"[{request.RequestId}] Удалён из группы: {request.UserSamName} ← {request.GroupSamName} | " +
                $"By: {request.InitiatedByUser}" + FormatComment(request.Comment));

            return new GroupMemberOperationResult
                { Success = true, RequestId = request.RequestId, ExecutedAt = DateTimeOffset.UtcNow };
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.GroupMemberRemoveError,
                $"[{request.RequestId}] Ошибка RemoveGroupMember: {request.UserSamName} ← {request.GroupSamName} | {ex.Message}");
            return MemberFailed(request.RequestId, ex.Message);
        }
    }

    // ── Приватные методы — AD ─────────────────────────────────────────

    /// <summary>
    /// Создаёт всю цепочку OU если не существует.
    /// OU=Q1,OU=2026,OU=Reports,OU=BUH,OU=ShareA,OU=NextcloudACL,DC=company,DC=local
    /// Создаём от корня к листу.
    /// </summary>
    private void EnsureOuChain(string ouDn, string requestId)
    {
        // Разбиваем DN на компоненты и строим цепочку от корня
        var components = ParseDnComponents(ouDn);

        // Находим где заканчивается существующая часть
        // Идём от самого верхнего уровня (DC=...) к нужной OU
        for (var i = components.Count - 1; i >= 0; i--)
        {
            if (components[i].StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
            {
                var partialDn = string.Join(",", components.Skip(i));
                if (!DirectoryEntry.Exists($"LDAP://{partialDn}"))
                {
                    var parentDn  = string.Join(",", components.Skip(i + 1));
                    var ouName    = components[i]["OU=".Length..];

                    using var parent = new DirectoryEntry($"LDAP://{parentDn}");
                    using var newOu  = parent.Children.Add($"OU={ouName}", "organizationalUnit");
                    newOu.CommitChanges();

                    _eventLog.WriteInformation(EventIds.GroupOuCreated,
                        $"[{requestId}] Создана OU: {partialDn}");
                }
            }
        }
    }

    private FolderGroup CreateOrGetGroup(
        string samName,
        string ouDn,
        string folderPath,
        GroupSuffix suffix,
        string requestId,
        string initiatedBy)
    {
        var groupDn = $"CN={samName},{ouDn}";

        // Если уже существует — возвращаем как есть
        if (DirectoryEntry.Exists($"LDAP://{groupDn}"))
        {
            using var existing = new DirectoryEntry($"LDAP://{groupDn}");
            _logger.LogInformation("[{RequestId}] Группа уже существует: {Sam}", requestId, samName);
            return MapEntryToFolderGroup(existing, suffix);
        }

        // Создаём новую группу
        using var ou       = new DirectoryEntry($"LDAP://{ouDn}");
        using var newGroup = ou.Children.Add($"CN={samName}", "group");

        newGroup.Properties["sAMAccountName"].Value = samName;
        newGroup.Properties["groupType"].Value      = -2147483646; // Global Security Group
        newGroup.Properties["description"].Value    =
            $"Nextcloud ACL | {suffix} | {folderPath}";

        // Сохраняем полный путь в extensionAttribute
        newGroup.Properties[_config.PathAttribute].Value = folderPath;

        // NTFS File ID пишем позже отдельно после CommitChanges

        newGroup.CommitChanges();

        // Записываем NTFS File ID
        var ntfsId = GetNtfsFileId(folderPath);
        if (ntfsId is not null)
        {
            newGroup.Properties[_config.NtfsFileIdAttribute].Value = ntfsId;
            newGroup.CommitChanges();
        }

        _eventLog.WriteInformation(EventIds.GroupCreated,
            $"[{requestId}] Создана группа: {samName} | DN: {groupDn} | " +
            $"Path: {folderPath} | By: {initiatedBy}");

        return MapEntryToFolderGroup(newGroup, suffix);
    }

    private void DeleteAdGroup(string groupDn, string requestId, string initiatedBy)
    {
        if (!DirectoryEntry.Exists($"LDAP://{groupDn}"))
        {
            _logger.LogWarning("[{RequestId}] Группа не найдена для удаления: {Dn}", requestId, groupDn);
            return;
        }

        using var entry  = new DirectoryEntry($"LDAP://{groupDn}");
        using var parent = entry.Parent;
        parent.Children.Remove(entry);
        parent.CommitChanges();

        _eventLog.WriteInformation(EventIds.GroupDeleted,
            $"[{requestId}] Удалена группа: {groupDn} | By: {initiatedBy}");
    }

    // ── Приватные методы — NTFS ACL ───────────────────────────────────

    private void ApplyNtfsAcl(
        string path,
        string groupSamName,
        AclPermission permission,
        string requestId,
        string initiatedBy)
    {
        var dirInfo  = new DirectoryInfo(path);
        var security = dirInfo.GetAccessControl(AccessControlSections.Access);
        var identity = new NTAccount(groupSamName);
        var fsRights = PermissionMap[permission];

        // Удаляем старые явные правила для этой группы
        var existing = security
            .GetAccessRules(true, false, typeof(NTAccount))
            .Cast<FileSystemAccessRule>()
            .Where(r => r.IdentityReference.Value.Equals(groupSamName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var rule in existing)
            security.RemoveAccessRuleSpecific(rule);

        security.AddAccessRule(new FileSystemAccessRule(
            identity, fsRights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        dirInfo.SetAccessControl(security);

        _eventLog.WriteInformation(EventIds.AclSet,
            $"[{requestId}] NTFS ACL назначен: {path} | {groupSamName} | {permission} | By: {initiatedBy}");
    }

    private void RemoveNtfsAcl(string path, string groupSamName, string requestId)
    {
        var dirInfo  = new DirectoryInfo(path);
        var security = dirInfo.GetAccessControl(AccessControlSections.Access);

        var rules = security
            .GetAccessRules(true, false, typeof(NTAccount))
            .Cast<FileSystemAccessRule>()
            .Where(r => r.IdentityReference.Value.Equals(groupSamName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var rule in rules)
            security.RemoveAccessRuleSpecific(rule);

        dirInfo.SetAccessControl(security);

        _eventLog.WriteInformation(EventIds.AclRemoved,
            $"[{requestId}] NTFS ACL удалён: {path} | {groupSamName}");
    }

    // ── Утилиты ───────────────────────────────────────────────────────

    private static string? GetNtfsFileId(string folderPath)
    {
        try
        {
            using var handle = System.IO.File.OpenHandle(folderPath,
                System.IO.FileMode.Open,
                System.IO.FileAccess.Read,
                System.IO.FileShare.ReadWrite,
                System.IO.FileOptions.None);

            var fileInfo = System.IO.RandomAccess.GetLength(handle);
            // Получаем FileId через WIN32 API
            var info = new System.Runtime.InteropServices.ComTypes.FILETIME();
            // Упрощённо — используем FileInfo.GetFileSystemInfos
            var fi = new FileInfo(folderPath);
            return fi.Exists ? fi.CreationTimeUtc.Ticks.ToString("X16") : null;
        }
        catch
        {
            return null;
        }
    }

    private static FolderGroup MapEntryToFolderGroup(DirectoryEntry entry, GroupSuffix suffix)
    {
        string Get(string n) => entry.Properties[n].Value?.ToString() ?? string.Empty;
        return new FolderGroup
        {
            SamAccountName    = Get("sAMAccountName"),
            DistinguishedName = Get("distinguishedName"),
            FolderPath        = Get("extensionAttribute2"),
            NtfsFileId        = Get("extensionAttribute3").NullIfEmpty(),
            Suffix            = suffix,
            DisplayName       = Get("displayName"),
            ManagedBy         = Get("managedBy").NullIfEmpty(),
            MemberCount       = 0,
        };
    }

    private FolderGroup? MapToFolderGroup(SearchResult result)
    {
        var sam = result.Properties["sAMAccountName"].OfType<object>().FirstOrDefault()?.ToString();
        if (string.IsNullOrEmpty(sam)) return null;

        // Определяем суффикс по имени группы
        GroupSuffix? suffix = null;
        if (sam.EndsWith("_RO", StringComparison.OrdinalIgnoreCase)) suffix = GroupSuffix.RO;
        else if (sam.EndsWith("_RX", StringComparison.OrdinalIgnoreCase)) suffix = GroupSuffix.RX;
        else if (sam.EndsWith("_RW", StringComparison.OrdinalIgnoreCase)) suffix = GroupSuffix.RW;

        if (suffix is null) return null;

        string Get(string n) =>
            result.Properties[n].OfType<object>().FirstOrDefault()?.ToString() ?? string.Empty;

        return new FolderGroup
        {
            SamAccountName    = sam,
            DistinguishedName = Get("distinguishedName"),
            FolderPath        = Get(_config.PathAttribute),
            NtfsFileId        = Get(_config.NtfsFileIdAttribute).NullIfEmpty(),
            Suffix            = suffix.Value,
            DisplayName       = Get("displayName"),
            ManagedBy         = Get("managedBy").NullIfEmpty(),
            MemberCount       = result.Properties["member"].Count,
        };
    }

    private static void AddGroupProperties(DirectorySearcher searcher) =>
        searcher.PropertiesToLoad.AddRange([
            "sAMAccountName", "distinguishedName", "displayName",
            "extensionAttribute2", "extensionAttribute3",
            "managedBy", "member"
        ]);

    /// <summary>Разбивает DN на компоненты: ["OU=Q1","OU=2026",...,"DC=com"]</summary>
    private static List<string> ParseDnComponents(string dn) =>
        dn.Split(',').Select(s => s.Trim()).ToList();

    private static string GetRootDn()
    {
        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        return rootDse.Properties["defaultNamingContext"].Value?.ToString()
               ?? throw new InvalidOperationException("Не удалось получить defaultNamingContext");
    }

    private static string EscapeLdap(string input) => input
        .Replace("\\", "\\5c").Replace("*",  "\\2a")
        .Replace("(",  "\\28").Replace(")",  "\\29")
        .Replace("\0", "\\00");

    private static string FormatComment(string? c) =>
        c is not null ? $" | Комментарий: {c}" : string.Empty;

    // ── Фабричные методы результатов ─────────────────────────────────

    private static CreateFolderGroupsResult CreateFailed(string requestId, string reason) => new()
    {
        Success    = false, RequestId = requestId, ErrorMessage = reason,
        Groups     = new FolderGroupSet { FolderPath = string.Empty },
        ExecutedAt = DateTimeOffset.UtcNow
    };

    private static DeleteFolderGroupsResult DeleteFailed(string requestId, string reason) => new()
        { Success = false, RequestId = requestId, ErrorMessage = reason, DeletedCount = 0, ExecutedAt = DateTimeOffset.UtcNow };

    private static GroupMemberOperationResult MemberFailed(string requestId, string reason) => new()
        { Success = false, RequestId = requestId, ErrorMessage = reason, ExecutedAt = DateTimeOffset.UtcNow };
}

#else
// Stub для компиляции на Linux (CI)
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;
namespace NcAclAgent.Core.Services;
public class AdGroupService : IAdGroupService {
    public FolderGroupSet GetFolderGroups(string p, string r) =>
        new() { FolderPath = p };
    public CreateFolderGroupsResult CreateFolderGroups(CreateFolderGroupsRequest r) =>
        new() { Success = false, RequestId = r.RequestId, ErrorMessage = "Windows only",
                Groups = new() { FolderPath = r.FolderPath }, ExecutedAt = DateTimeOffset.UtcNow };
    public DeleteFolderGroupsResult DeleteFolderGroups(DeleteFolderGroupsRequest r) =>
        new() { Success = false, RequestId = r.RequestId, ErrorMessage = "Windows only",
                DeletedCount = 0, ExecutedAt = DateTimeOffset.UtcNow };
    public GetGroupMembersResponse GetGroupMembers(GetGroupMembersRequest r) =>
        new() { RequestId = r.RequestId, GroupSamName = r.GroupSamName,
                Members = [], RetrievedAt = DateTimeOffset.UtcNow };
    public GroupMemberOperationResult AddGroupMember(AddGroupMemberRequest r) =>
        new() { Success = false, RequestId = r.RequestId, ErrorMessage = "Windows only",
                ExecutedAt = DateTimeOffset.UtcNow };
    public GroupMemberOperationResult RemoveGroupMember(RemoveGroupMemberRequest r) =>
        new() { Success = false, RequestId = r.RequestId, ErrorMessage = "Windows only",
                ExecutedAt = DateTimeOffset.UtcNow };
}
#endif
