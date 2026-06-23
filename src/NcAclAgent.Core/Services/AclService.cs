using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

public class AclService : IAclService
{
    private readonly IPathValidator       _pathValidator;
    private readonly IAdGroupValidator    _adGroupValidator;
    private readonly IEventLogWriter      _eventLog;
    private readonly SecurityConfig       _securityConfig;
    private readonly ILogger<AclService>  _logger;

    private const int MaxCommentLength = 256;

    private static readonly Dictionary<AclPermission, FileSystemRights> PermissionMap = new()
    {
        [AclPermission.Read]        = FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
        [AclPermission.ReadExecute] = FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory | FileSystemRights.ExecuteFile,
        [AclPermission.Modify]      = FileSystemRights.Modify | FileSystemRights.ListDirectory
        // Full Control намеренно отсутствует
    };

    public AclService(
        IPathValidator      pathValidator,
        IAdGroupValidator   adGroupValidator,
        IEventLogWriter     eventLog,
        IOptions<AgentConfiguration> config,
        ILogger<AclService> logger)
    {
        _pathValidator    = pathValidator;
        _adGroupValidator = adGroupValidator;
        _eventLog         = eventLog;
        _securityConfig   = config.Value.Security;
        _logger           = logger;
    }

    // ── GetAcl ────────────────────────────────────────────────────────

    public GetAclResponse GetAcl(GetAclRequest request)
    {
        var validation = _pathValidator.Validate(request.Path);
        if (!validation.IsValid)
        {
            _eventLog.WriteWarning(
                validation.SecurityEventId ?? EventIds.PathNotAllowed,
                $"[{request.RequestId}] GetAcl отклонён: {validation.ViolationReason} | Path: {request.Path}");
            throw new UnauthorizedAccessException(validation.ViolationReason);
        }

        var dirInfo = new DirectoryInfo(validation.NormalizedPath);
        if (!dirInfo.Exists)
        {
            _eventLog.WriteError(EventIds.PathNotFound,
                $"[{request.RequestId}] Папка не найдена: {validation.NormalizedPath}");
            throw new DirectoryNotFoundException($"Папка не найдена: {validation.NormalizedPath}");
        }

        try
        {
            var security = dirInfo.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            var owner    = security.GetOwner(typeof(NTAccount))?.Value ?? "Unknown";

            var entries = security
                .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(NTAccount))
                .Cast<FileSystemAccessRule>()
                .Select(MapToAclEntry)
                .OfType<AclEntry>()
                .ToList();

            _eventLog.WriteInformation(EventIds.AclRead,
                $"[{request.RequestId}] ACL прочитан: {validation.NormalizedPath} | Записей: {entries.Count}");

            return new GetAclResponse
            {
                RequestId   = request.RequestId,
                Path        = validation.NormalizedPath,
                Owner       = owner,
                Entries     = entries,
                RetrievedAt = DateTimeOffset.UtcNow
            };
        }
        catch (UnauthorizedAccessException ex)
        {
            _eventLog.WriteError(EventIds.AclReadError,
                $"[{request.RequestId}] Нет прав чтения ACL: {validation.NormalizedPath} | {ex.Message}");
            throw;
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.AclReadError,
                $"[{request.RequestId}] Ошибка чтения ACL: {validation.NormalizedPath} | {ex.Message}");
            throw;
        }
    }

    // ── SetAcl ────────────────────────────────────────────────────────

    public AclOperationResult SetAcl(SetAclRequest request)
    {
        // Валидация Comment
        if (request.Comment is { Length: > MaxCommentLength })
            return Failed(request.RequestId, $"Comment превышает {MaxCommentLength} символов");

        // Валидация пути
        var pathResult = _pathValidator.Validate(request.Path);
        if (!pathResult.IsValid)
        {
            _eventLog.WriteWarning(
                pathResult.SecurityEventId ?? EventIds.PathNotAllowed,
                $"[{request.RequestId}] SetAcl отклонён: {pathResult.ViolationReason} | " +
                $"Path: {request.Path} | By: {request.InitiatedByUser}");
            return Failed(request.RequestId, pathResult.ViolationReason!);
        }

        // Проверка формата и локальных доменов
        if (!IsAdGroupFormat(request.GroupIdentity))
        {
            _eventLog.WriteWarning(EventIds.LocalIdentityAttempt,
                $"[{request.RequestId}] Не AD группа: {request.GroupIdentity} | By: {request.InitiatedByUser}");
            return Failed(request.RequestId, "Разрешены только доменные группы AD (DOMAIN\\GroupName)");
        }

        // Проверка защищённых групп
        if (IsProtectedGroup(request.GroupIdentity))
        {
            _eventLog.WriteWarning(EventIds.ProtectedGroupAttempt,
                $"[{request.RequestId}] Попытка изменить защищённую группу: {request.GroupIdentity} | " +
                $"By: {request.InitiatedByUser}");
            return Failed(request.RequestId, $"Группа {request.GroupIdentity} защищена от изменений");
        }

        // Проверка существования группы в AD — до любых изменений ACL
        var adResult = _adGroupValidator.ValidateGroup(request.GroupIdentity);
        if (!adResult.IsValid)
        {
            _eventLog.WriteWarning(
                adResult.ErrorEventId ?? EventIds.AdGroupNotFound,
                $"[{request.RequestId}] {adResult.ErrorMessage} | By: {request.InitiatedByUser}");
            return Failed(request.RequestId, adResult.ErrorMessage!);
        }

        var dirInfo = new DirectoryInfo(pathResult.NormalizedPath);
        if (!dirInfo.Exists)
        {
            _eventLog.WriteError(EventIds.PathNotFound,
                $"[{request.RequestId}] Папка не найдена: {pathResult.NormalizedPath}");
            return Failed(request.RequestId, "Папка не найдена");
        }

        try
        {
            var security   = dirInfo.GetAccessControl(AccessControlSections.Access);
            var identity   = new NTAccount(request.GroupIdentity);
            var fsRights   = PermissionMap[request.Permission];
            var accessType = request.Action == AclAction.Allow
                ? AccessControlType.Allow
                : AccessControlType.Deny;

            // Удаляем существующие явные правила для этой группы
            var existing = security
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(NTAccount))
                .Cast<FileSystemAccessRule>()
                .Where(r => r.IdentityReference.Value.Equals(
                    request.GroupIdentity, StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var rule in existing)
                security.RemoveAccessRuleSpecific(rule);

            // Добавляем новое правило с наследованием
            security.AddAccessRule(new FileSystemAccessRule(
                identity, fsRights,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                accessType));

            dirInfo.SetAccessControl(security);

            _eventLog.WriteInformation(EventIds.AclSet,
                $"[{request.RequestId}] ACL изменён: {pathResult.NormalizedPath} | " +
                $"Группа: {request.GroupIdentity} | Права: {request.Permission} ({request.Action}) | " +
                $"By: {request.InitiatedByUser}" +
                FormatComment(request.Comment));

            return Ok(request.RequestId);
        }
        catch (UnauthorizedAccessException ex)
        {
            _eventLog.WriteError(EventIds.AclSetError,
                $"[{request.RequestId}] Нет прав для изменения ACL: {pathResult.NormalizedPath} | {ex.Message}");
            return Failed(request.RequestId, $"Нет прав: {ex.Message}");
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.AclSetError,
                $"[{request.RequestId}] Ошибка SetAcl: {pathResult.NormalizedPath} | {ex.Message}");
            return Failed(request.RequestId, $"Внутренняя ошибка: {ex.Message}");
        }
    }

    // ── RemoveAcl ─────────────────────────────────────────────────────

    public AclOperationResult RemoveAcl(RemoveAclRequest request)
    {
        if (request.Comment is { Length: > MaxCommentLength })
            return Failed(request.RequestId, $"Comment превышает {MaxCommentLength} символов");

        var pathResult = _pathValidator.Validate(request.Path);
        if (!pathResult.IsValid)
        {
            _eventLog.WriteWarning(
                pathResult.SecurityEventId ?? EventIds.PathNotAllowed,
                $"[{request.RequestId}] RemoveAcl отклонён: {pathResult.ViolationReason} | " +
                $"By: {request.InitiatedByUser}");
            return Failed(request.RequestId, pathResult.ViolationReason!);
        }

        if (!IsAdGroupFormat(request.GroupIdentity))
        {
            _eventLog.WriteWarning(EventIds.LocalIdentityAttempt,
                $"[{request.RequestId}] Не AD группа: {request.GroupIdentity} | By: {request.InitiatedByUser}");
            return Failed(request.RequestId, "Разрешены только доменные группы AD");
        }

        if (IsProtectedGroup(request.GroupIdentity))
        {
            _eventLog.WriteWarning(EventIds.ProtectedGroupAttempt,
                $"[{request.RequestId}] Попытка удалить защищённую группу: {request.GroupIdentity} | " +
                $"By: {request.InitiatedByUser}");
            return Failed(request.RequestId, $"Группа {request.GroupIdentity} защищена от изменений");
        }

        // Проверяем существование группы в AD перед удалением
        var adResult = _adGroupValidator.ValidateGroup(request.GroupIdentity);
        if (!adResult.IsValid)
        {
            _eventLog.WriteWarning(
                adResult.ErrorEventId ?? EventIds.AdGroupNotFound,
                $"[{request.RequestId}] {adResult.ErrorMessage} | By: {request.InitiatedByUser}");
            return Failed(request.RequestId, adResult.ErrorMessage!);
        }

        var dirInfo = new DirectoryInfo(pathResult.NormalizedPath);
        if (!dirInfo.Exists)
            return Failed(request.RequestId, "Папка не найдена");

        try
        {
            var security = dirInfo.GetAccessControl(AccessControlSections.Access);

            var rules = security
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(NTAccount))
                .Cast<FileSystemAccessRule>()
                .Where(r => r.IdentityReference.Value.Equals(
                    request.GroupIdentity, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (rules.Count == 0)
                return Failed(request.RequestId,
                    $"Группа {request.GroupIdentity} не найдена в ACL папки");

            // RemoveAccessRuleSpecific — точное совпадение, без partial match
            foreach (var rule in rules)
                security.RemoveAccessRuleSpecific(rule);

            dirInfo.SetAccessControl(security);

            _eventLog.WriteInformation(EventIds.AclRemoved,
                $"[{request.RequestId}] ACL удалён: {pathResult.NormalizedPath} | " +
                $"Группа: {request.GroupIdentity} | By: {request.InitiatedByUser}" +
                FormatComment(request.Comment));

            return Ok(request.RequestId);
        }
        catch (Exception ex)
        {
            _eventLog.WriteError(EventIds.AclSetError,
                $"[{request.RequestId}] Ошибка RemoveAcl: {pathResult.NormalizedPath} | {ex.Message}");
            return Failed(request.RequestId, ex.Message);
        }
    }

    // ── Вспомогательные методы ────────────────────────────────────────

    private static AclEntry? MapToAclEntry(FileSystemAccessRule rule)
    {
        var identity = rule.IdentityReference.Value;
        if (IsBuiltinIdentity(identity)) return null;

        var permission = MapFromFileSystemRights(rule.FileSystemRights);
        if (permission is null) return null;

        return new AclEntry
        {
            IdentityReference = identity,
            Permission        = permission.Value,
            Action            = rule.AccessControlType == AccessControlType.Allow
                                    ? AclAction.Allow : AclAction.Deny,
            IsInherited       = rule.IsInherited
        };
    }

    private static AclPermission? MapFromFileSystemRights(FileSystemRights rights)
    {
        // Full Control показываем как Modify (не раскрываем полный объём)
        if (rights.HasFlag(FileSystemRights.FullControl))  return AclPermission.Modify;
        if (rights.HasFlag(FileSystemRights.Modify))       return AclPermission.Modify;
        if (rights.HasFlag(FileSystemRights.ReadAndExecute)) return AclPermission.ReadExecute;
        if (rights.HasFlag(FileSystemRights.Read) ||
            rights.HasFlag(FileSystemRights.ListDirectory)) return AclPermission.Read;
        return null;
    }

    private static bool IsBuiltinIdentity(string identity) =>
        identity.StartsWith("NT AUTHORITY\\",   StringComparison.OrdinalIgnoreCase) ||
        identity.StartsWith("BUILTIN\\",        StringComparison.OrdinalIgnoreCase) ||
        identity.Equals("Everyone",             StringComparison.OrdinalIgnoreCase) ||
        identity.Contains("TrustedInstaller",   StringComparison.OrdinalIgnoreCase);

    private static bool IsAdGroupFormat(string identity)
    {
        if (!identity.Contains('\\')) return false;
        var domain = identity.Split('\\', 2)[0];
        return !domain.Equals("BUILTIN",      StringComparison.OrdinalIgnoreCase) &&
               !domain.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) &&
               !domain.Equals(".",            StringComparison.OrdinalIgnoreCase);
    }

    private bool IsProtectedGroup(string identity) =>
        _securityConfig.ProtectedGroups.Any(pg =>
            pg.Equals(identity, StringComparison.OrdinalIgnoreCase));

    private static string FormatComment(string? comment) =>
        comment is not null ? $" | Комментарий: {comment}" : string.Empty;

    private static AclOperationResult Ok(string requestId) => new()
        { Success = true,  RequestId = requestId, ExecutedAt = DateTimeOffset.UtcNow };

    private static AclOperationResult Failed(string requestId, string reason) => new()
        { Success = false, RequestId = requestId, ErrorMessage = reason, ExecutedAt = DateTimeOffset.UtcNow };
}
