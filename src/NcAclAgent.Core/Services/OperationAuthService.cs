using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

/// <summary>
/// Авторизация операций с группами.
///
/// Правило 1 — NcAdminGroups:
///   Если initiator входит в любую из NcAdminGroups → разрешаем всё.
///   Проверяется через заголовок X-Nc-User-Groups который NC плагин передаёт
///   с каждым запросом (агент доверяет плагину после mTLS).
///
/// Правило 2 — AdManagerDelegation (только для операций с членами группы):
///   Если включено → строим цепочку руководителей targetUser до MaxDepth.
///   Если initiator есть в цепочке → разрешаем.
///   Иначе → 403.
/// </summary>
public class OperationAuthService : IOperationAuthService
{
    private readonly NcAdminGroupsConfig    _adminGroups;
    private readonly AdManagerDelegation    _delegation;
    private readonly IAdUserService         _userService;
    private readonly IEventLogWriter        _eventLog;
    private readonly ILogger<OperationAuthService> _logger;

    public OperationAuthService(
        IOptions<AgentConfiguration>    config,
        IAdUserService                  userService,
        IEventLogWriter                 eventLog,
        ILogger<OperationAuthService>   logger)
    {
        _adminGroups = config.Value.NcAdminGroups;
        _delegation  = config.Value.AdManagerDelegation;
        _userService = userService;
        _eventLog    = eventLog;
        _logger      = logger;
    }

    public AuthorizationResult AuthorizeGroupMemberOperation(
        string initiatorSam,
        string targetUserSam,
        string requestId,
        IReadOnlyList<string> initiatorGroups)
    {
        // ── Правило 1: NC Admin группы ────────────────────────────────
        if (IsNcAdmin(initiatorGroups))
        {
            _eventLog.WriteInformation(EventIds.ManagerCheckPassed,
                $"[{requestId}] Разрешено по NcAdminGroups | Initiator: {initiatorSam}");
            return new AuthorizationResult { Allowed = true, Via = "AdminGroup" };
        }

        // ── Правило 2: Manager delegation ────────────────────────────
        if (!_delegation.Enabled)
        {
            _eventLog.WriteWarning(EventIds.ManagerCheckFailed,
                $"[{requestId}] Отказано: не Admin и AdManagerDelegation выключен | " +
                $"Initiator: {initiatorSam} | Target: {targetUserSam}");
            return new AuthorizationResult
            {
                Allowed = false,
                Reason  = "Недостаточно прав. Обратитесь к администратору."
            };
        }

        // Строим цепочку руководителей targetUser
        ManagerChain chain;
        try
        {
            chain = _userService.GetManagerChain(new GetManagerChainRequest
            {
                RequestId = requestId,
                UserSam   = targetUserSam,
                MaxDepth  = _delegation.MaxDepth
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{RequestId}] Ошибка построения цепочки для {Target}",
                requestId, targetUserSam);
            return new AuthorizationResult
            {
                Allowed = false,
                Reason  = "Не удалось проверить цепочку руководителей"
            };
        }

        // Проверяем есть ли initiator в цепочке
        var inChain = chain.Chain.Any(m =>
            m.SamAccountName.Equals(initiatorSam, StringComparison.OrdinalIgnoreCase));

        if (inChain)
        {
            _eventLog.WriteInformation(EventIds.ManagerCheckPassed,
                $"[{requestId}] Разрешено по ManagerChain | " +
                $"Initiator: {initiatorSam} | Target: {targetUserSam} | " +
                $"Цепочка: [{string.Join(" → ", chain.Chain.Select(u => u.SamAccountName))}]");

            return new AuthorizationResult
            {
                Allowed = true,
                Via     = "ManagerChain"
            };
        }

        _eventLog.WriteWarning(EventIds.ManagerCheckFailed,
            $"[{requestId}] Отказано: {initiatorSam} не является руководителем {targetUserSam} | " +
            $"Цепочка: [{string.Join(" → ", chain.Chain.Select(u => u.SamAccountName))}]");

        return new AuthorizationResult
        {
            Allowed = false,
            Reason  = $"Вы не являетесь руководителем пользователя {targetUserSam} " +
                      $"(проверено до {_delegation.MaxDepth} уровней)"
        };
    }

    public AuthorizationResult AuthorizeFolderGroupOperation(
        string initiatorSam,
        string requestId,
        IReadOnlyList<string> initiatorGroups)
    {
        // Создание/удаление групп папки — только NcAdminGroups, делегирование не применяется
        if (IsNcAdmin(initiatorGroups))
        {
            _eventLog.WriteInformation(EventIds.ManagerCheckPassed,
                $"[{requestId}] FolderGroup операция разрешена по NcAdminGroups | " +
                $"Initiator: {initiatorSam}");
            return new AuthorizationResult { Allowed = true, Via = "AdminGroup" };
        }

        _eventLog.WriteWarning(EventIds.ManagerCheckFailed,
            $"[{requestId}] FolderGroup операция отклонена: {initiatorSam} не в NcAdminGroups");

        return new AuthorizationResult
        {
            Allowed = false,
            Reason  = "Создание и удаление групп доступно только администраторам"
        };
    }

    // ── Приватные методы ──────────────────────────────────────────────

    /// <summary>
    /// Проверяет входит ли хотя бы одна из групп инициатора в NcAdminGroups.
    /// Сравнение без учёта регистра.
    /// </summary>
    private bool IsNcAdmin(IReadOnlyList<string> initiatorGroups) =>
        initiatorGroups.Any(g =>
            _adminGroups.Groups.Any(ag =>
                ag.Equals(g, StringComparison.OrdinalIgnoreCase)));
}
