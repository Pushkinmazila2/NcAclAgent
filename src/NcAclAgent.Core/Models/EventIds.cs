namespace NcAclAgent.Core.Models;

/// <summary>
/// 1xxx — успешные операции
/// 2xxx — нарушения безопасности (SIEM алерт)
/// 3xxx — ошибки операций
/// 4xxx — self-test и startup
/// 5xxx — AD группы
/// 6xxx — AD пользователи / manager chain
/// </summary>
public static class EventIds
{
    // ── Успешные операции ────────────────────────────────────────────
    public const int AgentStarted  = 1000;
    public const int AgentStopped  = 1001;
    public const int AclRead       = 1010;
    public const int AclSet        = 1011;
    public const int AclRemoved    = 1012;

    // ── Безопасность — SIEM АЛЕРТ ───────────────────────────────────
    public const int AuthTokenInvalid           = 2000;
    public const int AuthCertInvalid            = 2001;
    public const int AuthCertExpired            = 2002;
    public const int AuthCertEkuInvalid         = 2003;
    public const int PathTraversalAttempt       = 2010;
    public const int PathNotAllowed             = 2011;
    public const int RateLimitExceeded          = 2020;
    public const int IpBlocked                  = 2021;
    public const int LocalIdentityAttempt       = 2030;
    public const int ProtectedGroupAttempt      = 2031;
    public const int ForbiddenPermissionAttempt = 2032;
    public const int UnauthorizedGroupOuAttempt = 2033; // группа вне разрешённых OU

    // ── Ошибки операций ACL ──────────────────────────────────────────
    public const int AclReadError    = 3000;
    public const int AclSetError     = 3001;
    public const int PathNotFound    = 3002;
    public const int AdGroupNotFound = 3003;
    public const int AdLookupError   = 3004;
    public const int ConfigError     = 3010;

    // ── Self-test / startup ──────────────────────────────────────────
    public const int SelfTestPassed = 4000;
    public const int SelfTestFailed = 4001;
    public const int SelfTestCheck  = 4002;

    // ── AD группы (создание / удаление / состав) ─────────────────────
    public const int GroupSetCreated       = 5000; // комплект RO+RX+RW создан
    public const int GroupCreated          = 5001; // одна группа создана
    public const int GroupDeleted          = 5002;
    public const int GroupSetDeleted       = 5003;
    public const int GroupOuCreated        = 5004; // промежуточная OU создана
    public const int GroupMemberAdded      = 5010;
    public const int GroupMemberRemoved    = 5011;
    public const int GroupRead             = 5020;
    public const int GroupCreateError      = 5030;
    public const int GroupDeleteError      = 5031;
    public const int GroupMemberAddError   = 5032;
    public const int GroupMemberRemoveError = 5033;
    public const int GroupOuCreateError    = 5034;
    public const int GroupNameCollision    = 5040; // коллизия имени → добавлен хэш

    // ── AD пользователи / manager chain ──────────────────────────────
    public const int UserSearched          = 6000;
    public const int ManagerChainResolved  = 6001;
    public const int ManagerCheckPassed    = 6010;
    public const int ManagerCheckFailed    = 6011; // не руководитель → 403
    public const int ManagerChainError     = 6020;
    public const int UserNotFound          = 6021;
}
