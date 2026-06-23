namespace NcAclAgent.Core.Models;

// ── Режим агента ──────────────────────────────────────────────────────

public enum AgentMode { Test, Prod }

// ── ACL ───────────────────────────────────────────────────────────────

public enum AclPermission
{
    Read        = 1,   // RO
    ReadExecute = 2,   // RX
    Modify      = 3,   // RW
}

/// <summary>Суффикс группы — RO / RX / RW</summary>
public enum GroupSuffix
{
    RO,   // Read Only       → AclPermission.Read
    RX,   // Read Execute    → AclPermission.ReadExecute
    RW,   // Read Write      → AclPermission.Modify
}

public enum AclAction { Allow, Deny }

public record AclEntry
{
    public required string        IdentityReference { get; init; }
    public required AclPermission Permission        { get; init; }
    public required AclAction     Action            { get; init; }
    public          bool          IsInherited       { get; init; }
}

// ── AD Группа папки ───────────────────────────────────────────────────

/// <summary>
/// Группа привязанная к папке через extensionAttribute2
/// </summary>
public record FolderGroup
{
    /// <summary>sAMAccountName — NCFS_BUH_Reports_2026_Q1_a3f7_RW</summary>
    public required string      SamAccountName  { get; init; }

    /// <summary>Полный DN в AD</summary>
    public required string      DistinguishedName { get; init; }

    /// <summary>UNC путь из extensionAttribute2</summary>
    public required string      FolderPath      { get; init; }

    /// <summary>NTFS File ID из extensionAttribute3</summary>
    public          string?     NtfsFileId      { get; init; }

    public required GroupSuffix Suffix          { get; init; }
    public required string      DisplayName     { get; init; }

    /// <summary>managedBy DN</summary>
    public          string?     ManagedBy       { get; init; }

    public required int         MemberCount     { get; init; }
}

/// <summary>Все группы папки (RO + RX + RW)</summary>
public record FolderGroupSet
{
    public required string       FolderPath { get; init; }
    public          FolderGroup? RO         { get; init; }
    public          FolderGroup? RX         { get; init; }
    public          FolderGroup? RW         { get; init; }

    /// <summary>true если хотя бы одна группа существует</summary>
    public bool HasAny => RO is not null || RX is not null || RW is not null;
}

// ── AD Пользователь ───────────────────────────────────────────────────

public record AdUser
{
    public required string  SamAccountName  { get; init; }
    public required string  DisplayName     { get; init; }
    public required string  DistinguishedName { get; init; }
    public          string? Email           { get; init; }
    public          string? Department      { get; init; }
    public          string? Title           { get; init; }

    /// <summary>DN прямого руководителя</summary>
    public          string? ManagerDn       { get; init; }
}

/// <summary>Цепочка руководителей пользователя</summary>
public record ManagerChain
{
    public required string          SubjectSam  { get; init; }
    public required IReadOnlyList<AdUser> Chain { get; init; }
    public required int             Depth       { get; init; }
}

// ── Запросы / ответы ACL ─────────────────────────────────────────────

public record GetAclRequest
{
    public required string RequestId { get; init; }
    public required string Path      { get; init; }
}

public record GetAclResponse
{
    public required string                  RequestId   { get; init; }
    public required string                  Path        { get; init; }
    public required string                  Owner       { get; init; }
    public required IReadOnlyList<AclEntry> Entries     { get; init; }
    public required DateTimeOffset          RetrievedAt { get; init; }
}

public record SetAclRequest
{
    public required string        RequestId       { get; init; }
    public required string        Path            { get; init; }
    public required string        GroupIdentity   { get; init; }
    public required AclPermission Permission      { get; init; }
    public required AclAction     Action          { get; init; }
    public required string        InitiatedByUser { get; init; }

    /// <summary>Максимум 256 символов</summary>
    public          string?       Comment         { get; init; }
}

public record RemoveAclRequest
{
    public required string  RequestId       { get; init; }
    public required string  Path            { get; init; }
    public required string  GroupIdentity   { get; init; }
    public required string  InitiatedByUser { get; init; }
    public          string? Comment         { get; init; }
}

public record AclOperationResult
{
    public required bool           Success      { get; init; }
    public required string         RequestId    { get; init; }
    public          string?        ErrorMessage { get; init; }
    public required DateTimeOffset ExecutedAt   { get; init; }
}

// ── Запросы / ответы групп ────────────────────────────────────────────

/// <summary>Создать комплект групп (RO+RX+RW) для папки</summary>
public record CreateFolderGroupsRequest
{
    public required string  RequestId       { get; init; }
    public required string  FolderPath      { get; init; }
    public required string  InitiatedByUser { get; init; }
    public          string? Comment         { get; init; }

    /// <summary>
    /// Какие суффиксы создавать. По умолчанию все три.
    /// </summary>
    public IReadOnlyList<GroupSuffix> Suffixes { get; init; } =
        [GroupSuffix.RO, GroupSuffix.RX, GroupSuffix.RW];
}

public record CreateFolderGroupsResult
{
    public required bool             Success      { get; init; }
    public required string           RequestId    { get; init; }
    public          string?          ErrorMessage { get; init; }
    public required FolderGroupSet   Groups       { get; init; }
    public required DateTimeOffset   ExecutedAt   { get; init; }
}

public record DeleteFolderGroupsRequest
{
    public required string  RequestId       { get; init; }
    public required string  FolderPath      { get; init; }
    public required string  InitiatedByUser { get; init; }
    public          string? Comment         { get; init; }
}

public record DeleteFolderGroupsResult
{
    public required bool           Success      { get; init; }
    public required string         RequestId    { get; init; }
    public          string?        ErrorMessage { get; init; }
    public required int            DeletedCount { get; init; }
    public required DateTimeOffset ExecutedAt   { get; init; }
}

// ── Запросы / ответы членов группы ───────────────────────────────────

public record GetGroupMembersRequest
{
    public required string RequestId      { get; init; }
    public required string GroupSamName   { get; init; }
    public required string RequestedByUser { get; init; }
}

public record GetGroupMembersResponse
{
    public required string                RequestId   { get; init; }
    public required string                GroupSamName { get; init; }
    public required IReadOnlyList<AdUser> Members     { get; init; }
    public required DateTimeOffset        RetrievedAt { get; init; }
}

public record AddGroupMemberRequest
{
    public required string  RequestId       { get; init; }
    public required string  GroupSamName    { get; init; }
    public required string  UserSamName     { get; init; }
    public required string  InitiatedByUser { get; init; }
    public          string? Comment         { get; init; }
}

public record RemoveGroupMemberRequest
{
    public required string  RequestId       { get; init; }
    public required string  GroupSamName    { get; init; }
    public required string  UserSamName     { get; init; }
    public required string  InitiatedByUser { get; init; }
    public          string? Comment         { get; init; }
}

public record GroupMemberOperationResult
{
    public required bool           Success      { get; init; }
    public required string         RequestId    { get; init; }
    public          string?        ErrorMessage { get; init; }
    public required DateTimeOffset ExecutedAt   { get; init; }
}

// ── Запросы / ответы пользователей ───────────────────────────────────

public record SearchUsersRequest
{
    public required string RequestId { get; init; }
    public required string Query     { get; init; }   // минимум 3 символа
    public          int    MaxResults { get; init; } = 20;
}

public record SearchUsersResponse
{
    public required string                RequestId { get; init; }
    public required IReadOnlyList<AdUser> Users     { get; init; }
}

public record GetManagerChainRequest
{
    public required string RequestId  { get; init; }
    public required string UserSam    { get; init; }
    public          int?   MaxDepth   { get; init; }   // null = берём из конфига
}

// ── Конфигурация ──────────────────────────────────────────────────────

public record AgentConfiguration
{
    public required ListenConfig          Listen              { get; init; }
    public required SecurityConfig        Security            { get; init; }
    public required AllowedPathsConfig    Paths               { get; init; }
    public required NcAdminGroupsConfig   NcAdminGroups       { get; init; }
    public required AdManagerDelegation   AdManagerDelegation { get; init; }
    public required AdGroupManagementConfig AdGroupManagement { get; init; }
    public required RateLimitConfig       RateLimit           { get; init; }
    public required EventLogConfig        EventLog            { get; init; }
    public          AgentMode             Mode                { get; init; } = AgentMode.Test;
}

public record ListenConfig
{
    public required string IpAddress           { get; init; }
    public required int    Port                { get; init; }
    public required string CertificatePath     { get; init; }
    public required string CertificatePassword { get; init; }
}

public record SecurityConfig
{
    public required string                  BearerToken        { get; init; }
    public required ClientCertificateConfig ClientCertificate  { get; init; }
    public IReadOnlyList<string>            ProtectedGroups    { get; init; } = [];
    public int                              MaxPathDepth        { get; init; } = 5;
}

public record ClientCertificateConfig
{
    public required string  TrustedCaThumbprint    { get; init; }
    public          string? Thumbprint             { get; init; }
    public string           RequiredEku            { get; init; } = "1.3.6.1.5.5.7.3.2";
    public bool             AllowExpiredInTestMode { get; init; } = false;
}

public record AllowedPathsConfig
{
    public required IReadOnlyList<string> Allowed { get; init; }
    public IReadOnlyList<string>          Denied  { get; init; } = [];
}

/// <summary>
/// Группы NC пользователей с полным доступом ко всем операциям агента.
/// Проверяется на стороне NC плагина — агент доверяет заголовку X-Nc-User-Groups.
/// </summary>
public record NcAdminGroupsConfig
{
    public IReadOnlyList<string> Groups { get; init; } = [];
}

/// <summary>
/// Делегирование через цепочку руководителей AD.
/// Если включено — руководитель может управлять группами своих подчинённых.
/// </summary>
public record AdManagerDelegation
{
    public bool Enabled  { get; init; } = false;
    public int  MaxDepth { get; init; } = 3;
}

public record AdGroupManagementConfig
{
    /// <summary>
    /// Маппинг шара → корневая OU.
    /// Путь папки должен начинаться с Share чтобы агент знал в какую OU писать.
    /// </summary>
    public required IReadOnlyList<ShareOuMapping> RootOUs { get; init; }

    /// <summary>Префикс имени группы. Например "NCFS"</summary>
    public string GroupPrefix          { get; init; } = "NCFS";

    /// <summary>extensionAttribute для хранения полного UNC пути</summary>
    public string PathAttribute        { get; init; } = "extensionAttribute2";

    /// <summary>extensionAttribute для хранения NTFS File ID</summary>
    public string NtfsFileIdAttribute  { get; init; } = "extensionAttribute3";
}

public record ShareOuMapping
{
    /// <summary>UNC путь шары: \\\\FILESERVER1\\ShareA</summary>
    public required string Share { get; init; }

    /// <summary>Корневая OU для этой шары: OU=ShareA,OU=NextcloudACL,DC=company,DC=local</summary>
    public required string OU    { get; init; }
}

public record RateLimitConfig
{
    public int RequestsPerSecond    { get; init; } = 10;
    public int AclChangesPerMinute  { get; init; } = 50;
    public int BlockDurationMinutes { get; init; } = 5;
}

public record EventLogConfig
{
    public string Source  { get; init; } = "NextcloudAclAgent";
    public string LogName { get; init; } = "Application";
}

// ── Self-Test ─────────────────────────────────────────────────────────

public record SelfTestResult
{
    public required bool                         Passed { get; init; }
    public required IReadOnlyList<SelfTestCheck> Checks { get; init; }
    public required DateTimeOffset               RanAt  { get; init; }
    public required AgentMode                    Mode   { get; init; }
}

public record SelfTestCheck
{
    public required string  Name   { get; init; }
    public required bool    Passed { get; init; }
    public          string? Detail { get; init; }
}
