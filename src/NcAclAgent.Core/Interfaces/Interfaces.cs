using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Interfaces;

public interface IAclService
{
    GetAclResponse     GetAcl    (GetAclRequest    request);
    AclOperationResult SetAcl    (SetAclRequest    request);
    AclOperationResult RemoveAcl (RemoveAclRequest request);
}

public interface IAdGroupService
{
    FolderGroupSet             GetFolderGroups  (string folderPath, string requestId);
    CreateFolderGroupsResult   CreateFolderGroups(CreateFolderGroupsRequest request);
    DeleteFolderGroupsResult   DeleteFolderGroups(DeleteFolderGroupsRequest request);
    GetGroupMembersResponse    GetGroupMembers  (GetGroupMembersRequest  request);
    GroupMemberOperationResult AddGroupMember   (AddGroupMemberRequest   request);
    GroupMemberOperationResult RemoveGroupMember(RemoveGroupMemberRequest request);
}

public interface IAdUserService
{
    SearchUsersResponse SearchUsers     (SearchUsersRequest    request);
    AdUser?             GetUser         (string samAccountName);
    ManagerChain        GetManagerChain (GetManagerChainRequest request);
}

public interface IOperationAuthService
{
    /// <summary>
    /// Проверяет право управлять членством targetUser в группе.
    /// initiatorGroups — список AD групп инициатора (из заголовка X-Nc-User-Groups).
    /// </summary>
    AuthorizationResult AuthorizeGroupMemberOperation(
        string                initiatorSam,
        string                targetUserSam,
        string                requestId,
        IReadOnlyList<string> initiatorGroups);

    /// <summary>
    /// Проверяет право создавать/удалять группы папки.
    /// Только NcAdminGroups — делегирование не применяется.
    /// </summary>
    AuthorizationResult AuthorizeFolderGroupOperation(
        string                initiatorSam,
        string                requestId,
        IReadOnlyList<string> initiatorGroups);
}

public record AuthorizationResult
{
    public required bool    Allowed { get; init; }
    public          string? Reason  { get; init; }
    public          string? Via     { get; init; }  // "AdminGroup" | "ManagerChain"
}

public interface IGroupNameService
{
    GroupNameResult  ComputeGroupName (string folderPath, GroupSuffix suffix);
    string           ComputeOuDn      (string folderPath);
    ShareOuMapping?  FindShareMapping (string folderPath);
}

public record GroupNameResult
{
    public required string      SamAccountName { get; init; }
    public required GroupSuffix Suffix         { get; init; }
    public required bool        WasTruncated   { get; init; }
    public          string?     Hash           { get; init; }
}

public interface IPathValidator
{
    PathValidationResult Validate(string path);
}

public record PathValidationResult
{
    public required bool    IsValid         { get; init; }
    public required string  NormalizedPath  { get; init; }
    public          string? ViolationReason { get; init; }
    public          int?    SecurityEventId { get; init; }
}

public interface IAdGroupValidator
{
    AdGroupValidationResult ValidateGroup(string identity);
}

public record AdGroupValidationResult
{
    public required bool    IsValid      { get; init; }
    public          string? ErrorMessage { get; init; }
    public          int?    ErrorEventId { get; init; }
}

public interface IEventLogWriter
{
    void WriteInformation(int eventId, string message);
    void WriteWarning    (int eventId, string message);
    void WriteError      (int eventId, string message);
}

public interface IRateLimiter
{
    RateLimitResult CheckRequest   (string ipAddress);
    void            RecordAclChange(string ipAddress);
    bool            IsBlocked      (string ipAddress);
}

public record RateLimitResult
{
    public required bool    Allowed     { get; init; }
    public          string? BlockReason { get; init; }
}

public interface ISelfTestService
{
    SelfTestResult Run();
}
