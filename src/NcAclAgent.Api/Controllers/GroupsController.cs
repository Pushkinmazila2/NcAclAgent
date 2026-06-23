using Microsoft.AspNetCore.Mvc;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Api.Controllers;

[ApiController]
[Route("api/groups")]
[Produces("application/json")]
public class GroupsController : ControllerBase
{
    private readonly IAdGroupService        _groupService;
    private readonly IOperationAuthService  _authService;
    private readonly IRateLimiter           _rateLimiter;
    private readonly ILogger<GroupsController> _logger;

    public GroupsController(
        IAdGroupService groupService,
        IOperationAuthService authService,
        IRateLimiter rateLimiter,
        ILogger<GroupsController> logger)
    {
        _groupService = groupService;
        _authService  = authService;
        _rateLimiter  = rateLimiter;
        _logger       = logger;
    }

    /// <summary>GET /api/groups?path=\\SERVER\Share\Folder — группы папки</summary>
    [HttpGet]
    public IActionResult GetFolderGroups([FromQuery] string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest(new { error = "Параметр path обязателен" });

        var requestId = GetRequestId();
        try
        {
            var result = _groupService.GetFolderGroups(path, requestId);
            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(403, new { requestId, error = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{Id}] GetFolderGroups: {Path}", requestId, path);
            return StatusCode(500, new { requestId, error = "Внутренняя ошибка" });
        }
    }

    /// <summary>POST /api/groups — создать комплект групп RO/RX/RW для папки</summary>
    [HttpPost]
    public IActionResult CreateFolderGroups([FromBody] CreateFolderGroupsDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var requestId      = GetRequestId();
        var initiator      = GetInitiator();
        var initiatorGroups = GetInitiatorGroups();
        var remoteIp       = GetRemoteIp();

        // Только NcAdminGroups могут создавать группы папок
        var auth = _authService.AuthorizeFolderGroupOperation(initiator, requestId, initiatorGroups);
        if (!auth.Allowed)
            return StatusCode(403, new { requestId, error = auth.Reason });

        var result = _groupService.CreateFolderGroups(new CreateFolderGroupsRequest
        {
            RequestId       = requestId,
            FolderPath      = dto.FolderPath,
            InitiatedByUser = initiator,
            Comment         = dto.Comment,
            Suffixes        = dto.Suffixes ?? [GroupSuffix.RO, GroupSuffix.RX, GroupSuffix.RW]
        });

        if (result.Success) _rateLimiter.RecordAclChange(remoteIp);

        return result.Success
            ? Ok(result)
            : BadRequest(new { requestId, error = result.ErrorMessage });
    }

    /// <summary>DELETE /api/groups?path=\\SERVER\Share\Folder — удалить группы папки</summary>
    [HttpDelete]
    public IActionResult DeleteFolderGroups(
        [FromQuery] string path,
        [FromQuery] string initiatedByUser,
        [FromQuery] string? comment = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest(new { error = "Параметр path обязателен" });

        var requestId       = GetRequestId();
        var initiator       = GetInitiator();
        var initiatorGroups = GetInitiatorGroups();
        var remoteIp        = GetRemoteIp();

        var auth = _authService.AuthorizeFolderGroupOperation(initiator, requestId, initiatorGroups);
        if (!auth.Allowed)
            return StatusCode(403, new { requestId, error = auth.Reason });

        var result = _groupService.DeleteFolderGroups(new DeleteFolderGroupsRequest
        {
            RequestId       = requestId,
            FolderPath      = path,
            InitiatedByUser = initiator,
            Comment         = comment
        });

        if (result.Success) _rateLimiter.RecordAclChange(remoteIp);

        return result.Success
            ? Ok(result)
            : BadRequest(new { requestId, error = result.ErrorMessage });
    }

    /// <summary>GET /api/groups/{groupName}/members — состав группы</summary>
    [HttpGet("{groupName}/members")]
    public IActionResult GetMembers(string groupName)
    {
        var requestId = GetRequestId();
        try
        {
            var result = _groupService.GetGroupMembers(new GetGroupMembersRequest
            {
                RequestId       = requestId,
                GroupSamName    = groupName,
                RequestedByUser = GetInitiator()
            });
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{Id}] GetMembers: {Group}", requestId, groupName);
            return StatusCode(500, new { requestId, error = "Внутренняя ошибка" });
        }
    }

    /// <summary>POST /api/groups/{groupName}/members — добавить пользователя</summary>
    [HttpPost("{groupName}/members")]
    public IActionResult AddMember(string groupName, [FromBody] GroupMemberDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var requestId       = GetRequestId();
        var initiator       = GetInitiator();
        var initiatorGroups = GetInitiatorGroups();
        var remoteIp        = GetRemoteIp();

        // Проверяем право добавлять targetUser (admin или руководитель)
        var auth = _authService.AuthorizeGroupMemberOperation(
            initiator, dto.UserSamName, requestId, initiatorGroups);
        if (!auth.Allowed)
            return StatusCode(403, new { requestId, error = auth.Reason });

        var result = _groupService.AddGroupMember(new AddGroupMemberRequest
        {
            RequestId       = requestId,
            GroupSamName    = groupName,
            UserSamName     = dto.UserSamName,
            InitiatedByUser = initiator,
            Comment         = dto.Comment
        });

        if (result.Success) _rateLimiter.RecordAclChange(remoteIp);

        return result.Success
            ? Ok(result)
            : BadRequest(new { requestId, error = result.ErrorMessage });
    }

    /// <summary>DELETE /api/groups/{groupName}/members/{userSam} — удалить пользователя</summary>
    [HttpDelete("{groupName}/members/{userSam}")]
    public IActionResult RemoveMember(
        string groupName, string userSam, [FromQuery] string? comment = null)
    {
        var requestId       = GetRequestId();
        var initiator       = GetInitiator();
        var initiatorGroups = GetInitiatorGroups();
        var remoteIp        = GetRemoteIp();

        var auth = _authService.AuthorizeGroupMemberOperation(
            initiator, userSam, requestId, initiatorGroups);
        if (!auth.Allowed)
            return StatusCode(403, new { requestId, error = auth.Reason });

        var result = _groupService.RemoveGroupMember(new RemoveGroupMemberRequest
        {
            RequestId       = requestId,
            GroupSamName    = groupName,
            UserSamName     = userSam,
            InitiatedByUser = initiator,
            Comment         = comment
        });

        if (result.Success) _rateLimiter.RecordAclChange(remoteIp);

        return result.Success
            ? Ok(result)
            : BadRequest(new { requestId, error = result.ErrorMessage });
    }

    // ── Хелперы ───────────────────────────────────────────────────────

    private string GetRequestId() =>
        HttpContext.Items["RequestId"]?.ToString() ?? "unknown";

    private string GetRemoteIp() =>
        HttpContext.Items["RemoteIp"]?.ToString() ?? "unknown";

    /// <summary>
    /// NC плагин передаёт SAM логин текущего пользователя в заголовке.
    /// Агент доверяет этому значению после mTLS проверки.
    /// </summary>
    private string GetInitiator() =>
        HttpContext.Request.Headers["X-Nc-User"].FirstOrDefault() ?? "unknown";

    /// <summary>
    /// NC плагин передаёт список AD групп пользователя (comma-separated).
    /// Используется для проверки NcAdminGroups.
    /// </summary>
    private IReadOnlyList<string> GetInitiatorGroups() =>
        HttpContext.Request.Headers["X-Nc-User-Groups"]
            .FirstOrDefault()
            ?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        ?? [];
}

// ── DTO ───────────────────────────────────────────────────────────────

public record CreateFolderGroupsDto
{
    [System.ComponentModel.DataAnnotations.Required]
    public required string FolderPath { get; init; }

    [System.ComponentModel.DataAnnotations.MaxLength(256)]
    public string? Comment { get; init; }

    /// <summary>null = создать все три (RO+RX+RW)</summary>
    public IReadOnlyList<GroupSuffix>? Suffixes { get; init; }
}

public record GroupMemberDto
{
    [System.ComponentModel.DataAnnotations.Required]
    public required string UserSamName { get; init; }

    [System.ComponentModel.DataAnnotations.MaxLength(256)]
    public string? Comment { get; init; }
}
