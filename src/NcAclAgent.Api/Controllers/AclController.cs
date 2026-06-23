using Microsoft.AspNetCore.Mvc;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Api.Controllers;

[ApiController]
[Route("api/acl")]
[Produces("application/json")]
public class AclController : ControllerBase
{
    private readonly IAclService             _aclService;
    private readonly IRateLimiter            _rateLimiter;
    private readonly ILogger<AclController>  _logger;

    public AclController(IAclService aclService, IRateLimiter rateLimiter, ILogger<AclController> logger)
    {
        _aclService  = aclService;
        _rateLimiter = rateLimiter;
        _logger      = logger;
    }

    /// <summary>GET /api/acl?path=\\SERVER\Share\Folder</summary>
    [HttpGet]
    public IActionResult GetAcl([FromQuery] string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest(new { error = "Параметр path обязателен" });

        var requestId = GetRequestId();

        try
        {
            var result = _aclService.GetAcl(new GetAclRequest { Path = path, RequestId = requestId });
            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { requestId, error = ex.Message });
        }
        catch (DirectoryNotFoundException ex)
        {
            return NotFound(new { requestId, error = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{RequestId}] Ошибка GetAcl для: {Path}", requestId, path);
            return StatusCode(500, new { requestId, error = "Внутренняя ошибка агента" });
        }
    }

    /// <summary>POST /api/acl — установить / обновить права группы</summary>
    [HttpPost]
    public IActionResult SetAcl([FromBody] SetAclRequestDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var requestId = GetRequestId();
        var remoteIp  = HttpContext.Items["RemoteIp"]?.ToString() ?? "unknown";

        var request = new SetAclRequest
        {
            RequestId       = requestId,
            Path            = dto.Path,
            GroupIdentity   = dto.GroupIdentity,
            Permission      = dto.Permission,
            Action          = dto.Action,
            InitiatedByUser = dto.InitiatedByUser,
            Comment         = dto.Comment
        };

        var result = _aclService.SetAcl(request);

        if (result.Success)
            _rateLimiter.RecordAclChange(remoteIp);

        return result.Success
            ? Ok(result)
            : BadRequest(new { requestId, error = result.ErrorMessage });
    }

    /// <summary>DELETE /api/acl — удалить группу из ACL</summary>
    [HttpDelete]
    public IActionResult RemoveAcl([FromBody] RemoveAclRequestDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var requestId = GetRequestId();
        var remoteIp  = HttpContext.Items["RemoteIp"]?.ToString() ?? "unknown";

        var request = new RemoveAclRequest
        {
            RequestId       = requestId,
            Path            = dto.Path,
            GroupIdentity   = dto.GroupIdentity,
            InitiatedByUser = dto.InitiatedByUser,
            Comment         = dto.Comment
        };

        var result = _aclService.RemoveAcl(request);

        if (result.Success)
            _rateLimiter.RecordAclChange(remoteIp);

        return result.Success
            ? Ok(result)
            : BadRequest(new { requestId, error = result.ErrorMessage });
    }

    /// <summary>GET /api/acl/health</summary>
    [HttpGet("health")]
    public IActionResult Health() => Ok(new
    {
        status    = "ok",
        timestamp = DateTimeOffset.UtcNow,
        version   = "1.0.0"
    });

    private string GetRequestId() =>
        HttpContext.Items["RequestId"]?.ToString()
        ?? HttpContext.Response.Headers["X-Request-Id"].FirstOrDefault()
        ?? "unknown";
}

// ── DTO для входящих запросов (валидация аннотациями) ─────────────────

public record SetAclRequestDto
{
    [System.ComponentModel.DataAnnotations.Required]
    public required string Path            { get; init; }

    [System.ComponentModel.DataAnnotations.Required]
    public required string GroupIdentity   { get; init; }

    public required AclPermission Permission { get; init; }
    public required AclAction     Action     { get; init; }

    [System.ComponentModel.DataAnnotations.Required]
    public required string InitiatedByUser { get; init; }

    [System.ComponentModel.DataAnnotations.MaxLength(256)]
    public string? Comment { get; init; }
}

public record RemoveAclRequestDto
{
    [System.ComponentModel.DataAnnotations.Required]
    public required string Path            { get; init; }

    [System.ComponentModel.DataAnnotations.Required]
    public required string GroupIdentity   { get; init; }

    [System.ComponentModel.DataAnnotations.Required]
    public required string InitiatedByUser { get; init; }

    [System.ComponentModel.DataAnnotations.MaxLength(256)]
    public string? Comment { get; init; }
}
