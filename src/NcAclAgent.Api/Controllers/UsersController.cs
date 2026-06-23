using Microsoft.AspNetCore.Mvc;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Api.Controllers;

[ApiController]
[Route("api/users")]
[Produces("application/json")]
public class UsersController : ControllerBase
{
    private readonly IAdUserService          _userService;
    private readonly ILogger<UsersController> _logger;

    public UsersController(IAdUserService userService, ILogger<UsersController> logger)
    {
        _userService = userService;
        _logger      = logger;
    }

    /// <summary>GET /api/users/search?q=ivan&max=20 — поиск пользователей в AD</summary>
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string q, [FromQuery] int max = 20)
    {
        if (string.IsNullOrWhiteSpace(q) || q.Length < 3)
            return BadRequest(new { error = "Минимум 3 символа для поиска" });

        var requestId = GetRequestId();
        try
        {
            var result = _userService.SearchUsers(new SearchUsersRequest
            {
                RequestId  = requestId,
                Query      = q,
                MaxResults = Math.Clamp(max, 1, 100)
            });
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{Id}] Search users: {Q}", requestId, q);
            return StatusCode(500, new { requestId, error = "Внутренняя ошибка" });
        }
    }

    /// <summary>GET /api/users/{sam}/manager-chain — цепочка руководителей</summary>
    [HttpGet("{sam}/manager-chain")]
    public IActionResult GetManagerChain(string sam, [FromQuery] int? depth = null)
    {
        var requestId = GetRequestId();
        try
        {
            var result = _userService.GetManagerChain(new GetManagerChainRequest
            {
                RequestId = requestId,
                UserSam   = sam,
                MaxDepth  = depth
            });
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{Id}] GetManagerChain: {Sam}", requestId, sam);
            return StatusCode(500, new { requestId, error = "Внутренняя ошибка" });
        }
    }

    private string GetRequestId() =>
        HttpContext.Items["RequestId"]?.ToString() ?? "unknown";
}
