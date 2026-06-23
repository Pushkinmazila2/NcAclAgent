using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

public class PathValidator : IPathValidator
{
    private readonly AllowedPathsConfig    _config;
    private readonly ILogger<PathValidator> _logger;

    private static readonly string[] TraversalPatterns =
    [
        "..", "//", "%2e%2e", "%252e", "\0",
        // UNC traversal специфика
        "\\..\\", "/../"
    ];

    public PathValidator(IOptions<AgentConfiguration> config, ILogger<PathValidator> logger)
    {
        _config = config.Value.Paths;
        _logger = logger;
    }

    public PathValidationResult Validate(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return Invalid("Пустой путь", EventIds.PathNotAllowed);

        // 1. Traversal до нормализации
        foreach (var pattern in TraversalPatterns)
        {
            if (path.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Path traversal attempt: {Path}", path);
                return Invalid($"Path traversal: {pattern}", EventIds.PathTraversalAttempt);
            }
        }

        // 2. Нормализация
        string normalized;
        try
        {
            normalized = Path.GetFullPath(path).TrimEnd('\\', '/');
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Path normalization failed: {Path} | {Error}", path, ex.Message);
            return Invalid("Некорректный путь", EventIds.PathNotAllowed);
        }

        // 3. Traversal после нормализации
        foreach (var pattern in TraversalPatterns)
        {
            if (normalized.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return Invalid("Path traversal после нормализации", EventIds.PathTraversalAttempt);
        }

        // 4. Сначала Denied — работает по префиксу, блокирует всё дерево
        foreach (var denied in _config.Denied)
        {
            string normalizedDenied;
            try { normalizedDenied = Path.GetFullPath(denied).TrimEnd('\\', '/'); }
            catch { continue; }

            if (normalized.StartsWith(normalizedDenied, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Access to denied subtree: {Path}", normalized);
                return Invalid("Путь явно запрещён конфигурацией", EventIds.PathNotAllowed);
            }
        }

        // 5. Затем Allowed — тоже по префиксу
        foreach (var allowed in _config.Allowed)
        {
            string normalizedAllowed;
            try { normalizedAllowed = Path.GetFullPath(allowed).TrimEnd('\\', '/'); }
            catch { continue; }

            if (normalized.StartsWith(normalizedAllowed, StringComparison.OrdinalIgnoreCase))
                return new PathValidationResult { IsValid = true, NormalizedPath = normalized };
        }

        _logger.LogWarning("Path not in whitelist: {Path}", normalized);
        return Invalid("Путь не входит в список разрешённых", EventIds.PathNotAllowed);
    }

    private static PathValidationResult Invalid(string reason, int eventId) => new()
    {
        IsValid         = false,
        NormalizedPath  = string.Empty,
        ViolationReason = reason,
        SecurityEventId = eventId
    };
}
