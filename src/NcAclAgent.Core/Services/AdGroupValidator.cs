using Microsoft.Extensions.Logging;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

public class AdGroupValidator : IAdGroupValidator
{
    private readonly ILogger<AdGroupValidator> _logger;

    public AdGroupValidator(ILogger<AdGroupValidator> logger) => _logger = logger;

    public AdGroupValidationResult ValidateGroup(string identity)
    {
        if (!identity.Contains('\\'))
            return Fail("Ожидается формат DOMAIN\\GroupName", EventIds.LocalIdentityAttempt);

        var parts  = identity.Split('\\', 2);
        var domain = parts[0];
        var name   = parts[1];

        if (IsBuiltinDomain(domain))
            return Fail("Встроенные домены не разрешены", EventIds.LocalIdentityAttempt);

#if WINDOWS
        try
        {
            using var context = new System.DirectoryServices.AccountManagement.PrincipalContext(
                System.DirectoryServices.AccountManagement.ContextType.Domain, domain);
            using var group = System.DirectoryServices.AccountManagement.GroupPrincipal
                .FindByIdentity(context,
                    System.DirectoryServices.AccountManagement.IdentityType.Name, name);

            if (group is null)
            {
                _logger.LogWarning("AD group not found: {Identity}", identity);
                return Fail($"Группа не найдена в AD: {identity}", EventIds.AdGroupNotFound);
            }
            if (group.IsSecurityGroup != true)
                return Fail($"Объект {identity} не является группой безопасности", EventIds.AdGroupNotFound);

            return new AdGroupValidationResult { IsValid = true };
        }
        catch (System.DirectoryServices.AccountManagement.PrincipalServerDownException ex)
        {
            _logger.LogError(ex, "AD server unavailable: {Domain}", domain);
            return Fail($"Сервер AD недоступен: {domain}", EventIds.AdLookupError);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AD lookup error: {Identity}", identity);
            return Fail($"Ошибка запроса к AD: {ex.Message}", EventIds.AdLookupError);
        }
#else
        // На Linux (CI) — пропускаем проверку AD
        _logger.LogWarning("AD validation skipped (non-Windows): {Identity}", identity);
        return new AdGroupValidationResult { IsValid = true };
#endif
    }

    private static bool IsBuiltinDomain(string domain) =>
        domain.Equals("BUILTIN",      StringComparison.OrdinalIgnoreCase) ||
        domain.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
        domain.Equals(".",            StringComparison.OrdinalIgnoreCase);

    private static AdGroupValidationResult Fail(string msg, int eventId) =>
        new() { IsValid = false, ErrorMessage = msg, ErrorEventId = eventId };
}
