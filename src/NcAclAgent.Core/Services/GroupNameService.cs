using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

/// <summary>
/// Вычисляет sAMAccountName и DN OU для групп папок.
///
/// Правила именования:
///   Формат:  {Prefix}_{PathPart}_{Suffix}
///   Пример:  NCFS_BUH_Reports_2026_Q1_RW
///
///   Если PathPart не вмещается — обрезаем середину и добавляем 4-символьный хэш:
///   NCFS_BUH_Rep_a3f7_RW
///
///   Максимум sAMAccountName в AD: 64 символа (без $)
/// </summary>
public class GroupNameService : IGroupNameService
{
    private readonly AdGroupManagementConfig _config;

    // AD sAMAccountName ограничен 64 символами
    private const int MaxSamLength = 64;

    private static readonly Dictionary<GroupSuffix, string> SuffixStrings = new()
    {
        [GroupSuffix.RO] = "RO",
        [GroupSuffix.RX] = "RX",
        [GroupSuffix.RW] = "RW",
    };

    public GroupNameService(IOptions<AgentConfiguration> config)
    {
        _config = config.Value.AdGroupManagement;
    }

    public GroupNameResult ComputeGroupName(string folderPath, GroupSuffix suffix)
    {
        var mapping = FindShareMapping(folderPath)
            ?? throw new InvalidOperationException($"Нет маппинга шары для пути: {folderPath}");

        var suffixStr = SuffixStrings[suffix];
        var prefix    = _config.GroupPrefix;

        // Вычисляем relative path — часть пути после шары
        // \\FILESERVER1\ShareA\BUH\Reports\2026\Q1 → BUH\Reports\2026\Q1
        var sharePath    = mapping.Share.TrimEnd('\\');
        var relativePath = folderPath.Substring(sharePath.Length).TrimStart('\\', '/');

        // Заменяем разделители и спецсимволы на _
        var pathPart = SanitizePathPart(relativePath);

        // Полное имя без обрезки: NCFS_BUH_Reports_2026_Q1_RW
        var fullName = $"{prefix}_{pathPart}_{suffixStr}";

        if (fullName.Length <= MaxSamLength)
        {
            return new GroupNameResult
            {
                SamAccountName = fullName,
                Suffix         = suffix,
                WasTruncated   = false
            };
        }

        // Нужна обрезка — вычисляем хэш от полного пути (4 символа)
        var hash = ComputePathHash(folderPath);

        // Доступно для PathPart: MaxSamLength - prefix_ - _hash_ - _suffix
        // Например: 64 - 5(NCFS_) - 5(_a3f7_) - 3(RW) = 51 символ
        var overhead      = prefix.Length + 1 + 1 + hash.Length + 1 + suffixStr.Length;
        var availableLen  = MaxSamLength - overhead;

        if (availableLen < 8)
            throw new InvalidOperationException(
                $"Prefix '{prefix}' слишком длинный, не хватает места для имени группы");

        // Обрезаем середину pathPart
        var truncated = TruncateMiddle(pathPart, availableLen);
        var samName   = $"{prefix}_{truncated}_{hash}_{suffixStr}";

        return new GroupNameResult
        {
            SamAccountName = samName,
            Suffix         = suffix,
            WasTruncated   = true,
            Hash           = hash
        };
    }

    public string ComputeOuDn(string folderPath)
    {
        var mapping = FindShareMapping(folderPath)
            ?? throw new InvalidOperationException($"Нет маппинга шары для пути: {folderPath}");

        var sharePath    = mapping.Share.TrimEnd('\\');
        var relativePath = folderPath.Substring(sharePath.Length).TrimStart('\\', '/');

        if (string.IsNullOrEmpty(relativePath))
            return mapping.OU;

        // Строим OU цепочку — каждый сегмент пути становится OU
        // \\FS\ShareA\BUH\Reports\2026\Q1
        //   →  OU=Q1,OU=2026,OU=Reports,OU=BUH,<RootOU>
        //
        // Имя OU = накопленный путь от корня шары:
        //   BUH              → OU=BUH
        //   BUH\Reports      → OU=BUH_Reports
        //   BUH\Reports\2026 → OU=BUH_Reports_2026
        // Это позволяет видеть полный контекст прямо в имени OU

        var segments  = relativePath.Split(new[] { '\\', '/' },
            StringSplitOptions.RemoveEmptyEntries);

        var ouParts = new List<string>();
        var accumulated = "";

        foreach (var segment in segments)
        {
            accumulated = string.IsNullOrEmpty(accumulated)
                ? SanitizePathPart(segment)
                : $"{accumulated}_{SanitizePathPart(segment)}";

            ouParts.Add($"OU={EscapeDnComponent(accumulated)}");
        }

        // В AD DN порядок — от дочернего к родительскому
        ouParts.Reverse();

        return string.Join(",", ouParts) + "," + mapping.OU;
    }

    public ShareOuMapping? FindShareMapping(string folderPath)
    {
        // Ищем наиболее специфичный маппинг (самый длинный совпадающий Share)
        return _config.RootOUs
            .Where(m => folderPath.StartsWith(
                m.Share.TrimEnd('\\'),
                StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(m => m.Share.Length)
            .FirstOrDefault();
    }

    // ── Приватные методы ──────────────────────────────────────────────

    /// <summary>
    /// Заменяет все символы кроме букв, цифр и _ на _
    /// </summary>
    private static string SanitizePathPart(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input)
        {
            sb.Append(char.IsLetterOrDigit(ch) ? ch : '_');
        }

        // Убираем двойные подчёркивания
        var result = sb.ToString();
        while (result.Contains("__"))
            result = result.Replace("__", "_");

        return result.Trim('_');
    }

    /// <summary>
    /// Обрезает середину строки, оставляя начало и конец.
    /// "BUH_Reports_2026_Q1_January_Week1" → "BUH_Rep...ek1" (условно)
    /// </summary>
    private static string TruncateMiddle(string input, int maxLength)
    {
        if (input.Length <= maxLength) return input;

        // Оставляем 60% начала и 40% конца
        var startLen = (int)(maxLength * 0.6);
        var endLen   = maxLength - startLen;

        var start = input[..startLen].TrimEnd('_');
        var end   = input[^endLen..].TrimStart('_');

        return $"{start}_{end}";
    }

    /// <summary>
    /// 4 символа верхнего регистра — первые 2 байта SHA256 от полного пути
    /// </summary>
    private static string ComputePathHash(string folderPath)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(folderPath.ToUpperInvariant()));
        return Convert.ToHexString(bytes)[..4].ToUpperInvariant();
    }

    /// <summary>
    /// Экранирует специальные символы в DN компоненте (RFC 4514)
    /// </summary>
    private static string EscapeDnComponent(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace(",",  "\\,")
            .Replace("+",  "\\+")
            .Replace("\"", "\\\"")
            .Replace("<",  "\\<")
            .Replace(">",  "\\>")
            .Replace(";",  "\\;")
            .Replace("#",  "\\#")
            .Replace("=",  "\\=");
    }
}
