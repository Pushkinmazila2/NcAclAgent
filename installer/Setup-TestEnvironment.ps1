#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Подготовка тестового окружения для NcAclAgent.
    Запускать на Windows Server где будет работать агент.

.DESCRIPTION
    Скрипт делает всё необходимое для запуска в Test режиме:
    1. Генерирует самоподписанный CA
    2. Генерирует серверный сертификат агента (подписан CA)
    3. Генерирует клиентский сертификат для NC плагина (подписан CA)
    4. Создаёт папки для конфигов и сертификатов
    5. Генерирует Bearer токен
    6. Заполняет appsettings.Test.json реальными значениями
    7. Создаёт тестовую шару C:\TestShare

.PARAMETER AgentDir
    Папка где лежит NcAclAgent.Api.exe (после распаковки релиза)

.EXAMPLE
    .\Setup-TestEnvironment.ps1 -AgentDir "C:\NcAclAgent"
#>
param(
    [string]$AgentDir       = "C:\ProgramData\NcAclAgent",
    [string]$ConfigDir      = "C:\ProgramData\NcAclAgent",
    [string]$CertDir        = "C:\ProgramData\NcAclAgent\certs",
    [string]$TestSharePath  = "C:\TestShare",
    [string]$CertPassword   = "NcAclTest2025!"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NcAclAgent — Настройка Test режима"   -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Создаём папки ─────────────────────────────────────────────────
Write-Host "[1/7] Создаём директории..." -ForegroundColor Yellow

@($ConfigDir, $CertDir, $TestSharePath, "$TestSharePath\Confidential", "$TestSharePath\Finance") |
    ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Host "      Создана: $_"
        } else {
            Write-Host "      Уже существует: $_"
        }
    }
# Задаем единое время старта для всех сертификатов со сдвигом назад на 1 час
$NotBeforeDate = (Get-Date).AddHours(-12)

Write-Host ""
Write-Host "[2/7] Генерируем самоподписанный CA..." -ForegroundColor Yellow

$caSubject = "CN=NcAclAgent-TestCA, O=NcAclAgent Test, C=RU"

# Удаляем старый CA из хранилищ, чтобы гарантированно перевыпустить его с правильным временем
Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\Root | 
    Where-Object { $_.Subject -eq $caSubject } | 
    Remove-Item -ErrorAction SilentlyContinue

$ca = New-SelfSignedCertificate `
    -Type Custom `
    -KeySpec Signature `
    -Subject $caSubject `
    -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 `
    -KeyLength 4096 `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyUsageProperty Sign `
    -KeyUsage CertSign, CRLSign `
    -NotBefore $NotBeforeDate `
    -NotAfter (Get-Date).AddYears(10)

Write-Host "      CA создан: $($ca.Thumbprint)"

# Помещаем CA в Trusted Root (для проверки цепочки)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $ca.Thumbprint })) {
    $store.Add($ca)
    Write-Host "      CA добавлен in Trusted Root"
}
$store.Close()

# ── 3. Серверный сертификат агента ───────────────────────────────────
Write-Host ""
Write-Host "[3/7] Генерируем серверный сертификат агента..." -ForegroundColor Yellow

# Очищаем старые серверные сертификаты
Get-ChildItem Cert:\LocalMachine\My | 
    Where-Object { $_.Subject -eq "CN=NcAclAgent-Server, O=NcAclAgent Test, C=RU" } | 
    Remove-Item -ErrorAction SilentlyContinue

$serverCert = New-SelfSignedCertificate `
    -Type Custom `
    -KeySpec KeyExchange `
    -Subject "CN=NcAclAgent-Server, O=NcAclAgent Test, C=RU" `
    -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 `
    -KeyLength 2048 `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -Signer $ca `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
    -NotBefore $NotBeforeDate `
    -NotAfter (Get-Date).AddYears(2)

$pwd = ConvertTo-SecureString $CertPassword -AsPlainText -Force
$serverPfxPath = "$CertDir\agent.pfx"
Export-PfxCertificate -Cert $serverCert -FilePath $serverPfxPath -Password $pwd | Out-Null
Write-Host "      Серверный сертификат: $($serverCert.Thumbprint)"
Write-Host "      Сохранён: $serverPfxPath"



# ── 4. Клиентский сертификат для NC плагина ──────────────────────────
Write-Host ""
Write-Host "[4/7] Генерируем клиентский сертификат (для NC плагина)..." -ForegroundColor Yellow

Get-ChildItem Cert:\LocalMachine\My | 
    Where-Object { $_.Subject -eq "CN=NcAclAgent-NextcloudClient, O=NcAclAgent Test, C=RU" } | 
    Remove-Item -ErrorAction SilentlyContinue

$clientCert = New-SelfSignedCertificate `
    -Type Custom `
    -KeySpec KeyExchange `
    -Subject "CN=NcAclAgent-NextcloudClient, O=NcAclAgent Test, C=RU" `
    -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 `
    -KeyLength 2048 `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -Signer $ca `
    -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
    -NotBefore $NotBeforeDate `
    -NotAfter (Get-Date).AddYears(2)

$clientPfxPath = "$CertDir\nextcloud-client.pfx"
Export-PfxCertificate -Cert $clientCert -FilePath $clientPfxPath -Password $pwd | Out-Null

# Экспортируем публичную часть (для переноса на NC сервер)
$clientPemPath = "$CertDir\nextcloud-client.pem"
$certBytes     = $clientCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$b64           = [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
"-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" | Out-File $clientPemPath -Encoding ASCII

Write-Host "      Клиентский сертификат: $($clientCert.Thumbprint)"
Write-Host "      PFX (для NC плагина):  $clientPfxPath"
Write-Host "      PEM (публичный):       $clientPemPath"

# ── 5. Генерируем Bearer токен ───────────────────────────────────────
Write-Host ""
Write-Host "[5/7] Генерируем Bearer токен..." -ForegroundColor Yellow

# Создаем буфер на 48 байт
$tokenBytes = New-Object byte[] 48

# Используем криптографический генератор, совместимый со всеми версиями .NET
$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rng.GetBytes($tokenBytes)
$rng.Dispose()

# Кодируем в Base64 (в итоге получится строка около 64 символов)
$bearerToken = [System.Convert]::ToBase64String($tokenBytes)
Write-Host "      Токен сгенерирован (64 символа)"


# ── 6. Заполняем appsettings.Test.json ──────────────────────────────
Write-Host ""
Write-Host "[6/7] Генерируем appsettings.Test.json..." -ForegroundColor Yellow

$testConfig = @{
    Agent = @{
        Listen = @{
            IpAddress           = "127.0.0.1"
            Port                = 8443
            CertificatePath     = $serverPfxPath.Replace('\', '\\')
            CertificatePassword = $CertPassword
        }
        Security = @{
            BearerToken       = $bearerToken
            ClientCertificate = @{
                TrustedCaThumbprint   = $ca.Thumbprint
                Thumbprint            = $clientCert.Thumbprint
                RequiredEku           = "1.3.6.1.5.5.7.3.2"
                AllowExpiredInTestMode = $true
            }
            ProtectedGroups = @("BUILTIN\Administrators")
            MaxPathDepth    = 5
        }
        Paths = @{
            Allowed = @($TestSharePath.Replace('\', '\\'))
            Denied  = @("$($TestSharePath.Replace('\', '\\'))\\Confidential")
        }
        NcAdminGroups = @{
            Groups = @()
        }
        AdManagerDelegation = @{
            Enabled  = $false
            MaxDepth = 2
        }
        AdGroupManagement = @{
            RootOUs = @(
                @{
                    Share = $TestSharePath.Replace('\', '\\')
                    OU    = "OU=TestShare,OU=NextcloudACL,DC=lab,DC=local"
                }
            )
            GroupPrefix         = "NCFS"
            PathAttribute       = "extensionAttribute2"
            NtfsFileIdAttribute = "extensionAttribute3"
        }
        RateLimit = @{
            RequestsPerSecond   = 50
            AclChangesPerMinute = 200
            BlockDurationMinutes = 1
        }
        EventLog = @{
            Source  = "NextcloudAclAgent"
            LogName = "Application"
        }
    }
} | ConvertTo-Json -Depth 10

$testConfigPath = "$AgentDir\appsettings.Test.json"
$testConfig | Out-File $testConfigPath -Encoding UTF8
Write-Host "      Записан: $testConfigPath"

# ── 7. Event Log source ───────────────────────────────────────────────
Write-Host ""
Write-Host "[7/7] Регистрируем Event Log source..." -ForegroundColor Yellow

if (-not [System.Diagnostics.EventLog]::SourceExists("NextcloudAclAgent")) {
    [System.Diagnostics.EventLog]::CreateEventSource("NextcloudAclAgent", "Application")
    Write-Host "      Создан: NextcloudAclAgent"
} else {
    Write-Host "      Уже существует: NextcloudAclAgent"
}

# ── Итог ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Настройка завершена!"                  -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Запуск агента:" -ForegroundColor Cyan
Write-Host "  `$env:NCACL_MODE = 'Test'"
Write-Host "  cd '$AgentDir'"
Write-Host "  .\NcAclAgent.Api.exe"
Write-Host ""
Write-Host "Проверка (health check):" -ForegroundColor Cyan
Write-Host "  Invoke-WebRequest https://127.0.0.1:8443/api/acl/health -SkipCertificateCheck"
Write-Host ""
Write-Host "Для NC плагина скопируй:" -ForegroundColor Cyan
Write-Host "  Bearer Token:      $bearerToken"
Write-Host "  Client PFX:        $clientPfxPath"
Write-Host "  Client PFX Pwd:    $CertPassword"
Write-Host "  CA Thumbprint:     $($ca.Thumbprint)"
Write-Host ""
Write-Host "Event Log:" -ForegroundColor Cyan
Write-Host "  Get-EventLog -LogName Application -Source NextcloudAclAgent -Newest 20"
Write-Host ""

# Сохраняем параметры подключения в файл (для NC плагина)
$connectionInfo = @"
# NcAclAgent Test — параметры подключения для NC плагина
# Сгенерировано: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

AgentUrl     = https://127.0.0.1:8443
BearerToken  = $bearerToken
CaPfxPath    = $clientPfxPath
CaPfxPwd     = $CertPassword
CaThumbprint = $($ca.Thumbprint)
"@

$connectionInfo | Out-File "$ConfigDir\nc-plugin-connection.txt" -Encoding UTF8
Write-Host "Параметры сохранены: $ConfigDir\nc-plugin-connection.txt" -ForegroundColor Green
