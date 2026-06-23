#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Установка Nextcloud ACL Agent как Windows Service
.DESCRIPTION
    Создаёт сервисный аккаунт в AD, регистрирует Windows Service,
    настраивает Event Log source, применяет минимальные права.
.PARAMETER ServiceUser
    Доменный аккаунт для запуска сервиса (DOMAIN\svc_ncaclagent)
.PARAMETER ServicePassword
    Пароль сервисного аккаунта
.PARAMETER InstallPath
    Путь установки (по умолчанию: C:\Program Files\NcAclAgent)
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ServiceUser,

    [Parameter(Mandatory=$true)]
    [SecureString]$ServicePassword,

    [string]$InstallPath = "C:\Program Files\NcAclAgent",
    [string]$ConfigPath  = "C:\ProgramData\NcAclAgent"
)

$ServiceName        = "NextcloudAclAgent"
$ServiceDisplayName = "Nextcloud ACL Agent"
$ServiceDescription = "Управление NTFS ACL по команде из Nextcloud"
$EventLogSource     = "NextcloudAclAgent"
$ExecutablePath     = Join-Path $InstallPath "NcAclAgent.Service.exe"

# ── Проверки ──────────────────────────────────────────────────────────
Write-Host "[*] Проверяем окружение..." -ForegroundColor Cyan

if (-not (Test-Path $ExecutablePath)) {
    Write-Error "Исполняемый файл не найден: $ExecutablePath"
    exit 1
}

# ── Event Log source ──────────────────────────────────────────────────
Write-Host "[*] Регистрируем Event Log source..." -ForegroundColor Cyan

if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
    [System.Diagnostics.EventLog]::CreateEventSource($EventLogSource, "Application")
    Write-Host "    Создан источник: $EventLogSource" -ForegroundColor Green
} else {
    Write-Host "    Источник уже существует: $EventLogSource" -ForegroundColor Yellow
}

# ── Директории и права ────────────────────────────────────────────────
Write-Host "[*] Настраиваем директории..." -ForegroundColor Cyan

@($InstallPath, "$ConfigPath\certs", "$ConfigPath\logs") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Host "    Создана папка: $_" -ForegroundColor Green
    }
}

# Сервисный аккаунт — только чтение конфига, нет прав на исходники
$acl = Get-Acl $ConfigPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $ServiceUser, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $ConfigPath $acl
Write-Host "    Права на $ConfigPath выданы для $ServiceUser" -ForegroundColor Green

# ── Windows Service ───────────────────────────────────────────────────
Write-Host "[*] Устанавливаем Windows Service..." -ForegroundColor Cyan

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "    Останавливаем существующий сервис..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

$cred = New-Object System.Management.Automation.PSCredential($ServiceUser, $ServicePassword)
$plainPassword = $cred.GetNetworkCredential().Password

# Создаём сервис
New-Service `
    -Name $ServiceName `
    -DisplayName $ServiceDisplayName `
    -Description $ServiceDescription `
    -BinaryPathName "`"$ExecutablePath`"" `
    -StartupType Automatic `
    -Credential $cred | Out-Null

Write-Host "    Сервис создан: $ServiceName" -ForegroundColor Green

# Настраиваем восстановление при сбое (перезапуск через 30 секунд)
sc.exe failure $ServiceName reset= 86400 actions= restart/30000/restart/60000/restart/120000 | Out-Null
Write-Host "    Настроено автовосстановление при сбоях" -ForegroundColor Green

# ── Firewall правило ─────────────────────────────────────────────────
Write-Host "[*] Настраиваем Firewall..." -ForegroundColor Cyan

$fwRuleName = "Nextcloud ACL Agent - Inbound"
Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue

# ВАЖНО: в Production указать конкретный IP Nextcloud-сервера в -RemoteAddress
New-NetFirewallRule `
    -DisplayName $fwRuleName `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8443 `
    -Action Allow `
    -Profile Domain `
    -Description "Разрешает входящие HTTPS соединения от Nextcloud к ACL Agent" | Out-Null

Write-Host "    Правило Firewall создано (Profile: Domain)" -ForegroundColor Green
Write-Host "    ВАЖНО: Ограничьте -RemoteAddress IP-адресом Nextcloud!" -ForegroundColor Yellow

# ── Запуск ────────────────────────────────────────────────────────────
Write-Host "[*] Запускаем сервис..." -ForegroundColor Cyan
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$status = Get-Service -Name $ServiceName
if ($status.Status -eq "Running") {
    Write-Host "[OK] Сервис запущен успешно" -ForegroundColor Green
} else {
    Write-Error "Сервис не запустился. Статус: $($status.Status)"
    Write-Host "Проверьте Event Log: Get-EventLog -LogName Application -Source $EventLogSource -Newest 10"
    exit 1
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Nextcloud ACL Agent установлен успешно!" -ForegroundColor Green
Write-Host "  Проверка логов:" -ForegroundColor White
Write-Host "  Get-EventLog -LogName Application -Source $EventLogSource -Newest 20" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
