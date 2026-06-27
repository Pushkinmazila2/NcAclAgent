# Nextcloud ACL Agent

Windows-агент для управления NTFS ACL по командам из Nextcloud плагина.
https://github.com/Pushkinmazila2/NextcloudACLmanager

## Структура монорепо

```
NcAclAgent/
├── src/
│   ├── NcAclAgent.Core/          — бизнес-логика (модели, сервисы, интерфейсы)
│   ├── NcAclAgent.Api/           — ASP.NET Core Web API
│   └── NcAclAgent.Service/       — Windows Service обёртка
├── .github/
│   └── workflows/
│       ├── build-release.yml     — сборка и публикация GitHub Release (по тегу)
│       └── deploy.yml            — деплой через Ansible (ручной запуск)
├── ansible/
│   ├── inventory/
│   │   ├── prod/                 — prod хосты + host_vars (с vault)
│   │   └── test/                 — test хосты
│   ├── group_vars/
│   │   ├── all/                  — общие переменные
│   │   ├── prod/                 — prod-специфичные
│   │   └── test/                 — test-специфичные
│   ├── roles/
│   │   └── ncaclagent/           — основная роль деплоя
│   │       ├── tasks/            — preflight, install, configure, service, verify...
│   │       ├── templates/        — appsettings.json.j2
│   │       └── files/certs/      — PFX сертификаты по хостам (НЕ в git!)
│   ├── playbooks/
│   │   ├── deploy.yml
│   │   └── rollback.yml
│   └── requirements.yml
└── installer/
    └── Install-NcAclAgent.ps1   — PowerShell установщик для Test режима
```

---

## Режимы работы

| | Test | Prod |
|---|---|---|
| Сертификат | Самоподписанный | Доверенный CA |
| Конфиг | Полный из файла | Только Paths + cert из файла |
| Секреты | appsettings.Test.json | Environment variables |
| Self-test fail | Предупреждение, продолжает | Падает, не запускается |
| Expired cert | Разрешён (если AllowExpiredInTestMode) | Запрещён |

Режим задаётся через `NCACL_MODE=Test|Prod`.

---

## CI/CD: Сборка и релиз

```bash
git tag v1.2.3
git push origin v1.2.3
```

GitHub Actions собирает win-x64 self-contained бинарник, прогоняет тесты и публикует GitHub Release.

### Необходимые GitHub Secrets

| Secret | Описание |
|---|---|
| `ANSIBLE_VAULT_PASSWORD` | Пароль для расшифровки vault файлов |
| `ANSIBLE_SSH_PRIVATE_KEY` | Приватный SSH ключ для Windows хостов |

---

## CI/CD: Деплой

```
GitHub → Actions → Deploy → Run workflow
  version:     v1.2.3
  environment: prod
  limit:       fileserver01.company.local
```

### Локально

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml

# Dry-run
ansible-playbook playbooks/deploy.yml \
  --inventory inventory/prod/hosts.yml \
  --vault-password-file ~/.vault_pass \
  --extra-vars "agent_version=v1.2.3" \
  --check --diff

# Деплой
ansible-playbook playbooks/deploy.yml \
  --inventory inventory/prod/hosts.yml \
  --vault-password-file ~/.vault_pass \
  --extra-vars "agent_version=v1.2.3"

# Откат
ansible-playbook playbooks/rollback.yml \
  --inventory inventory/prod/hosts.yml \
  --vault-password-file ~/.vault_pass \
  --extra-vars "agent_version=v1.1.0"
```

---

## Управление секретами

```bash
# Создать vault файл для хоста
ansible-vault create ansible/inventory/prod/host_vars/fileserver01.company.local.vault.yml

# Редактировать
ansible-vault edit ansible/inventory/prod/host_vars/fileserver01.company.local.vault.yml
```

Структура vault файла:
```yaml
vault_ansible_password:               "..."
vault_agent_bearer_token:             "..."   # минимум 32 символа
vault_agent_cert_password:            "..."
vault_agent_ca_thumbprint:            "..."
vault_agent_service_account_password: "..."
```

---

## Добавление нового хоста (Prod)

1. Запись в `ansible/inventory/prod/hosts.yml`
2. Создать `host_vars/<hostname>.yml` (незашифрованное)
3. Создать и зашифровать `host_vars/<hostname>.vault.yml`
4. Положить PFX: `ansible/roles/ncaclagent/files/certs/<hostname>/agent.pfx`
5. Запустить деплой с `--limit <hostname>`

---

## Windows Event Log

```powershell
Get-EventLog -LogName Application -Source NextcloudAclAgent -Newest 20
```

| EventID | Тип | Описание | SIEM |
|---|---|---|---|
| 1000 | Info | Агент запущен | |
| 1010-1012 | Info | ACL read/set/remove | |
| 2000-2003 | Warn | Ошибки аутентификации | ⚠️ |
| 2010 | Warn | Path traversal attempt | 🚨 |
| 2031 | Warn | Защищённая группа | ⚠️ |
| 4000 | Info | Self-test OK | |
| 4001 | Error | Self-test FAILED | 🚨 |
