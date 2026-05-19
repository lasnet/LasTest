# LasTest Pentest Platform

## 1. Название проекта

LasTest Pentest Platform.

## 2. Краткое описание проекта

LasTest - внутренняя платформа для автоматизации разрешённых pentest-проверок компании. Исторически проект запускался через терминальное меню на Kali Linux. Сейчас добавлен первый web/API-слой управления и Docker Compose-инфраструктура, чтобы проект можно было запускать локально как контейнеризированный сервис.

Важно: платформа предназначена только для активов, на которые у команды есть письменное разрешение на проверку.

## 3. Что умеет проект

- Вести проекты и scope: домены, IP-адреса, исключения.
- Хранить ручной scope отдельно от результатов recon, чтобы найденные поддомены не загрязняли разрешённый scope.
- Работать в старом CLI-режиме через `python main.py`.
- Запускать web-панель управления на FastAPI.
- Использовать login/password авторизацию с JWT-сессиями.
- Разграничивать доступ по ролям `admin`, `analyst`, `viewer`.
- Использовать тёмный cybersecurity SaaS UI с постоянным левым меню и отдельными страницами: Dashboard, Assets, Recon, Scans, Findings, Reports, Automation, Projects / Scope, Logs и Admin.
- После login проект не выбирается автоматически: пользователь должен выбрать существующий проект или создать новый.
- Наполнять dashboard реальными артефактами проекта: subdomains, DNS records, HTTP probe, findings и history jobs.
- Создавать задачи через API и web UI.
- Выполнять задачи отдельным worker-процессом через SQLite-очередь.
- Поддерживать первые web-задачи:
  - `subfinder` - пассивный поиск поддоменов;
  - `dns-records` - резолв DNS-записей `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`;
  - `httpx-root` - проверка доступных HTTP/S-хостов;
  - `nuclei` - шаблонный web vulnerability scan по живым целям.
- Сохранять результаты в директории проекта.

## 4. Архитектура проекта

Текущая архитектура гибридная:

- `main.py`, `core/`, `modules/` - существующий CLI и pentest-модули.
- `app/` - новый web/API-слой.
- `app/api/auth_routes.py` - login/logout, текущий пользователь, users и audit endpoints.
- `app/services/auth.py` - пользователи, password hashing, JWT, sessions и audit log в SQLite.
- `app/services/projects.py` - управление проектами и YAML-конфигами.
- `app/services/jobs.py` - SQLite-хранилище задач.
- `app/services/dashboard.py` - агрегация реальных результатов проекта для dashboard.
- `app/services/tool_registry.py` - безопасный реестр разрешённых задач. Web не принимает произвольные shell-команды.
- `app/worker.py` - отдельный процесс, который забирает задачи из очереди и запускает инструменты.
- `app/static/` - простая SPA web-панель без Node-сборки. Левое меню статично, рабочая область справа переключается через hash-routes.
- `Dockerfile` - multi-stage Kali-based образ: Go-инструменты собираются в builder stage, а в runtime попадают только готовые binaries.
- `docker-compose.yml` - сервисы `api` и `worker`; образ собирается один раз сервисом `api`, `worker` использует тот же image.

Перенос в web и Docker возможен. Правильная стратегия - не переписывать всё сразу, а постепенно выносить интерактивные CLI-функции в неинтерактивные сервисы, которые можно вызывать из API и worker.

## 5. Структура директорий

```text
.
├── app/                    # FastAPI, web UI, worker, сервисный слой
│   ├── api/                # HTTP routes
│   ├── core/               # settings, security
│   ├── models/             # Pydantic-схемы API
│   ├── services/           # проекты, задачи, валидация, запуск tools
│   └── static/             # HTML/CSS/JS web-панели
├── config/                 # общие YAML-настройки, например proxy config
├── core/                   # существующее CLI-ядро
├── modules/                # существующие pentest-модули
├── tests/                  # базовые тесты
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
├── README.md
└── AGENT.md
```

Runtime-директории создаются локально и не коммитятся:

```text
projects/   # проекты и результаты сканов
data/       # SQLite и runtime-данные
logs/       # логи приложения и задач
```

## 6. Используемые технологии

- Python 3.
- FastAPI и Uvicorn для web/API.
- SQLite для локальной очереди задач.
- PBKDF2-SHA256 password hashing и HMAC-SHA256 JWT без внешних auth-зависимостей.
- Vanilla HTML/CSS/JS для web UI.
- Docker Compose.
- Kali Linux container base image.
- Pentest tools: `nmap`, `amass`, `whatweb`, `nikto`, `sqlmap`, `theHarvester`, `ffuf`, `dnsmap`, `proxychains4`, `subfinder`, `httpx`, `nuclei`, `gau`, `waybackurls`, `katana`, `hakrevdns`.

## 7. Требования для запуска

Для Docker-запуска:

- Docker.
- Docker Compose v2.
- Доступ к сети на этапе сборки образа, потому что Go-инструменты устанавливаются через `go install`.

Для запуска без Docker:

- Python 3.11+.
- Системные pentest-инструменты в `PATH`.
- Go, если нужно устанавливать Go-based инструменты вручную.

## 8. Настройка `.env`

Создайте локальный `.env` из примера:

```bash
cp .env.example .env
```

Обязательно измените:

```bash
AUTH_JWT_SECRET=your-long-random-jwt-secret
AUTH_BOOTSTRAP_ADMIN_PASSWORD=your-long-random-admin-password
```

`AUTH_BOOTSTRAP_ADMIN_PASSWORD` должен быть минимум 12 символов. Если пароль короче, admin не будет создан, а UI покажет setup required.

При первом старте, если пользователей ещё нет, backend создаст admin-пользователя:

```bash
AUTH_BOOTSTRAP_ADMIN_USERNAME=admin
AUTH_BOOTSTRAP_ADMIN_PASSWORD=your-long-random-admin-password
```

После первого успешного входа пароль bootstrap можно удалить из `.env` или оставить пустым. Новый admin не будет пересоздан, если в базе уже есть пользователи.

Секреты и токены задаются только через `.env` или переменные окружения:

```bash
CENSYS_PERSONAL_ACCESS_TOKEN=
FINDOMAIN_VIRUSTOTAL_TOKEN=
SHODAN_API_KEY=
```

Не коммитьте `.env`.

## 9. Запуск через Docker Compose

Собрать и запустить:

```bash
docker compose up --build
```

Открыть web UI:

```text
http://localhost:8000
```

Войдите через форму login:

```text
username: admin
password: значение AUTH_BOOTSTRAP_ADMIN_PASSWORD из .env
```

Для полностью локального стенда можно временно отключить авторизацию:

```bash
WEB_AUTH_DISABLED=true
```

Не используйте этот режим на доступном извне сервере.

Проверить health endpoint:

```bash
curl http://localhost:8000/api/health
```

Остановить:

```bash
docker compose down
```

Просмотреть логи:

```bash
docker compose logs -f api
docker compose logs -f worker
```

## 10. Запуск без Docker

Создать окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Запустить старый CLI:

```bash
python main.py
```

Запустить web/API:

```bash
export AUTH_JWT_SECRET="local-jwt-secret"
export AUTH_BOOTSTRAP_ADMIN_PASSWORD="very-long-local-admin-password"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Запустить worker во втором терминале:

```bash
export AUTH_JWT_SECRET="local-jwt-secret"
python -m app.worker
```

## 11. Основные команды

```bash
# Тесты без внешних pentest-инструментов
python -m unittest discover -s tests

# CLI
python main.py

# API локально
uvicorn app.main:app --reload

# Worker локально
python -m app.worker

# Docker
docker compose up --build
docker compose down
```

## 12. Как проверить, что проект работает

1. Запустите `python -m unittest discover -s tests`.
2. Запустите `docker compose up --build`.
3. Откройте `http://localhost:8000`.
4. Войдите под admin-пользователем.
5. Создайте проект.
6. Добавьте разрешённый домен в scope.
7. После login выберите проект в workspace selector или создайте новый через `+ New project`.
8. Откройте `Projects / Scope` и добавьте разрешённый DNS/IP scope.
9. Откройте `Recon` или `Automation` и запустите задачи `Subdomains`, `DNS Records`, затем `HTTP Probe`.
10. Вернитесь в `Dashboard` и убедитесь, что cards, Assets, Scans и Logs начали обновляться реальными данными.

API-проверка:

```bash
TOKEN=$(curl -s \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASSWORD"}' \
  http://localhost:8000/api/auth/login | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/projects
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/projects/example.com/dashboard
curl -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task_type":"dns-records","params":{}}' \
  http://localhost:8000/api/projects/example.com/jobs
```

## 13. Типичные проблемы и их решение

- `AUTH_JWT_SECRET or WEB_API_KEY is not configured` - задайте `AUTH_JWT_SECRET` в `.env`.
- `No admin user exists` - задайте `AUTH_BOOTSTRAP_ADMIN_PASSWORD` длиной минимум 12 символов в `.env` и перезапустите `api`.
- `Session expired or invalid` - выполните login заново.
- `Role 'analyst' or higher is required` - пользователь с ролью `viewer` может смотреть данные, но не может создавать проекты, менять scope и запускать jobs.
- `Create or select a project first` - после login проект специально не выбирается автоматически. Создайте проект через `+ New project` или выберите существующий в workspace selector.
- `Missing required tools` - нужный binary не установлен или отсутствует в `PATH`.
- Docker build долго идёт - образ ставит Kali-пакеты и Go-based инструменты.
- `no space left on device` при Docker build - очистите старые Docker-слои командой `docker system prune -af` и проверьте место через `docker system df`; Dockerfile уже не сохраняет Go build cache в финальном образе.
- `api` перезапускается или unhealthy сразу после старта - проверьте `docker compose logs api --tail=100`; частая причина на bind mounts - права на `./projects`, `./data`, `./logs`. Entrypoint контейнера создаёт эти директории, исправляет владельца и запускает процесс от `appuser`.
- Если UI выглядит как неоформленный HTML с огромными чёрными иконками - браузер не загрузил актуальный CSS. Пересоберите контейнер, сделайте hard refresh `Ctrl+F5`; статические ассеты имеют cache-busting query и `Cache-Control: no-store`.
- `nuclei` не находит шаблоны - обновите templates внутри контейнера или worker-среды.
- Нет DNS Records - проверьте, что в scope есть домен и контейнер/сервер может резолвить DNS.
- Нет результатов `httpx-root` - сначала запустите `subfinder` или передайте targets через API.
- Старые CLI-модули запрашивают ввод - это ожидаемо; web должен использовать неинтерактивные сервисы из `app/services/`.

## 14. Что ещё нужно доработать в будущем

- Перенести остальные CLI-модули в неинтерактивные сервисы.
- Добавить полноценные статусы прогресса по стадиям сканирования.
- Добавить PostgreSQL/Redis при переходе от single-host запуска к multi-user режиму.
- Добавить отмену задач и лимиты параллелизма.
- Добавить scheduler для регулярных проверок.
- Добавить централизованный отчётный модуль.
- Расширить UI управления пользователями: disable/reset password/edit role.
- Добавить OpenAPI-примеры для каждого task type.
- Закрепить версии системных и Go-инструментов для воспроизводимых сборок.

## 15. Другие важные моменты по проекту

- Web API не должен запускать произвольные команды пользователя.
- Любой новый scanner добавляется через `app/services/tool_registry.py`.
- Все новые переменные окружения нужно добавлять в `.env.example`, `README.md` и `AGENT.md`.
- Все изменения архитектуры или команд запуска нужно отражать в `AGENT.md`.
- Секреты нельзя хранить в `core/config.yaml`, `.env.example`, README, тестах или коде.
- Директории `projects/`, `data/`, `logs/` являются runtime-данными и исключены из git.
- Если реальный токен уже попадал в git-историю, его нужно отозвать и выпустить новый.
