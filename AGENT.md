# AGENT.md

## 1. Назначение проекта

LasTest Pentest Platform - внутренняя платформа автоматизации разрешённых pentest-проверок. Проект содержит старый CLI-режим и новый web/API-слой для управления проектами, scope и задачами сканирования.

Работать только в рамках легального и явно разрешённого scope. Не добавлять функции, которые обходят ограничения авторизации, скрывают активность или запускают произвольные команды из web.

## 2. Главная бизнес-логика

Главная сущность - проект. У проекта есть `config.yaml`, scope доменов/IP и директории с результатами:

- `recon/`
- `web/`
- `osint/`
- `phishing/`
- `reports/`
- `logs/`

Web/API создаёт задачи в SQLite. Worker забирает queued-задачи, запускает заранее разрешённые инструменты и сохраняет результаты в директорию проекта.

Web UI работает как простая SPA без Node-сборки: левое меню остаётся постоянным, а правая рабочая область переключается по hash-routes. После login проект не выбирается автоматически; пользователь должен выбрать проект в workspace selector или создать новый.

Dashboard не должен считать mock-метрики для реального проекта. Для выбранного проекта он читает артефакты из `projects/<project>/recon/...` и `projects/<project>/web/...`, а также историю jobs из SQLite.

## 3. Архитектура проекта

- CLI слой: `main.py`, `core/`, `modules/`.
- Web/API слой: `app/main.py`, `app/api/routes.py`.
- Runtime settings: `app/core/settings.py`.
- Auth guards and role dependencies: `app/core/security.py`.
- Auth routes: `app/api/auth_routes.py`.
- Auth service: `app/services/auth.py`.
- Project service: `app/services/projects.py`.
- Job queue: `app/services/jobs.py`.
- Dashboard aggregator: `app/services/dashboard.py`.
- Tool registry: `app/services/tool_registry.py`.
- Worker: `app/worker.py`.
- Static web UI: `app/static/`; страницы переключаются через `data-view` / `data-view-link` в `app/static/index.html` и `state.activeView` в `app/static/app.js`.
- Docker: `Dockerfile`, `docker-compose.yml`.

Текущий web-перенос реализован как v1-обвязка, а не полная замена CLI. При добавлении новых web-возможностей сначала выносить бизнес-логику из интерактивных CLI-функций в сервисы.

## 4. Структура директорий

```text
app/                 # новый web/API/worker слой
config/              # общие YAML-настройки
core/                # существующее CLI-ядро
modules/             # существующие pentest-модули
modules/recon/       # recon-инструменты
modules/web/         # web pentest-инструменты
modules/osint/       # OSINT-модули
modules/phishing/    # restricted-модули
modules/reports/     # отчёты
tests/               # базовые unit-тесты
```

Runtime-директории не коммитить:

```text
projects/
data/
logs/
```

## 5. Основные файлы и за что они отвечают

- `main.py` - вход в старое терминальное меню.
- `core/project.py` - CLI-управление проектами.
- `core/project_context.py` - глобальный контекст активного CLI-проекта.
- `core/user_config.py` - загрузка безопасного конфига и env-overrides.
- `core/config.yaml` - безопасный YAML-шаблон без реальных секретов.
- `app/main.py` - FastAPI app factory и static UI.
- `app/api/routes.py` - REST endpoints.
- `app/api/auth_routes.py` - login/logout/me/users/audit endpoints.
- `app/services/auth.py` - SQLite users, PBKDF2 password hashes, JWT sessions, role checks and audit log.
- `app/services/projects.py` - создание/чтение проектов и scope.
- `app/services/jobs.py` - SQLite jobs storage.
- `app/services/dashboard.py` - чтение subdomains, DNS records, HTTP probe, nuclei findings и jobs для web-dashboard.
- `app/services/tool_registry.py` - список разрешённых задач и запуск tools.
- `app/worker.py` - loop обработки очереди.
- `app/static/index.html` - shell UI, постоянный sidebar и отдельные секции Dashboard/Assets/Recon/Scans/Findings/Reports/Automation/Projects Scope/Logs/Admin.
- `app/static/app.js` - auth/session state, hash-навигация, выбор проекта, запуск задач и рендер live dashboard.
- `app/static/styles.css` - dark cybersecurity theme.
- `.env.example` - список переменных окружения без секретов.
- `docker-compose.yml` - сервисы `api` и `worker`.

## 6. Как запускать проект

Docker:

```bash
cp .env.example .env
# отредактировать AUTH_JWT_SECRET и AUTH_BOOTSTRAP_ADMIN_PASSWORD
# AUTH_BOOTSTRAP_ADMIN_PASSWORD должен быть минимум 12 символов
docker compose up --build
```

Без Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export AUTH_JWT_SECRET="local-jwt-secret"
export AUTH_BOOTSTRAP_ADMIN_PASSWORD="very-long-local-admin-password"
uvicorn app.main:app --reload
```

Worker:

```bash
export AUTH_JWT_SECRET="local-jwt-secret"
python -m app.worker
```

CLI:

```bash
python main.py
```

## 7. Как запускать тесты

Минимальные тесты без внешних pentest-инструментов:

```bash
python -m unittest discover -s tests
```

Если установлен `pytest`:

```bash
pytest
```

Перед завершением изменений запускать хотя бы `python -m unittest discover -s tests` и `python -m compileall app core modules main.py tests`.

## 8. Как добавлять новые функции

Для нового web-task:

1. Вынести неинтерактивную бизнес-логику в `app/services/`.
2. Добавить task spec в `app/services/tool_registry.py`.
3. Запускать команды только через list-based `subprocess`, без `shell=True`.
4. Валидировать все входные параметры.
5. Сохранять артефакты в директорию проекта.
6. Если результат влияет на dashboard, добавить чтение артефакта в `app/services/dashboard.py`.
7. Добавить тесты на валидацию/очередь/нормализацию/dashboard aggregation.
8. Обновить `README.md`, `AGENT.md`, `.env.example`, если появились новые команды, зависимости или переменные.

Для CLI-модуля:

1. Не ломать существующее меню.
2. Не добавлять web-зависимости в CLI-функции.
3. Общую логику держать в сервисе, а CLI оставлять thin wrapper.

## 9. Какие правила кодстайла использовать

- Python: понятные имена, type hints для новых сервисов.
- Не писать весь код в один файл.
- Не использовать `shell=True` для пользовательских параметров.
- Комментарии только для неочевидной логики.
- Ошибки превращать в понятные API-ответы или job errors.
- Runtime paths брать из settings/env.
- Не смешивать интерактивный ввод `Prompt.ask` с web-service кодом.

## 10. Какие файлы нельзя менять без необходимости

- `modules/recon/worldlist/*` - большие wordlists, менять только осознанно.
- `projects/`, `data/`, `logs/` - runtime-данные, не коммитить.
- `.env` - локальные секреты, не коммитить.
- `core/config.yaml` - держать как безопасный шаблон без реальных токенов.
- `docker-compose.yml` и `Dockerfile` - обновлять только вместе с документацией.

## 11. Какие данные нельзя коммитить

- `.env` и любые `.env.*`, кроме `.env.example`.
- API-токены Censys, Shodan, VirusTotal, Findomain.
- Логи сканирования.
- Результаты сканов.
- SQLite DB.
- Клиентские домены/IP, если они относятся к реальным внутренним проверкам.
- Nuclei findings и отчёты с уязвимостями.
- Если секрет уже попадал в историю git, не переписывать историю без прямого запроса владельца; сообщить, что секрет нужно отозвать и заменить.

## 12. Как обновлять документацию

Обновлять `README.md`, если меняется:

- способ запуска;
- Docker Compose;
- зависимости;
- переменные окружения;
- команды проверки;
- пользовательский workflow.

Обновлять `AGENT.md`, если меняется:

- архитектура;
- структура директорий;
- бизнес-логика;
- правила добавления модулей;
- статус проекта;
- roadmap.

## 13. Частые ошибки и важные нюансы

- Старые CLI-функции часто используют `Prompt.ask` и `input()`. Их нельзя напрямую вызывать из web worker.
- Web API должен работать только с разрешёнными task types из registry.
- API использует Bearer JWT, а не постоянный API key. Старый `WEB_API_KEY` оставлен только как legacy fallback для JWT secret.
- Роли: `viewer` читает, `analyst` создаёт проекты/scope/jobs, `admin` управляет users/audit.
- Первый admin создаётся из `AUTH_BOOTSTRAP_ADMIN_USERNAME` и `AUTH_BOOTSTRAP_ADMIN_PASSWORD`, только если таблица users пустая. Пароль должен быть минимум 12 символов; короткий пароль не должен ломать startup, но admin не будет создан.
- JWT-сессии хранят `jti` в SQLite `auth_sessions`; logout отзывает текущую сессию.
- Audit log хранится в SQLite `audit_events`; логировать login/logout, управление пользователями и mutating project/job actions.
- Реальные dashboard-метрики берутся через `GET /api/projects/{project_name}/dashboard`.
- `scope.domains` - ручной разрешённый scope. Не записывать туда найденные поддомены; для recon-результатов использовать `recon/subdomains/subdomains.json`.
- `dns-records` использует `dnspython`, не требует системного binary и пишет `recon/dns_records/dns_records.json`.
- `AUTH_JWT_SECRET` обязателен, если `WEB_AUTH_DISABLED=false`. `WEB_AUTH_DISABLED=true` допустим только для локального стенда.
- UI не должен автоподставлять первый проект после login. Нельзя запускать jobs или сохранять scope, пока `state.selectedProject` пустой.
- Dashboard без выбранного проекта должен показывать только состояние выбора проекта, а не mock-метрики.
- Новые UI-разделы добавлять как отдельные `data-view` секции; не превращать Dashboard в страницу “всё сразу”.
- Docker-образ тяжёлый, потому что основан на Kali и ставит pentest tools.
- Go-based tools собираются в отдельном Docker builder stage и копируются в runtime как готовые binaries. Не добавлять `build` в `worker`, иначе Compose снова начнёт собирать один и тот же image дважды.
- Go-based tools ставятся на этапе build, поэтому нужен доступ к сети.
- Контейнер стартует через `docker-entrypoint.sh`: он чинит права на bind mounts `projects/data/logs`, затем запускает команду от `appuser`. Не возвращать `USER appuser` без альтернативного способа исправить права на host-mounted директории.
- `app/main.py` добавляет `Cache-Control: no-store` для `/` и `/static/*`, а HTML подключает CSS/JS с version query. Это нужно, чтобы браузер не показывал старый или неоформленный UI после пересборки контейнера.
- SQLite подходит для локального single-host режима. Для multi-user и высокой параллельности нужен PostgreSQL/Redis.
- Не выводить секреты в логи job.

## 14. Текущий статус проекта

Сделано:

- Добавлен FastAPI web/API слой.
- Добавлена статическая web-панель в dark cybersecurity dashboard стиле.
- UI переведён на отдельные страницы внутри SPA: Dashboard, Assets, Recon, Scans, Findings, Reports, Automation, Projects / Scope, Logs и Admin.
- Добавлена login/password авторизация, JWT-сессии, роли пользователей и audit log.
- Добавлен live dashboard aggregator для реальных subdomains, DNS records, HTTP probe, findings и jobs.
- Добавлена SQLite-очередь задач.
- Добавлен worker.
- Добавлен Dockerfile на Kali.
- Добавлен Docker Compose с `api` и `worker`.
- Добавлен `.env.example`.
- Удалён hardcoded API token из `core/config.yaml`.
- `core/user_config.py` теперь поддерживает env-overrides для секретов.
- Добавлены базовые тесты.

Ограничения:

- Web покрывает первые задачи: `subfinder`, `dns-records`, `httpx-root`, `nuclei`.
- Большая часть старых CLI-модулей ещё не вынесена в неинтерактивные сервисы.
- Управление пользователями в UI пока минимальное: create/list/audit.
- Нет отмены задач.

## 15. TODO / Roadmap

- Перенести `nmap`, URL discovery, ffuf, reports в web task registry.
- Добавить PostgreSQL и Redis/RQ или Celery для production-подобного режима.
- Добавить отмену задач и лимиты параллелизма.
- Добавить reset password / disable user / edit role в UI.
- Добавить scheduler.
- Добавить экспорт отчётов через web.
- Добавить интеграционные тесты API.
- Зафиксировать версии Go tools и nuclei templates.
- Разделить lightweight API image и heavy worker image, если build станет слишком большим.
