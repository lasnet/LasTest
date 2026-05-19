# LasTest Pentest Platform

## 1. Название проекта

LasTest Pentest Platform.

## 2. Краткое описание проекта

LasTest - внутренняя платформа для автоматизации разрешённых pentest-проверок компании. Исторически проект запускался через терминальное меню на Kali Linux. Сейчас добавлен первый web/API-слой управления и Docker Compose-инфраструктура, чтобы проект можно было запускать локально как контейнеризированный сервис.

Важно: платформа предназначена только для активов, на которые у команды есть письменное разрешение на проверку.

## 3. Что умеет проект

- Вести проекты и scope: домены, IP-адреса, исключения.
- Работать в старом CLI-режиме через `python main.py`.
- Запускать web-панель управления на FastAPI.
- Создавать задачи через API и web UI.
- Выполнять задачи отдельным worker-процессом через SQLite-очередь.
- Поддерживать первые web-задачи:
  - `subfinder` - пассивный поиск поддоменов;
  - `httpx-root` - проверка доступных HTTP/S-хостов;
  - `nuclei` - шаблонный web vulnerability scan по живым целям.
- Сохранять результаты в директории проекта.

## 4. Архитектура проекта

Текущая архитектура гибридная:

- `main.py`, `core/`, `modules/` - существующий CLI и pentest-модули.
- `app/` - новый web/API-слой.
- `app/services/projects.py` - управление проектами и YAML-конфигами.
- `app/services/jobs.py` - SQLite-хранилище задач.
- `app/services/tool_registry.py` - безопасный реестр разрешённых задач. Web не принимает произвольные shell-команды.
- `app/worker.py` - отдельный процесс, который забирает задачи из очереди и запускает инструменты.
- `app/static/` - простая web-панель без Node-сборки.
- `Dockerfile` - единый Kali-based образ с Python, Go-инструментами и pentest-tooling.
- `docker-compose.yml` - сервисы `api` и `worker`.

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
WEB_API_KEY=your-long-random-local-key
```

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

В поле `X-API-Key` вставьте значение `WEB_API_KEY` из `.env`.

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
export WEB_API_KEY="local-dev-key"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Запустить worker во втором терминале:

```bash
export WEB_API_KEY="local-dev-key"
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
4. Введите API key.
5. Создайте проект.
6. Добавьте разрешённый домен в scope.
7. Запустите задачу `Subfinder`.
8. Убедитесь, что задача появилась в списке Jobs и worker пишет лог.

API-проверка:

```bash
curl -H "X-API-Key: $WEB_API_KEY" http://localhost:8000/api/projects
```

## 13. Типичные проблемы и их решение

- `WEB_API_KEY is not configured` - задайте `WEB_API_KEY` в `.env`.
- `Invalid or missing API key` - в web UI указан неверный ключ.
- `Missing required tools` - нужный binary не установлен или отсутствует в `PATH`.
- Docker build долго идёт - образ ставит Kali-пакеты и Go-based инструменты.
- `nuclei` не находит шаблоны - обновите templates внутри контейнера или worker-среды.
- Нет результатов `httpx-root` - сначала запустите `subfinder` или передайте targets через API.
- Старые CLI-модули запрашивают ввод - это ожидаемо; web должен использовать неинтерактивные сервисы из `app/services/`.

## 14. Что ещё нужно доработать в будущем

- Перенести остальные CLI-модули в неинтерактивные сервисы.
- Добавить полноценные статусы прогресса по стадиям сканирования.
- Добавить RBAC и нормальную пользовательскую авторизацию.
- Добавить PostgreSQL/Redis при переходе от single-host запуска к multi-user режиму.
- Добавить отмену задач и лимиты параллелизма.
- Добавить scheduler для регулярных проверок.
- Добавить централизованный отчётный модуль.
- Добавить audit log для действий пользователя.
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
