# Установка LasTest

Для готового образа Linux `amd64` нужны Docker и Docker Compose. API и worker используют один образ и общий том `lastest-data`.

## Запуск и первый вход

```bash
docker compose up -d
docker compose exec api lastest admin setup-code
```

Откройте `http://127.0.0.1:8080`. На экране **Create the first administrator** введите поле `code` из вывода команды, имя и пароль от 12 символов. Затем войдите под созданной учётной записью.

Код выдаётся локальной командой, действует 15 минут и погашается при создании первого пользователя. Повторный выпуск заменяет предыдущий код. Пароль администратора задаётся в браузере. После создания аккаунта форма настройки закрывается. Для установки без браузера можно выполнить `docker compose exec api lastest admin bootstrap --username admin` и ввести пароль в терминале.

## Доступ с других машин

Создайте `.env` из `.env.example` только если нужно изменить настройки. Docker Compose читает `.env` автоматически.

| Доступ | Настройки |
| --- | --- |
| С Docker-хоста по HTTP | `LASTEST_HOST_IP=127.0.0.1` и `LASTEST_SECURE_COOKIES=false` по умолчанию |
| Из доверенной LAN или VPN | IP интерфейса Docker-хоста в `LASTEST_HOST_IP`. На обеих машинах открывайте этот IP. |
| Через HTTPS reverse proxy | `LASTEST_HOST_IP=127.0.0.1` и `LASTEST_SECURE_COOKIES=true` |

Порт задаётся через `LASTEST_PORT`, по умолчанию `8080`. После изменения `.env` выполните `docker compose up -d`. Диапазоны для задач настраиваются отдельно через `LASTEST_INTERNAL_RANGES`.

## Обновление образа и данных

По умолчанию Compose использует `ghcr.io/lasnet/lastest:dev`. Для закрепления сборки можно указать `LASTEST_IMAGE=ghcr.io/lasnet/lastest@sha256:...` в `.env`. Digest доступен в итогах запуска GitHub Actions.

```bash
docker compose pull
docker compose up -d --no-build --pull never
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health/ready
```

Если API привязан к другому адресу, используйте этот адрес для проверки. Для дополнительной диагностики выполните `docker compose run --rm api doctor`.

При переходе со старого Compose сначала остановите его из старой копии командой `down`, сохранив том. Имя тома можно увидеть через `docker volume ls --filter name=lastest`. Укажите его в новом `.env` как `LASTEST_DATA_VOLUME`, чтобы подключить существующие аккаунты, проекты и результаты. При первом старте SQLite применит новую миграцию. Для чистой установки используйте пустой том.

Для внешних скриптов обновите префикс маршрутов на `/api`. Встроенный интерфейс и CLI уже используют новые адреса.

## HTTPS через reverse proxy

Для HTTPS используйте доверенный reverse proxy на Docker-хосте и задайте `LASTEST_HOST_IP=127.0.0.1`.

Пример Caddy:

```caddy
lastest.example.internal {
    reverse_proxy 127.0.0.1:8080
}
```

Условия:

- `LASTEST_SECURE_COOKIES=true`;
- браузер открывает только HTTPS URL прокси;
- прокси передаёт исходный `Host` и не ослабляет `Origin`;
- порт 8080 не публикуется во внешнюю сеть.

Проверка: после входа cookie `lastest_session` имеет `HttpOnly`, `Secure`, `SameSite=Strict`; изменяющий запрос без совпадающего `Origin` возвращает `403 csrf_failed`.

## Права тома и ограничения

Образ работает как UID/GID `10001:10001`, без root, с `cap_drop: ALL` и `no-new-privileges`. Для bind mount заранее выдайте права:

```bash
install -d -m 0750 -o 10001 -g 10001 /srv/lastest-data
```

Настройки роста:

- SQLite WAL на локальном томе, короткие транзакции, `busy_timeout`;
- `max_artifact_bytes`, `max_body_bytes`, `max_queue_targets`, `max_crawl_pages`, `max_wordlist_entries`;
- Docker logging ограничен `20m × 5`;
- `retention_days` задокументирован; автоматическое удаление доказательств не включено в первый релиз, очистку выполняйте по инструкции [rollback.md](rollback.md).

## Конфигурация

Шаблон: `config/lastest.toml.example`. Файл передаётся через `LASTEST_CONFIG`. Основные env-overrides: `LASTEST_DATA_DIR`, `LASTEST_BIND`, `LASTEST_DNS_SERVER`, `LASTEST_SECURE_COOKIES`, `LASTEST_INTERNAL_RANGES`, `LASTEST_CERTSPOTTER_TOKEN`, `LASTEST_CENSYS_API_ID`, `LASTEST_CENSYS_API_SECRET`, `LASTEST_NMAP_PATH`, `LASTEST_LOG_LEVEL`.

Внутренние диапазоны — только явно заданные администратором. Адреса метаданных (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) блокируются всегда. DNS-имя в scope не даёт разрешения на сканирование всех портов его IP.

## Локальная сборка

```bash
docker build -t lastest:local .
LASTEST_IMAGE=lastest:local docker compose up -d --no-build --pull never
```

Для сборки с нуля добавьте `--pull --no-cache` к `docker build`. Если нужна чистая база, команда `docker compose down -v` удаляет том LasTest с аккаунтами, проектами и результатами. После запуска на пустом томе снова получите код из раздела «Запуск и первый вход».

Для сквозной проверки запуска используйте `./scripts/e2e.sh` с `LASTEST_IMAGE` по digest. Скрипт создаёт собственные контейнеры, сеть и том и выполняет тестовую задачу.
