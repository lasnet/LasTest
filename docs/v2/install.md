# Установка LasTest 2.0

LasTest 2.0 использует один OCI-образ для API и worker. Оба процесса работают от непривилегированного пользователя и используют общий том `lastest-v2-data`, смонтированный в `/data`.

## 1. Скачать образ из GHCR

После проверки ветки `dev` GitHub Actions публикует образ для Linux `amd64`. Тег `dev` указывает на последнюю проверенную сборку, а тег `sha-<полный SHA коммита>` позволяет найти конкретную сборку. В итогах запуска Actions указан её digest.

Для приватного пакета войдите в GHCR под GitHub-аккаунтом с доступом к пакету. При запросе пароля введите GitHub PAT classic с правом `read:packages`. Токен хранится в настройках клиента Docker и не входит в `.env.v2`. [Вход в GHCR](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic)

```bash
docker login ghcr.io
docker pull ghcr.io/lasnet/lastest:dev
docker image inspect ghcr.io/lasnet/lastest:dev --format '{{index .RepoDigests 0}}'
```

Скопируйте строку вида `ghcr.io/lasnet/lastest@sha256:...` для Compose. Если digest уже есть из CI, достаточно входа в GHCR и шага 2.

## 2. Подготовить Compose

При первой установке создайте `.env.v2` командой `cp .env.v2.example .env.v2`. Укажите полученный digest в `LASTEST_IMAGE`. Со стандартными настройками API доступен на `127.0.0.1:8080`. Для HTTP на loopback либо в доверенной локальной сети выставьте `LASTEST_SECURE_COOKIES=false`. Для HTTPS через reverse proxy оставьте `true`. Внутренние диапазоны для сканирования задаются отдельно в `LASTEST_INTERNAL_RANGES`.

```bash
docker compose --env-file .env.v2 -f compose.v2.yaml config -q
docker compose --env-file .env.v2 -f compose.v2.yaml pull
```

## 3. Первый администратор

При чистой установке создайте первого администратора. Команда попросит ввести пароль в терминале. Минимум 12 символов. При обновлении существующей установки переходите к следующему шагу.

```bash
docker compose --env-file .env.v2 -f compose.v2.yaml run --rm -i --no-deps --pull never \
  api admin bootstrap --username admin
```

Для локального запуска без Compose:

```bash
lastest --data-dir ./lastest-data admin bootstrap --username admin --password-stdin
```

## 4. Запуск и диагностика

```bash
docker compose --env-file .env.v2 -f compose.v2.yaml up -d --no-build --pull never
docker compose --env-file .env.v2 -f compose.v2.yaml ps
curl -fsS http://127.0.0.1:8080/api/v2/health/ready
```

Для обновления с локального образа `lastest-v2:local` или предыдущего digest замените только `LASTEST_IMAGE` в действующем `.env.v2`. Выполните `pull` из шага 2 и `up` выше. Compose использует существующий том с регистрацией пользователей, проектами и результатами.

Если порт опубликован на конкретном IP сервера, используйте этот IP для проверки `/api/v2/health/ready`.

Перед запуском проверьте конфигурацию и том:

```bash
docker compose --env-file .env.v2 -f compose.v2.yaml run --rm api doctor
```

`doctor` сообщает: валидна ли конфигурация, доступен ли том на запись, свободное место, версию и совместимость схемы, доступность Nmap и настроенных провайдеров. Go/Python/компиляторы в runtime отсутствуют.

## 5. TLS и reverse proxy

Приложение не завершает TLS само. Рабочая схема: trusted reverse proxy на том же хосте, API слушает только loopback.

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

## 6. Права тома и ограничения

Образ работает как UID/GID `10001:10001`, без root, с `cap_drop: ALL` и `no-new-privileges`. Для bind mount заранее выдайте права:

```bash
install -d -m 0750 -o 10001 -g 10001 /srv/lastest-data
```

Настройки роста:

- SQLite WAL на локальном томе, короткие транзакции, `busy_timeout`;
- `max_artifact_bytes`, `max_body_bytes`, `max_queue_targets`, `max_crawl_pages`, `max_wordlist_entries`;
- Docker logging ограничен `20m × 5`;
- `retention_days` задокументирован; автоматическое удаление доказательств не включено в первый релиз, очистку выполняйте по инструкции [rollback.md](rollback.md).

## 7. Конфигурация

Шаблон: `config/v2/lastest.toml.example`. Файл передаётся через `LASTEST_CONFIG`. Основные env-overrides: `LASTEST_DATA_DIR`, `LASTEST_BIND`, `LASTEST_DNS_SERVER`, `LASTEST_SECURE_COOKIES`, `LASTEST_INTERNAL_RANGES`, `LASTEST_CERTSPOTTER_TOKEN`, `LASTEST_CENSYS_API_ID`, `LASTEST_CENSYS_API_SECRET`, `LASTEST_NMAP_PATH`, `LASTEST_LOG_LEVEL`.

Внутренние диапазоны — только явно заданные администратором. Адреса метаданных (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) блокируются всегда. DNS-имя в scope не даёт разрешения на сканирование всех портов его IP.

## 8. Чистый хост

Минимальный сценарий:

1. Установить Docker/Compose.
2. Войти в GHCR и указать digest в `.env.v2`.
3. Выполнить `pull` и создать администратора.
4. Выполнить `up -d --no-build --pull never`.
5. Выполнить одну задачу на локальном стенде.
6. Перезапустить оба контейнера и убедиться, что история и отчёт сохранились.
7. Проверить отсутствие компиляторов и скачивания шаблонов при первом старте.

Автоматический вариант — `./scripts/v2-e2e.sh` с `LASTEST_IMAGE` по digest. Скрипт создаёт собственную сеть, том и контейнеры и удаляет только их.

## 9. Локальная сборка для разработки

```bash
docker build -f Dockerfile.v2 -t lastest-v2:local .
```

Для этого режима задайте `LASTEST_IMAGE=lastest-v2:local` и запускайте Compose с `--pull never`.
