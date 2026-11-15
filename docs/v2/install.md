# Установка LasTest 2.0

Контур 2.0 поставляется одним OCI-образом. API и worker запускаются двумя непривилегированными процессами из одного digest и используют общий локальный том `/data`.

## 1. Получить digest

Тег образа изменяем. Для установки нужен digest из CI или реестра:

```bash
docker buildx imagetools inspect ghcr.io/OWNER/lastest:2.0.0 --format '{{json .Manifest.Digest}}'
# или после pull:
docker image inspect ghcr.io/OWNER/lastest:2.0.0 --format '{{index .RepoDigests 0}}'
```

Результат должен иметь вид `ghcr.io/OWNER/lastest@sha256:...`.

## 2. Подготовить Compose

```bash
cp .env.v2.example .env.v2
# LASTEST_IMAGE=ghcr.io/OWNER/lastest@sha256:...
# LASTEST_SECURE_COOKIES=true (TLS через reverse proxy)
# LASTEST_INTERNAL_RANGES= только для явно разрешённых внутренних стендов
docker compose --env-file .env.v2 -f compose.v2.yaml config -q
```

`compose.v2.yaml` не содержит `build:`, плавающих тегов и ссылок на исходники хоста. API публикуется только на `127.0.0.1`. Том `lastest-v2-data` хранит SQLite и доказательства.

## 3. Первый администратор

Пароль передаётся только через stdin или защищённый файл (`chmod 600`). Пароль короче 12 символов отклоняется.

```bash
docker run --rm -i -v lastest-v2-data:/data \
  ghcr.io/OWNER/lastest@sha256:... \
  admin bootstrap --username admin --password-stdin
```

Для локального запуска без Compose:

```bash
lastest --data-dir ./lastest-data admin bootstrap --username admin --password-stdin
```

## 4. Запуск и диагностика

```bash
docker compose --env-file .env.v2 -f compose.v2.yaml pull
docker compose --env-file .env.v2 -f compose.v2.yaml up -d --no-build
docker compose --env-file .env.v2 -f compose.v2.yaml ps
curl -fsS http://127.0.0.1:8080/api/v2/health/ready
```

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
2. Получить digest.
3. `pull` и `up -d --no-build`.
4. Создать администратора.
5. Выполнить одну задачу на локальном стенде.
6. Перезапустить оба контейнера и убедиться, что история и отчёт сохранились.
7. Проверить отсутствие компиляторов и скачивания шаблонов при первом старте.

Автоматический вариант — `./scripts/v2-e2e.sh` с `LASTEST_IMAGE` по digest. Скрипт создаёт собственную сеть, том и контейнеры и удаляет только их.
