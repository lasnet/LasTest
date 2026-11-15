# Проверки и замеры LasTest 2.0

Команды выполняются из корня проекта.

## Обязательные команды

| Команда | Ожидаемый результат |
| --- | --- |
| `cargo fmt --all -- --check` | код отформатирован, вывода нет |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | нет предупреждений |
| `cargo test --locked --all-targets --all-features` | все unit/integration тесты зелёные |
| `cargo build --locked --release` | `target/release/lastest`, без Go |
| `./scripts/v2-e2e.sh` | изолированный image-сценарий, readiness, задача, отчёт, рестарт, отсутствие Go/Python/компиляторов |
| `docker compose -f compose.v2.yaml config -q` | конфигурация валидна; нужен `LASTEST_IMAGE` |
| `docker compose -f compose.v2.yaml pull` | образ по digest скачан |
| `docker compose -f compose.v2.yaml up -d --no-build` | API/worker без сборки |
| `docker compose -f compose.v2.yaml ps` | оба сервиса запущены |
| `git diff --check` | нет whitespace errors |

`LASTEST_IMAGE` должен содержать `@sha256:`. Compose-команды используют тестовую конфигурацию и локальный порт; `scripts/v2-e2e.sh` создаёт собственную сеть/том и удаляет только их.

## Покрытие тестов

| Область | Файл / тесты |
| --- | --- |
| Scope, URL, IDNA, IPv6/CIDR, исключения, metadata, redirect, scope narrowing, отсутствие запроса вне scope | `tests/v2_scope_network.rs`, unit tests `src/scope` |
| Auth, cookie/Bearer, истечение/отзыв, CSRF, роли, last admin, аудит | `tests/v2_auth_api.rs` |
| Очередь, два worker, отмена, lease, stale attempt, идемпотентность, partial, лимит артефакта, цепочка, публикация файлов | `tests/v2_queue_files.rs` |
| Локальный DNS, wildcard, HTTP/crawler, soft 404, archive sources, reverse IP provider, SOCKS5, Nmap XML, web rules | `tests/v2_modules.rs`, unit tests `src/tasks/web_checks.rs` |
| Импорт, dry-run=apply, конфликт имён, symlink, идемпотентность, архивные jobs, pending scope, backup | `tests/v2_import.rs` |
| CLI/UI API и persistence | `tests/v2_e2e_cli.rs` |

Тест `tests/v2_e2e_cli.rs` запускает реальные процессы `serve`/`worker`, создаёт проект, утверждает scope, выполняет HTTP-probe, экспортирует JSON/CSV, перезапускает API и проверяет сохранение истории. HTML/JS проверяются на наличие реального login и API-вызовов; браузерная клавиатурная проверка вынесена в ручной чек-лист (см. ниже).

## Фактические замеры

Среда: macOS Darwin x86_64, Intel Core i7-9750H (2.60 GHz), 16 GiB RAM, Rust 1.100.0, release build, локальный стенд `127.0.0.1`, один worker, `max_concurrent_jobs=1`.

На этапе перехода прошли `cargo fmt --check`, `cargo clippy ... -D warnings`, `cargo test --locked --all-targets --all-features`, `cargo build --locked --release`, проверка конфигурации Compose и `git diff --check`.

| Показатель | Значение | Условия |
| --- | --- | --- |
| Размер binary | 10.7 MiB (11 215 664 байта) | `target/release/lastest`, `strip`, LTO thin |
| Время до readiness | 0.215 s | пустая БД, `curl /health/ready` |
| Память API в простое | ~5.7 MiB RSS | после readiness, без запросов |
| Память worker в простое | ~4.9 MiB RSS | очередь пуста |
| Суммарная память | ~10.6 MiB RSS | API + worker |
| DNS `dns.records` | 500 хостов / 1.58 s ≈ 317 хостов/с | локальный UDP DNS, только A, один worker, динамическая проверка scope |
| HTTP `http.probe` | 500 URL / 2.64 s ≈ 189 запросов/с | локальный HTTP-сервер, один worker, динамическая проверка scope на каждый запрос |

Ориентиры архитектуры — до 100 MiB сжатого образа и до 120 MiB памяти в простое. При отдельной проверке на Linux `amd64` образ собрался, Compose запустил API и worker по digest с `--no-build`. Размер сжатых слоёв и конфигурации в тестовом реестре составил 37 027 309 байт (35,3 MiB). Сквозной тест прошёл все девять шагов после исправления передачи stdin, имени API в сети Docker и записи правил scope в `/tmp`. Для повторной проверки можно использовать следующие команды.

```bash
docker build -f Dockerfile.v2 -t lastest-v2:local .
docker image inspect lastest-v2:local --format '{{.Size}}'
docker save lastest-v2:local | gzip -9 | wc -c
```

Сравнение с 1.x на тех же фикстурах не выполнено: работоспособная база 1.x с Kali/Go-инструментами в этой среде отсутствовала. Ускорение не заявляется; сетевые задачи ограничены сетью/квотами провайдеров.

## Ручной чек-лист UI

1. Открыть `/` и убедиться, что видна только форма входа. Войти под `admin` и проверить, что форма исчезла, а панель появилась сразу в видимой области. Обновить страницу и убедиться, что с действующей сессией сразу открывается панель.
2. Убедиться, что проект не выбран и dashboard не показывает mock-метрики.
3. Создать проект, добавить и утвердить scope.
4. Запустить `http.probe` на локальном стенде, увидеть partial/empty состояния.
5. Проверить Assets/Findings/Reports; скачать JSON и CSV.
6. Пройти все действия только клавиатурой (Tab/Shift+Tab/Enter/Space), проверить видимый focus.
7. Войти viewer: действия изменения скрыты/запрещены, Users недоступны.
8. Войти через HTTPS reverse proxy: cookie содержит `Secure`, `HttpOnly`, `SameSite=Strict`; запрос с чужим `Origin` отклонён.

## Открытые пункты

- Пик расхода диска при скачивании и запуске образа ещё предстоит измерить.
- CI содержит сборку amd64 и подготовительную сборку arm64 (`docker buildx --platform linux/arm64`); runtime-проверка arm64 требует отдельного arm64-хоста и не заявляется как выполненная.
- Локальная проверка в Chromium прошла вход, создание проекта, утверждение scope, HTTP-задачу, экспорт JSON/CSV, роль `viewer` и вход через тестовый HTTPS-прокси. Постоянного браузерного теста в CI пока нет. Ручной чек-лист приведён выше.
- Полный язык шаблонов Nuclei, браузерный JS-обход, планировщик, OSINT/phishing, raw-packet/OS/NSE Nmap исключены из релиза и перечислены в API/UI каталоге.
