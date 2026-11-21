# Проверки и замеры LasTest

Команды выполняются из корня проекта.

## Обязательные команды

| Команда | Ожидаемый результат |
| --- | --- |
| `cargo fmt --all -- --check` | код отформатирован, вывода нет |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | нет предупреждений |
| `cargo test --locked --all-targets --all-features` | все unit/integration тесты зелёные |
| `cargo build --locked --release` | `target/release/lastest`, без Go |
| `./scripts/e2e.sh` | первый администратор, readiness, задача, отчёт, рестарт, отсутствие Go/Python/компиляторов |
| `docker compose config -q` | валидная конфигурация с настройками по умолчанию |
| `docker compose pull` | образ по digest скачан |
| `docker compose up -d --no-build` | API/worker без сборки |
| `docker compose ps` | оба сервиса запущены |
| `git diff --check` | нет whitespace errors |

Перед запуском `scripts/e2e.sh` передайте образ по digest в `LASTEST_IMAGE`. Скрипт создаёт собственные контейнеры, сеть и том. Для независимой проверки Compose используйте отдельный локальный порт и тестовый том.

## Покрытие тестов

| Область | Файл / тесты |
| --- | --- |
| Scope, URL, IDNA, IPv6/CIDR, исключения, metadata, redirect, scope narrowing, отсутствие запроса вне scope | `tests/scope_network.rs`, unit tests `src/scope` |
| Первый администратор, истечение и перевыпуск кода, миграция базы, cookie/Bearer, CSRF, роли и аудит | `tests/auth_api.rs` |
| Очередь, два worker, 1/4 параллельных слота и их пополнение, изоляция ошибок/отмены, остановка процессов, lease, stale attempt, идемпотентность, partial, лимит артефакта, порядок цепочки, публикация файлов | `tests/queue_files.rs`, `tests/worker_parallel.rs` |
| Локальный DNS (NODATA/NXDOMAIN/SERVFAIL/REFUSED/IPv6), wildcard, CT after-пагинация и сохранение частичных результатов, обязательная A/AAAA-проверка всех четырёх задач через worker/Assets API/JSON-артефакт, HTTP/crawler, soft 404, archive sources, reverse IP provider, SOCKS5, Nmap XML, web rules | `tests/modules.rs`, unit tests `src/tasks/web_checks.rs` |
| Импорт, dry-run=apply, конфликт имён, symlink, идемпотентность, архивные jobs, pending scope, backup | `tests/import.rs` |
| Asset Discovery: адаптеры Shodan/Censys v3/legacy, границы имён, публикация кандидата и Asset только после разрешённой A/AAAA, неподтверждённые имена, классификация, общий кэш/лимитер/cooldown, цепочка с собственными committed-входами, пустой вход не классифицирует историю | `tests/asset_discovery.rs`, `tests/provider_cache.rs`, `tests/asset_discovery_chain.rs` |
| CLI/UI API и persistence | `tests/e2e_cli.rs` |

Тест `tests/e2e_cli.rs` запускает реальные процессы `serve`/`worker`, создаёт проект, утверждает scope, выполняет HTTP-probe, экспортирует JSON/CSV, перезапускает API и проверяет сохранение истории. HTML/JS проверяются на наличие реального login и API-вызовов; браузерная клавиатурная проверка вынесена в ручной чек-лист (см. ниже).

## Фактические замеры

Среда: macOS Darwin x86_64, Intel Core i7-9750H (2.60 GHz), 16 GiB RAM, Rust 1.100.0, release build, локальный стенд `127.0.0.1`, один worker, `max_concurrent_jobs=1`.

На этапе перехода прошли `cargo fmt --check`, `cargo clippy ... -D warnings`, `cargo test --locked --all-targets --all-features`, `cargo build --locked --release`, проверка конфигурации Compose и `git diff --check`.

| Показатель | Значение | Условия |
| --- | --- | --- |
| Размер binary | 10.7 MiB (11 215 664 байта) | `target/release/lastest`, `strip`, LTO thin |
| Время до readiness | 0.215 s | пустая БД, запрос readiness |
| Память API в простое | ~5.7 MiB RSS | после readiness, без запросов |
| Память worker в простое | ~4.9 MiB RSS | очередь пуста |
| Суммарная память | ~10.6 MiB RSS | API + worker |
| DNS `dns.records` | 500 хостов / 1.58 s ≈ 317 хостов/с | локальный UDP DNS, только A, один worker, динамическая проверка scope |
| HTTP `http.probe` | 500 URL / 2.64 s ≈ 189 запросов/с | локальный HTTP-сервер, один worker, динамическая проверка scope на каждый запрос |

Ориентиры архитектуры — до 100 MiB сжатого образа и до 120 MiB памяти в простое. При отдельной проверке на Linux `amd64` образ собрался, Compose запустил API и worker по digest с `--no-build`. Размер сжатых слоёв и конфигурации в тестовом реестре составил 37 027 309 байт (35,3 MiB). Сквозной тест прошёл все девять шагов после исправления передачи stdin, имени API в сети Docker и записи правил scope в `/tmp`. Для повторной проверки можно использовать следующие команды.

```bash
docker build -t lastest:local .
docker image inspect lastest:local --format '{{.Size}}'
docker save lastest:local | gzip -9 | wc -c
```

Сравнение с 1.x на тех же фикстурах не выполнено: работоспособная база 1.x с Kali/Go-инструментами в этой среде отсутствовала. Ускорение не заявляется; сетевые задачи ограничены сетью/квотами провайдеров.

## Ручной чек-лист UI

1. На пустом томе открыть `/`, получить код командой `docker compose exec api lastest admin setup-code` и создать администратора через форму. Войти и проверить, что панель появилась сразу в видимой области. Обновить страницу и убедиться, что с действующей сессией сразу открывается панель.
2. Убедиться, что проект не выбран и dashboard не показывает mock-метрики.
3. Создать проект, добавить и утвердить scope.
4. Запустить `http.probe` на локальном стенде, увидеть partial/empty состояния.
5. В Scans выбрать Asset Discovery, настроить источники, проверить read-only состояние Censys без поля ключа, включить/выключить активный HTTP и выбрать карточку и нажать общую кнопку Start scanning. Убедиться, что создаётся одна цепочка из трёх стадий, а не три параллельных задания.
6. В Assets проверить фильтры кандидатов (источник, DNS, совпадение IP, текущий Scope, confidence, interest), различие `not_permitted` и `no_addresses`, карточку кандидата, карточку актива и «Add to Scope» без потери несохранённых правок и без автоматического утверждения Scope.
7. Проверить Assets/Findings/Reports; скачать JSON, CSV и отдельные `discovery-json`/`discovery-csv`.
6. Пройти все действия только клавиатурой (Tab/Shift+Tab/Enter/Space), проверить видимый focus.
7. Войти viewer: действия изменения скрыты/запрещены, Users недоступны.
8. Войти через HTTPS reverse proxy: cookie содержит `Secure`, `HttpOnly`, `SameSite=Strict`; запрос с чужим `Origin` отклонён.

## Открытые пункты

- Пик расхода диска при скачивании и запуске образа ещё предстоит измерить.
- CI содержит сборку amd64 и подготовительную сборку arm64 (`docker buildx --platform linux/arm64`); runtime-проверка arm64 требует отдельного arm64-хоста и не заявляется как выполненная.
- Локальная проверка в Chromium прошла вход, создание проекта, утверждение scope, HTTP-задачу, экспорт JSON/CSV, роль `viewer` и вход через тестовый HTTPS-прокси. Постоянного браузерного теста в CI пока нет. Ручной чек-лист приведён выше.
- Полный язык шаблонов Nuclei, браузерный JS-обход, планировщик, OSINT/phishing, raw-packet/OS/NSE Nmap исключены из релиза и перечислены в API/UI каталоге.

## Asset Discovery review checks

`tests/discovery_regressions.rs` covers stored HTTP attribution, explicit target
selection, immutable candidate inputs between overlapping runs, technology evidence
roundtrips, exact-domain DNS discovery, credential rotation, subsecond shared rate
limits, scope narrowing during retry backoff, default chain sources/idempotency, and
matching list/export filters across the complete candidate inventory.

For browser acceptance, use an isolated local provider/DNS/HTTP fixture and separate
data directory. Check the sequential Discovery launch, source checkboxes with missing
Censys disabled, HTTP toggle, both candidate states, saved HTTP 403 details, filters,
export, switching projects, and Add to Scope followed by cancelling the unsaved change.
Check keyboard focus, light/dark themes and a 390px viewport without page overflow.

Проверка Asset Discovery выполнена 21 ноября 2026 на отдельном локальном стенде:
вход администратора и Viewer, PTR/Shodan/Censys source controls, оба варианта запуска
Discovery, последовательные стадии, кандидаты allowed/denied, фильтрованный JSON-экспорт,
карточка с сохранённым HTTP 403 и технологическими evidence, явный HTTP-переключатель,
обогащение локального HTTP-сервиса, смена проекта и перенос имени в несохранённый Scope.
Проверены Enter/Escape, тёмная тема и viewport 390px (scrollWidth не превышает innerWidth).
Ошибок в консоли браузера не обнаружено. Использованы только фиктивные учётные данные,
локальные DNS/HTTP/API-провайдеры и отдельная временная БД; платных запросов не было.

## Project → Assets workflow checks (22 ноября 2026)

`tests/asset_workflow.rs` проверяет подготовку пустого проекта, обязательный DNS enumeration,
атомарный импорт IP/Network (исключения, лимиты IPv4/IPv6, версия Scope, повтор без дубликатов,
политика сети, роль и CSRF), изоляцию ID и URL выбранных Assets, запрет клиентских служебных
разрешений, повторную A/AAAA-проверку перед TCP и отзыв допуска при сужении Scope.
Отдельные сквозные worker-сценарии подтверждают Discovery для IP-only и для дочернего DNS Asset
под exact_domain без отдельных IP-правил в Scope; исходный Asset обогащается/классифицируется,
даже если reverse-IP не нашёл кандидатов. Старые API и импорт 1.x остаются в общем наборе тестов.

В браузере на отдельном локальном стенде проверены все три подсказки подготовки Assets,
подтверждённый импорт Network, последовательный запуск Discovery из Assets, перенос настроек
под шестерёнку, выбор хостов (поиск, выбрать все, снять выбор, Save/Cancel), сохранение выбора
после перезагрузки, запрет выбора HTTP-хоста без URL, успешная проверка ровно одного сохранённого
URL, наборы портов и правая панель IP/хоста. На 1440/768/390px нет горизонтального переполнения;
проверены светлая и тёмная темы, консоль без ошибок. Фикстуры и БД хранятся вне репозитория.

## Job history: завершение и ошибки проверок (22 ноября 2026)

На локальном DNS/HTTP-стенде проверены отсутствие PTR (NXDOMAIN и NODATA) без Errors,
настоящий SERVFAIL с диагностикой, PTR miss вместе с Shodan 200/404 и сохранение причин
неудачного HTTP-обогащения в summary-артефакте. IP-only Discovery без PTR завершается succeeded.

На отдельной временной БД браузер проверяет `partial` и `succeeded` как Completed,
ненулевые красные Errors, нормальный цвет нулевого счётчика, отдельный Failed и свёрнутые
Error details/Failure details. Раскрытие через клавиатуру и сохранение раскрытия после Refresh
подтверждены. Внутри деталей HTTP доступны URL и причина ошибки. Проверены светлая/тёмная темы
и ширина 390px без горизонтального переполнения; ошибок консоли нет. Технические статусы
API/очереди, правила цепочек и существующие исторические счётчики не переписываются.
