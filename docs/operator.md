# Работа оператора

## Основной сценарий

1. Войти в web или CLI.
2. Выбрать проект. После входа проект не выбирается автоматически; без выбора dashboard показывает только приглашение выбрать проект.
3. Проверить и утвердить scope. До утверждения запуск задач запрещён.
4. Запустить отдельную задачу или цепочку `All in one`.
5. Следить за counters, статусом и частичными ошибками источников.
6. Открыть dashboard/активы/находки, выгрузить JSON или CSV.
7. При необходимости отменить задачу.

## Web UI

Разделы: Dashboard, Scope, Scans, Assets, Findings, Reports, Users, Logout. Левое меню остаётся постоянным, рабочая область переключается hash-routes. Все поля из внешних артефактов выводятся как текст, без HTML-инъекций.

- **Scope**: список правил, добавление/удаление, сохранение черновика, сохранение с утверждением, утверждение текущей ревизии. Исключения визуально отмечены и имеют приоритет.
- **Scans**: карточки Recon и Vulnerability Analysis, выбор нескольких техник, информация и настройки для каждой, запуск реализованных задач, история, отмена и артефакты. Состав и план инструментов находятся в [scan-modules.md](scan-modules.md).
- **Dashboard**: реальные метрики из SQLite; отдельно пустой результат, частичный прогон и ошибки источников. HTTP, порты, покрытие web-проверок.
- **Assets**: домены, IP, URL с временем первого/последнего наблюдения.
- **Findings**: severity, правило/версия, asset, доказательство, время.
- **Reports**: JSON/CSV по текущему снимку.
- **Users**: только admin; создание, роль, активность, аудит.

Клавиатурная доступность: поля связаны с `label`, навигация и действия — обычные ссылки/кнопки, видимый focus, нет обязательных drag-and-drop или hover-only действий. Проверка в браузере: пройти login → создание/выбор проекта → scope → задачу → dashboard → отчёт только с клавиатуры (Tab/Shift+Tab/Enter/Space/Escape для закрытия подсказок браузера).

TLS в рабочем варианте: trusted reverse proxy, HTTPS URL, `LASTEST_SECURE_COOKIES=true`. Проверить cookie `Secure`/`HttpOnly`/`SameSite`.

## CLI

CLI обращается к тому же API. Сессия хранится в `<data_dir>/cli-session.json` с правами `0600`; при более широких правах команда откажется работать. Пароль вводится через stdin (`--password-stdin`) или файл `chmod 600` (`--password-file`). Вывод — машиночитаемый JSON. Коды выхода: `0` успех, `2` ошибка аргументов, `3` нет/истекла авторизация, `4` ошибка API/сети, `5` не найдено, `1` прочее.

```bash
lastest --data-dir /data auth login --username admin --password-stdin --api-url https://lastest.example.internal
lastest --data-dir /data project list
lastest --data-dir /data project create --name client-a --client ACME
lastest --data-dir /data scope show --project client-a
cat >rules.json <<'JSON'
[{"kind":"subdomain_tree","value":"example.com","exclusion":false}]
JSON
lastest --data-dir /data scope update --project client-a --rules-file rules.json --expected-version 1 --approve
lastest --data-dir /data job submit --project client-a --task-type http.probe \
  --params '{"targets":["https://www.example.com"],"mode":"url"}' --idempotency-key http-1
lastest --data-dir /data job status --id job_...
lastest --data-dir /data job cancel --id job_...
lastest --data-dir /data report export --project client-a --format json --output report.json
lastest --data-dir /data task-types
lastest --data-dir /data auth logout
```

Локальные команды с доступом к каталогу данных:

```bash
lastest --data-dir /data admin setup-code
lastest --data-dir /data admin bootstrap --username admin --password-stdin
lastest --data-dir /data doctor
lastest --data-dir /data import legacy --projects-dir ./legacy/projects --database ./legacy/lastest.sqlite --dry-run
lastest --data-dir /data import legacy --projects-dir ./legacy/projects --database ./legacy/lastest.sqlite --apply
lastest --data-dir /data backup --output ./backup-2026-11-15
lastest --data-dir /data restore --from ./backup-2026-11-15 --force
```

## Типы задач и ограничения

| Задача | Вход | Что сохраняется |
| --- | --- | --- |
| `subdomains.discover` | домены из scope/явно | подтверждённые A/AAAA имена и IP; wildcard, rejected, страницы и квоты в артефакте |
| `subdomains.subfinder` | домены из scope/явно, источники; A/AAAA всегда | подтверждённые host, DNS/IP-наблюдения, subdomains artifact |
| `dns.records` | цели + типы A/AAAA/CNAME/MX/NS/TXT/PTR | DNS-наблюдения, IP-связи, артефакт |
| `dns.wordlist` | домен, wordlist=default, concurrency=4/8/16 (default 8); words через API | найденные хосты, wildcard-диагностика |
| `reverse.ip` | явные IP; `sources` = ptr/shodan_internetdb/censys или legacy `providers` | кандидаты с происхождением, PTR, отдельно Shodan InternetDB/Censys, проверка A/AAAA |
| `assets.enrich` | project-local candidate_ids/asset_ids или committed-вход цепочки; `http_enrichment` (default false) | снимок enrichment: DNS, HTTP, порты (confirmed/passive), сеть, технологии |
| `assets.classify` | project-local кандидаты/активы или committed-вход цепочки | группы технологий, категории, surface hints, confidence/interest и evidence |
| `http.probe` | roots или URL | проверенный IP, URL, status, title, server, TLS, технологии |
| `urls.passive` | домены | Wayback CDX и Common Crawl URL с источником |
| `http.crawl` | seeds | ограниченный HTML-обход, внешние ссылки как denied |
| `paths.discover` | base URLs + слова | найденные пути, soft-404 отдельно |
| `tcp.connect` | явные IP + порты, optional SOCKS5 | подтверждённые, кандидаты (timeout/error), закрытые |
| `nmap.profile` | явные IP + порты | фиксированный unprivileged `-sT -sV`, XML, службы |
| `web.checks` | HTTPS targets | HSTS, срок сертификата, Secure cookie |

## Asset Discovery

1. Создайте Project, заполните и утвердите Scope. При наличии DNS name сначала наполните Assets через Subdomain Enumeration; в IP/Network-проекте подтвердите импорт IP в Assets. Слишком большие сети отклоняются до импорта. См. [модель работы](product-workflow.md).
2. На странице Scans откройте Settings (шестерёнку) Asset Discovery, выберите источники (PTR, Shodan InternetDB, Censys) и при необходимости включите **Active HTTP enrichment**. Все настройки находятся в диалоге, карточка только выбирает модуль.
3. Выберите Asset Discovery и нажмите общую кнопку **Start scanning**: создаётся одна цепочка `reverse.ip` → `assets.enrich` → `assets.classify`; три независимых параллельных задания не ставятся.
4. В Assets кнопка Details открывает панель справа с найденными DNS/HTTP, технологиями, портами, сетью и классификацией; повторный запуск обновляет существующий актив. Для внешних имён откройте Discovery candidates: фильтры по источнику, DNS-статусу, совпадению IP, текущему Scope, confidence и interest. Карточка показывает историю свидетельств, причину `not_permitted`/`no_addresses` и сохранённый enrichment.
5. **Add to Scope** только переносит имя в редактор Scope. Сохранение и утверждение остаются явным действием с проверкой версии; клик не запускает задачи и не утверждает Scope.

Интеграции Censys принадлежат всей установке. `censys_pat` (env `LASTEST_CENSYS_PAT`) включает Platform v3; без PAT полная пара `censys_api_id`/`censys_api_secret` использует legacy v2. Неполная пара — ошибка конфигурации интеграции. Ключи не принимаются в параметрах задач, проектах, цепочках и не возвращаются API. Изменения конфигурации применяются перезапуском API и worker; hot reload не поддерживается. Открытие каталога, Assets или отчёта не выполняет сетевых запросов.

Ограничения контура: нет полного языка/каталога шаблонов Nuclei, браузерного JS-обхода, расписаний, OSINT/phishing-заглушек, сырых пакетов Nmap, OS detection и NSE. Импорт исторических Nuclei findings поддерживается.

## Частичные ошибки и отмена

- Ошибка одного источника/цели не стирает остальные результаты; задача становится `partial`, counters и `errors` показывают причину.
- `timeout` TCP — кандидат, а не «закрытый порт».
- SOCKS5 получает проверенный IP (не имя). Для подтверждения кандидата/timeout через прокси повторите запуск `tcp.connect`; одна свежая аутентифицированная TCP-сессия создаётся на каждый порт, результат содержит `socks5_confirmation`.
- Отмена ожидающей задачи удаляет её из очереди; активная задача получает флаг отмены, worker прекращает новые запросы при первой возможности и не публикует результаты после потери lease.
- После аварийного завершения активная задача помечается `interrupted`; для активных проверок требуется явный новый запуск.
