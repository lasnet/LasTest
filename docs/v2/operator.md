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
- **Scans**: выбор типа задачи, JSON-параметры, идемпотентный ключ, запуск, история, отмена, ссылки на доказательства. Недоступный Nmap/провайдер отображается причиной и не блокирует остальные задачи.
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
| `subdomains.discover` | домены из scope/явно | host-наблюдения, wildcard, страницы и квоты Cert Spotter |
| `dns.records` | цели + типы A/AAAA/CNAME/MX/NS/TXT/PTR | DNS-наблюдения, IP-связи, артефакт |
| `dns.wordlist` | домен + слова | найденные хосты, wildcard-диагностика |
| `reverse.ip` | явные IP | PTR, отдельно Shodan InternetDB/Censys |
| `http.probe` | roots или URL | проверенный IP, URL, status, title, server, TLS, технологии |
| `urls.passive` | домены | Wayback CDX и Common Crawl URL с источником |
| `http.crawl` | seeds | ограниченный HTML-обход, внешние ссылки как denied |
| `paths.discover` | base URLs + слова | найденные пути, soft-404 отдельно |
| `tcp.connect` | явные IP + порты, optional SOCKS5 | подтверждённые, кандидаты (timeout/error), закрытые |
| `nmap.profile` | явные IP + порты | фиксированный unprivileged `-sT -sV`, XML, службы |
| `web.checks` | HTTPS targets | HSTS, срок сертификата, Secure cookie |

Ограничения контура: нет полного языка/каталога шаблонов Nuclei, браузерного JS-обхода, расписаний, OSINT/phishing-заглушек, сырых пакетов Nmap, OS detection и NSE. Импорт исторических Nuclei findings поддерживается.

## Частичные ошибки и отмена

- Ошибка одного источника/цели не стирает остальные результаты; задача становится `partial`, counters и `errors` показывают причину.
- `timeout` TCP — кандидат, а не «закрытый порт».
- SOCKS5 получает проверенный IP (не имя). Для подтверждения кандидата/timeout через прокси повторите запуск `tcp.connect`; одна свежая аутентифицированная TCP-сессия создаётся на каждый порт, результат содержит `socks5_confirmation`.
- Отмена ожидающей задачи удаляет её из очереди; активная задача получает флаг отмены, worker прекращает новые запросы при первой возможности и не публикует результаты после потери lease.
- После аварийного завершения активная задача помечается `interrupted`; для активных проверок требуется явный новый запуск.
