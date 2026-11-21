# API LasTest

Базовый путь: `/api`. Web UI и CLI используют одни и те же маршруты, проверку ролей и scope. Старый HTTP API и JWT 1.x не поддерживаются этим API.

## Аутентификация

| Способ | Использование | Хранение |
| --- | --- | --- |
| Cookie `lastest_session` | Web | `HttpOnly`, `SameSite=Strict`, `Secure` при `secure_cookies=true`; сервер хранит SHA-256 хэш токена |
| Bearer | CLI | отдельная сессия после `POST /auth/login` с `"client":"cli"`; отзывается logout |

Пароли: Argon2id. Сессии имеют срок жизни, отзываются при logout и смене пароля/деактивации. Пять неудачных входов блокируют username на настроенный интервал. Ответ на неверного пользователя и неверный пароль одинаковый.

Изменяющие браузерные запросы требуют совпадающий `Origin` (или `Referer`) и `Host`; иначе `403` с кодом `csrf_failed`.

### Первый администратор

- `GET /auth/setup` возвращает `{"required": true}` для базы без пользователей.
- `POST /auth/setup` принимает `code`, `username` и `password`. Возвращает `201` и объект `user`. После создания пользователя используйте обычный `POST /auth/login`.
- Код выдаётся локальной командой `lastest admin setup-code` на хосте приложения. В SQLite хранится хэш кода. Код истекает через 15 минут, повторная выдача заменяет предыдущий, а успешная настройка погашает код.
- Неверный или истёкший код даёт `403 invalid_setup_code`. Если пользователи уже есть, настройка закрыта и возвращает `409 setup_closed`.

Роли:

- `viewer` — чтение проектов, истории, dashboard, доказательств и отчётов;
- `analyst` — дополнительно создание проектов, правка scope, запуск/отмена задач и цепочек;
- `admin` — дополнительно пользователи и аудит.

Последний активный администратор не может быть выключен или понижен (`409 last_admin`).

## Формат ошибок

```json
{"error":{"code":"invalid_target","message":"host outside.example is outside the approved scope"}}
```

Стабильные коды: `unauthenticated`, `invalid_credentials`, `forbidden`, `csrf_failed`, `not_found`, `invalid_request`, `invalid_params`, `invalid_target`, `invalid_scope`, `scope_version_conflict`, `scope_not_approved`, `idempotency_conflict`, `last_admin`, `user_exists`, `unavailable`, `internal_error`.

## Маршруты

| Метод и путь | Роль | Назначение |
| --- | --- | --- |
| `GET /health/live` | без auth | процесс жив |
| `GET /health/ready` | без auth | SQLite, схема, запись в data dir; состояние worker отдельным полем |
| `POST /auth/login` | без auth | cookie или CLI token |
| `POST /auth/logout` | auth | отзыв текущей сессии |
| `GET /auth/me` | auth | пользователь и роль |
| `GET /task-types` | viewer | типизированный каталог, доступность, лимиты, web-правила, исключения |
| `GET /providers` | viewer | read-only интеграции: `configured`, `requires_key`, реальный режим Censys, причина; без ключей |
| `GET /projects` | viewer | пагинация проектов |
| `POST /projects` | analyst | создать проект и черновик scope |
| `GET /projects/{id}` | viewer | проект, текущий scope, история ревизий |
| `GET /projects/{id}/scope?version=` | viewer | текущая или историческая ревизия |
| `PUT /projects/{id}/scope` | analyst | новая ревизия scope |
| `POST /projects/{id}/scope/{version}/approve` | analyst | утвердить ревизию |
| `GET /projects/{id}/jobs` | viewer | история, фильтр `status`, пагинация |
| `POST /projects/{id}/jobs` | analyst | `202` + ID задачи |
| `GET /jobs/{id}` | viewer | состояние, counters, ошибки, артефакты |
| `POST /jobs/{id}/cancel` | analyst | отмена ожидающей/активной задачи |
| `GET /projects/{id}/chains` | viewer | цепочки |
| `POST /projects/{id}/chains` | analyst | `202`, преднастроенная цепочка |
| `GET /chains/{id}` | viewer | стадии, пропуски и причины |
| `POST /chains/{id}/cancel` | analyst | отмена незавершённых стадий |
| `GET /projects/{id}/dashboard` | viewer | метрики, источники, покрытие правил |
| `GET /projects/{id}/assets?q=&offset=&technology=&provider=&category=` | viewer | общая таблица хостов и IP, поиск, фильтры, страницы по 10 строк |
| `GET /projects/{id}/assets/{asset_id}` | viewer | карточка из сохранённых данных: DNS, HTTP, порты, сеть, candidate, enrichment, classification |
| `GET /projects/{id}/assets/export/{txt|csv}?q=&technology=&provider=&category=` | viewer | все строки таблицы с учётом поиска и фильтров |
| `DELETE /projects/{id}/assets/{asset_id}` | analyst | удаление хоста или отдельного IP с аудитом |
| `GET /projects/{id}/discovery/candidates?q=&source=&dns_status=&ip_match=&scope_status=&confidence=&interest=&limit=&offset=` | viewer | кандидаты проекта с пересчитанным по текущему Scope статусом |
| `GET /projects/{id}/discovery/candidates/{candidate_id}` | viewer | происхождение, проверки, enrichment и classification кандидата |
| `GET /projects/{id}/discovery/export/{json|csv}` | viewer | отдельный расширенный экспорт кандидатов |
| `GET /evidence/{artifact_id}` | viewer | опубликованное доказательство |
| `GET /projects/{id}/reports/{json|csv|discovery-json|discovery-csv}` | viewer | снимок отчёта; discovery-* — аддитивный расширенный вариант |
| `GET/POST /users`, `PATCH /users/{id}`, `GET /audit` | admin | пользователи и аудит |

`{id}` проекта принимает стабильный ID или имя проекта для удобства CLI; ответы всегда содержат стабильный ID.

## Пагинация и фильтры

`limit` (1..500, по умолчанию 100) и `offset`. Ответ:

```json
{"items":[],"total":0,"limit":100,"offset":0}
```

Для `/projects/{id}/jobs` доступен `status=queued|running|succeeded|partial|failed|cancelled|interrupted`.

## Создание проекта

```http
POST /api/projects
Content-Type: application/json
Origin: https://lastest.example.internal

{"name":"client-a","client":"ACME","description":"approved assessment"}
```

`201`:

```json
{"project":{"id":"prj_...","name":"client-a","client":"ACME","description":"approved assessment"},
 "scope":{"id":"scr_...","version":1,"status":"draft","rules":[]},
 "next":"edit and approve scope before submitting jobs"}
```

## Scope

```http
PUT /api/projects/prj_.../scope
Content-Type: application/json
Origin: https://lastest.example.internal

{"rules":[
  {"kind":"subdomain_tree","value":"example.com","exclusion":false},
  {"kind":"exact_domain","value":"admin.example.com","exclusion":true},
  {"kind":"cidr","value":"203.0.113.0/24","exclusion":false}
],"expected_version":1,"note":"approved by ticket SEC-1","approve":true}
```

`kind`: `exact_domain`, `subdomain_tree`, `ip`, `cidr`. Имена нормализуются через IDNA; IPv4-mapped IPv6 приводится к IPv4; CIDR канонизируется. Исключение имеет приоритет. Правка создаёт новую версию; предыдущие читаются через `?version=`.

Несовпадение `expected_version` — `409 scope_version_conflict`. Сканирующие задачи запрещены, пока текущая ревизия не `approved` (`409 scope_not_approved`). Импортированный scope всегда `pending_review`.

## Запуск задачи

Web UI использует ID из Assets вместо ручных целей:

```json
{"task_type":"http.crawl","asset_ids":["ast_..."],"params":{"max_pages":100},"idempotency_key":"crawl-1"}
```

`asset_ids` — непустой список ID строк инвентаря текущего проекта. Сервер выводит IP/домены/URL из выбранных Assets и фиксирует снимок в служебном `_asset_input` параметров задания; прислать это поле с клиента нельзя. Вместе с `asset_ids` запрещены ручные `targets/domains/domain/ips/seeds/base_urls` и вложенные `asset_ids/candidate_ids` в `params`. Чужие, удалённые и пустые выборки отклоняются, без подстановки истории или Scope. `http.probe` получает все сохранённые URL только выбранных хостов и режим `url`; если URL нет, требуется Web Crawling. `http.crawl` и `paths.discover` начинают с HTTP/HTTPS корней выбранных хостов/IP. `urls.passive` требует DNS Assets.

Перед работой выбранные хосты проверяются по текущему и исходному Scope; выбранный Asset под разрешённым исходным DNS name допускается с приоритетом исключений. Для IP-проверок свежие A/AAAA должны пересекаться со снимком IP выбранного Asset. Это разрешение действует только для задачи и не меняет Scope. Обход и редиректы ограничены выбранными хостами. Изменение Scope, удаление Asset и отмена учитываются перед дальнейшими запросами.

- `GET /projects/{id}/assets/targets`: полный каталог хостов/IP для выбора, включая `urls`, `confidence`, `interest`; `next` — `scope_empty`, `approve_scope`, `enumerate_subdomains`, `import_scope` или `ready`, плюс `scope_version`, `import_count`, `import_error`. Сеть не используется.
- `POST /projects/{id}/assets/import-scope` с `{"scope_version":2}`: подтверждённый атомарный импорт разрешённых IP и адресов Network в Assets. Требует analyst и утверждённой текущей версии Scope без разрешённых DNS name. Исключения/политика сети применяются; слишком большая сеть (включая IPv6) отклоняется до раскрытия. Лимит `max_queue_targets`; сеть импортируется целиком либо не импортируется. Повтор не создаёт дубликатов, ответ `{"added":N}`. Scope не меняется.

Низкоуровневый API/CLI с явными целями сохраняется:

```http
POST /api/projects/prj_.../jobs
Content-Type: application/json
Origin: https://lastest.example.internal
Idempotency-Key: optional

{"task_type":"http.probe","params":{"targets":["https://www.example.com"],"mode":"url"},"idempotency_key":"ui-42"}
```

`202` с `job.id`, `status:"queued"`, `scope_version`, counters и ссылками. Повтор с тем же ключом и телом возвращает тот же ID; другое тело — `409 idempotency_conflict`.

Ошибки:

- неизвестный тип, неверные типы/поля, превышение лимитов — `400 invalid_params`;
- цель вне утверждённого scope, URL с неоднозначностью, неразрешённый IP — `400 invalid_target`;
- недоступный Nmap-адаптер — `400` с явным сообщением каталога; остальные задачи работают.

Для `tcp.connect`, `nmap.profile`, `reverse.ip` с ручными целями нужны явно разрешённые IP/CIDR. HTTP к разрешённому DNS-имени привязывается к проверенному IP с сохранением `Host`/SNI; редиректы проверяются отдельно; повторное разрешение имени после проверки не выполняется.

`dns.wordlist` использует dnsmap: `{"domain":"example.com","wordlist":"default","concurrency":8}`. Доступны 4, 8 или 16 параллельных исполнителей, по умолчанию 8. `default` содержит 989 слов; `words` остаётся совместимым API-входом и переопределяет содержимое списка. Лимит `max_wordlist_entries` к этой задаче не применяется. Неизвестные списки, неверная параллельность и некорректные DNS-метки отклоняются до постановки в очередь. Формат результата v1 сохраняет `domain`, `found`, `wildcard_addresses`, `searched` и дополняется `engine`, `wordlist`, `concurrency`. В Assets записываются только разрешённые имена с A/AAAA и их IP; JSON-артефакт доступен обычными маршрутами задания. Лимит 50 доменов снят для CT, Subfinder и из каталога цепочки.

## Ответ задачи

```json
{"job":{"id":"job_...","status":"partial","task_type":"http.probe",
 "scope_version":2,"counters":{"targets":2,"processed":1,"skipped":1,"errors":1},
 "error":"...","result":{"format_version":"1"},"artifacts":[
   {"id":"art_...","kind":"http_probe","size":1234,"sha256":"...","href":"/api/evidence/art_..."}
 ],"links":{"self":"/api/jobs/job_...","cancel":"/api/jobs/job_.../cancel"}}}
```

Статусы: `queued`, `running`, `succeeded`, `partial`, `failed`, `cancelled`, `interrupted`. После утраты lease старая попытка не может опубликовать результаты. Активный прогон с возможным побочным эффектом после сбоя требует нового запуска.

В UI технические `succeeded` и `partial` отображаются как Completed; ошибки отдельных проверок показываются счётчиком Errors и свёрнутыми Error details. `failed` отображается отдельно как Failed. Для reverse.ip отсутствие PTR (NXDOMAIN/NODATA) имеет статус источника `empty` и не увеличивает Errors. Summary-артефакт assets.enrich содержит `candidates[].http_errors` (URL и причина) для целей, где активное HTTP-обогащение не получило ответа.

## Цепочка All in one

```json
{"domains":["example.com"],"targets":[],"idempotency_key":"chain-1"}
```

Создаются связанные стадии `subdomains.discover → dns.records → http.probe → urls.passive → http.crawl → web.checks`. Каждая стадия ждёт терминального состояния предыдущей. Продолжение после `partial` разрешено; после `failed/cancelled/interrupted` зависимая стадия пропускается с причиной.

### Пресет Asset Discovery

Интерфейс передаёт `{"preset":"asset_discovery","asset_ids":["ast_..."],"sources":["ptr","shodan_internetdb"],"http_enrichment":false}`. Сервер получает IP из выбранных Assets; стадии enrich/classify обрабатывают исходные Assets, включая IP-only, и committed-кандидатов текущей цепочки. Если PTR/провайдер не нашёл кандидатов, исходные Assets всё равно обогащаются и классифицируются. Одновременная передача `ips` и `asset_ids` запрещена.

Совместимый низкоуровневый вариант:

```json
{"preset":"asset_discovery","ips":["203.0.113.10"],"sources":["ptr","shodan_internetdb"],"http_enrichment":false,"idempotency_key":"disc-1"}
```

Если `ips` пуст, backend берёт явные IP-записи утверждённого Scope; CIDR в UI не разворачивается. Создаются стадии `reverse.ip → assets.enrich → assets.classify` с явными `input_refs`: enrich читает только committed output reverse.ip этого запуска, classify — reverse.ip и assets.enrich. Отсутствие `preset` сохраняет прежний All in one. Неизвестный preset и пустой `sources` отклоняются. Значения `ips`, `sources` и `http_enrichment` фиксируются в запуске; scope snapshot закрепляется действующим механизмом jobs. В `GET /chains/{id}` стадии содержат `input_refs`, а результат каждой стадии — счётчики и снимок входов.

## Dashboard и отчёты

Assets объединяет хосты с их IPv4/IPv6 по сохранённым DNS, PTR и HTTP-наблюдениям, включая импорт 1.x. Новые DNS-запросы при просмотре не выполняются. Одна строка содержит `id`, `kind`, `host`, `ips`, `last_seen`; аддитивно возвращаются `groups`, `technologies`, `categories`, `confidence`, `interest`, `providers`. IP без связанного хоста имеет `host: null`. Поиск `q` — буквальное вхождение без учёта регистра в имя хоста или IP; он применяется ко всему проекту, до пагинации. Фильтры `technology`, `provider` и `category` работают по сохранённым классификациям и происхождению, без сети. Ответ использует `items`, `total`, `limit: 10`, `offset`; выходящий за диапазон offset возвращает последнюю страницу. TXT (табуляция) и CSV содержат Hosts, IP addresses, Last seen и выгружают все совпадения, независимо от страницы.

`GET /projects/{id}/discovery/candidates` возвращает кандидатов с `hostname`, `sources`, `dns_status` (`not_checked|verified|no_addresses|dns_error|not_permitted`), `ip_match` (`matched|not_matched|unknown`), `addresses`, `scope_status_at_check` и пересчитанным `current_scope_status`. Фильтр `scope_status` использует текущий Scope. Значения фильтров валидируются. Detail содержит историю evidence, enrichment и classification; чужие candidate/asset IDs дают `404`.

Удаление хоста атомарно очищает его запись, наблюдения, URL и находки с точным совпадением имени хоста (без поддоменов). Все IP-записи и наблюдения других хостов сохраняются. Освободившийся IP появляется отдельной строкой. Удаление связанного с хостом IP через API отклоняется с `409 ip_in_use`; отдельный IP можно удалить вместе с его наблюдениями и находками. Успех — `204`, отсутствующий в проекте актив — `404`. Scope, задания и файлы доказательств остаются; будущий запуск или повторный импорт может обнаружить удалённый актив заново. Действия записываются как `asset.delete` и `asset.export`.

`GET /projects/{id}/dashboard` возвращает `data_status` (`empty|partial|ready`), метрики, наблюдения по источникам, HTTP, порты (кандидаты отдельно от подтверждённых), находки, покрытие web-правил и недоступные источники. Данные читаются из SQLite, не из mock.

`GET /projects/{id}/reports/json|csv` строит снимок проекта: scope и история, jobs, DNS, HTTP, URL, службы, domain→IP, источники, находки. Аддитивно JSON содержит `candidates`, `enrichment` и `classification` с версиями, временем и provenance. `discovery-json`/`discovery-csv` — отдельный явный расширенный вариант; стандартный CSV/TXT Assets не меняется. CSV нейтрализует внешние значения, начинающиеся с `= + - @`, tab или CR. Отчёты и экспорт не выполняют сетевых запросов и не возвращают секреты или общий кэш провайдеров.

## Пользователи

```http
POST /api/users
{"username":"analyst1","password":"at-least-12-chars","role":"analyst","must_change_password":true}
```

```http
PATCH /api/users/usr_...
{"role":"viewer","is_active":true,"password":"new-password-at-least-12"}
```

Деактивация и смена пароля отзывают сессии пользователя. Аудит пишется для login/logout, управления пользователями, scope, запуска/отмены, импорта и экспорта.

Независимые задания выполняются параллельно: `limitations.max_concurrent_jobs` в каталоге показывает лимит одного процесса worker (по умолчанию 4). Цепочки остаются последовательными. В `subdomains.subfinder` отсутствие A/AAAA сохраняется как `rejected[].reason: no_addresses` без ошибки задания. В CT-артефакте `sources[].status` может быть `partial`: имена с успешно прочитанных страниц сохраняются вместе с `reason` последующего сбоя.

Для `subdomains.subfinder`, `subdomains.discover`, `dns.records` и `dns.wordlist` наличие A/AAAA обязательно перед публикацией имени в Assets. `subdomains.subfinder.resolve` объявлен устаревшим: старые значения, включая `false`, принимаются, но фактически выполняется `resolve=true`. CT wildcard-шаблоны сохраняются только в артефакте. У CT, DNS records и DNS wordlist результат v1 дополнен `hosts` (имя, `ips`, `dns_verified`) и `rejected`; список `subdomains` CT содержит только подтверждённые имена. В DNS records `record_types` определяет поля `records` артефакта, а проверка A/AAAA выполняется дополнительно независимо от выбора типов. Исторические Assets и импортированные результаты автоматически не удаляются.

### Asset Discovery: validation and snapshots

Discovery list/export apply the same validated source, DNS, IP-match, current-Scope,
confidence and interest filters. Pagination totals cover the complete matching
inventory; bounded JSON exports include `total` and `truncated`. Candidate detail
returns up to 200 recent evidence entries. The immutable job artifacts retain
run results. Classification history is kept in these artifacts and source evidence,
not recursively embedded into the latest classification row.

Explicit candidate/asset IDs must belong to the selected project; missing or foreign
IDs never select a fallback project sample. Chain inputs read candidate checks and
observations published by their referenced jobs, even if another run subsequently
updates the same candidate. Reusing a chain idempotency key with different inputs
returns HTTP 409. Omitting Discovery sources selects PTR and Shodan InternetDB.

Provider cache namespaces include a one-way hash of the effective credentials and
organization context. Credential rotation does not reuse an earlier credential's
response. Every actual request, including retries, observes the installation-wide
rate limit and the current approved IP scope. Provider endpoint URLs must use HTTPS;
HTTP is accepted only for loopback test fixtures. URLs with embedded credentials,
query strings or fragments are rejected. The provider catalog never exposes endpoints
or credentials and reports configuration rather than claiming a successful connection.
