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
| `GET /projects/{id}/assets?q=&offset=` | viewer | общая таблица хостов и IP, поиск, страницы по 10 строк |
| `GET /projects/{id}/assets/export/{txt|csv}?q=` | viewer | все строки таблицы с учётом поиска |
| `DELETE /projects/{id}/assets/{asset_id}` | analyst | удаление хоста или отдельного IP с аудитом |
| `GET /evidence/{artifact_id}` | viewer | опубликованное доказательство |
| `GET /projects/{id}/reports/{json|csv}` | viewer | снимок отчёта |
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

Для `tcp.connect`, `nmap.profile`, `reverse.ip` нужны явно разрешённые IP/CIDR. HTTP к разрешённому DNS-имени привязывается к проверенному IP с сохранением `Host`/SNI; редиректы проверяются отдельно; повторное разрешение имени после проверки не выполняется.

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

## Цепочка All in one

```json
{"domains":["example.com"],"targets":[],"idempotency_key":"chain-1"}
```

Создаются связанные стадии `subdomains.discover → dns.records → http.probe → urls.passive → http.crawl → web.checks`. Каждая стадия ждёт терминального состояния предыдущей. Продолжение после `partial` разрешено; после `failed/cancelled/interrupted` зависимая стадия пропускается с причиной.

## Dashboard и отчёты

Assets объединяет хосты с их IPv4/IPv6 по сохранённым DNS, PTR и HTTP-наблюдениям, включая импорт 1.x. Новые DNS-запросы при просмотре не выполняются. Одна строка содержит `id`, `kind`, `host`, `ips`, `last_seen`. IP без связанного хоста имеет `host: null`. Поиск `q` — буквальное вхождение без учёта регистра в имя хоста или IP; он применяется ко всему проекту, до пагинации. Ответ использует `items`, `total`, `limit: 10`, `offset`; выходящий за диапазон offset возвращает последнюю страницу. TXT (табуляция) и CSV содержат Hosts, IP addresses, Last seen и выгружают все совпадения, независимо от страницы.

Удаление хоста атомарно очищает его запись, наблюдения, URL и находки с точным совпадением имени хоста (без поддоменов). Все IP-записи и наблюдения других хостов сохраняются. Освободившийся IP появляется отдельной строкой. Удаление связанного с хостом IP через API отклоняется с `409 ip_in_use`; отдельный IP можно удалить вместе с его наблюдениями и находками. Успех — `204`, отсутствующий в проекте актив — `404`. Scope, задания и файлы доказательств остаются; будущий запуск или повторный импорт может обнаружить удалённый актив заново. Действия записываются как `asset.delete` и `asset.export`.

`GET /projects/{id}/dashboard` возвращает `data_status` (`empty|partial|ready`), метрики, наблюдения по источникам, HTTP, порты (кандидаты отдельно от подтверждённых), находки, покрытие web-правил и недоступные источники. Данные читаются из SQLite, не из mock.

`GET /projects/{id}/reports/json|csv` строит снимок проекта: scope и история, jobs, DNS, HTTP, URL, службы, domain→IP, источники, находки. CSV нейтрализует внешние значения, начинающиеся с `= + - @`, tab или CR.

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
