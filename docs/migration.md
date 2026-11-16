# Миграция с LasTest 1.x

Импорт читает согласованную копию старых данных, не изменяет источник и не активирует старый scope.

## Что переносится

- `config.yaml`: метаданные проекта и предложения scope (`scope.domains`, `scope.ips`, `scope.exclusions`);
- `recon/subdomains/subdomains.json`: `all` и `sources`;
- `recon/dns_records/dns_records.json`: `hosts[].records`;
- `recon/httpx/alive_hosts.json`, резервные ключи `recon.httpx.root_alive_hosts`/`recon.alive_hosts` и URL-файлы;
- `recon/urls/passive_urls.json`, `all_urls.txt`, `sources/*.txt`;
- `recon/nmap/*.json` и `domain_ip_map.json`: domain→IP, порты, службы;
- `web/nuclei/findings.json`;
- опционально jobs и audit из переданной старой SQLite;
- опционально пользователи и роли без сессий и паролей.

Оригиналы поддерживаемых артефактов копируются в `<data>/evidence/imports/<project_id>/<import_run>/...` и индексируются как `legacy_original`.

## Dry run и применение

```bash
lastest --data-dir /data import legacy \
  --projects-dir /srv/legacy-copy/projects \
  --database /srv/legacy-copy/lastest.sqlite \
  --logs-root /srv/legacy-copy/logs \
  --dry-run

lastest --data-dir /data import legacy \
  --projects-dir /srv/legacy-copy/projects \
  --database /srv/legacy-copy/lastest.sqlite \
  --logs-root /srv/legacy-copy/logs \
  --apply
```

Dry run не создаёт новую базу и каталог доказательств. Он показывает проекты, типы записей, количество, предупреждения, конфликты имён и битые входы. Применение на неизменном входе в свежий target подтверждает те же счётчики (проверяется `tests/import.rs`).

## Правила

- Старый scope импортируется как `pending_review`, каждое правило `verified=false`. Сканирующие задачи запрещены до утверждения оператором.
- `scope.domains`/`scope.ips` могут содержать найденные CLI-цели. Импорт трактует их как предложения, а не как подтверждённое разрешение.
- Исключения сохраняются и имеют приоритет.
- Совпадение имени с существующим проектом — конфликт. Данные не заменяются. Для явного сопоставления: `--map old-name=new-name`.
- Старые `queued` и `running` jobs становятся архивными `cancelled` с причиной; новый worker их никогда не выполняет.
- Пользователи: только имя/роль/активность. Пароли, хэши, JWT, сессии и токены не переносятся. Импортированный пользователь получает недоступный случайный пароль и флаг смены пароля; выключенный остаётся выключенным.
- Логи читаются только из явно переданного `--logs-root`; абсолютные пути и symlink за пределами источника не используются.
- Файлы проверяются по размеру и типу; symlink и path traversal отклоняются с предупреждением.
- Идемпотентность: повторный импорт не дублирует наблюдения, находки, порты и архивные jobs. Проект определяется по `source=lastest-1.x` + исходному имени.

## Конфликты и обновления источника

- Имя занято: используйте `--map`.
- Запись уже импортирована: пропускается.
- Источник обновился: новые исходные идентификаторы добавляются; изменённые записи с тем же исходным ID не перезаписываются автоматически. Для пересмотра используйте новую копию/проект и явное сопоставление.
- Обрыв импорта: повторный `--apply` продолжит с неимпортированных записей; уже применённые не дублируются.
- Битый файл виден в `warnings`; остальные поддерживаемые файлы проекта импортируются.

## Проверка

Тесты: `cargo test --locked --all-targets --all-features --test import`.

Синтетическая фикстура: `tests/fixtures/legacy/`. Она включает проекты, DNS/HTTP/URL/Nmap/Nuclei, битый JSON и проверку symlink. Полный цикл backup/restore проверяется отдельно.
