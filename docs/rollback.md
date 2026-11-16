# Backup, restore и откат

## Согласованная резервная копия

SQLite и файлы доказательств должны соответствовать друг другу. Проще всего остановить worker (и, при необходимости, API), затем выполнить backup.

```bash
docker compose stop worker
lastest --data-dir /data backup --output /backup/lastest-2026-11-15
docker compose start worker
```

`backup`:

1. создаёт `lastest.sqlite` через SQLite `VACUUM INTO` (согласованный снимок БД);
2. копирует `evidence/`;
3. пишет `manifest.json` с версией схемы и временем.

Скопируйте каталог backup на отдельный носитель. Не копируйте WAL-файлы отдельно от базы.

## Восстановление в отдельный том

```bash
docker volume create lastest-restore-data
docker run --rm \
  -v lastest-restore-data:/data \
  -v /backup/lastest-2026-11-15:/backup:ro \
  ghcr.io/lasnet/lastest@sha256:... \
  --data-dir /data restore --from /backup --force
```

Перед переключением проверьте:

```bash
docker run --rm -v lastest-restore-data:/data \
  ghcr.io/lasnet/lastest@sha256:... \
  --data-dir /data doctor
```

`doctor` должен показать `compatible=true`, доступный на запись том и корректный `schema_version`. Только после этого переключайте Compose на новый том.

`restore` отказывается перезаписывать существующую базу без `--force`. При `--force` предыдущая база сохраняется как `lastest.sqlite.pre-restore-<timestamp>`, предыдущий evidence-каталог переименовывается.

## Откат на LasTest 1.x

1. Сохраните текущий том LasTest целиком (или сделайте `lastest backup`).
2. Сохраните digest текущего образа LasTest.
3. Используйте отдельную копию исходников из тега [`v1-legacy`](https://github.com/lasnet/LasTest/tree/v1-legacy) и отдельные `projects/`, `data/`, `logs/` и SQLite 1.x.
4. Запустите Compose или CLI из этой копии.
5. Не удаляйте том текущей установки: после отката новые результаты 1.x в него не попадут.

Перед повторным включением LasTest:

- проверьте `doctor` и совместимость схемы;
- если binary новее схемы — примените миграции новым binary;
- если binary старее схемы, startup завершится ошибкой несовместимости; используйте binary с поддержкой этой схемы или восстановите backup.

## Политика хранения и очистка

`retention_days` задаёт ориентир хранения. Автоматическая очистка в первом релизе не включена, чтобы не удалить доказательства, на которые ссылаются отчёты/аудит. Безопасный порядок ручной очистки:

1. остановить worker;
2. определить артефакты старше срока и не входящие в нужные отчёты;
3. удалить строки `artifacts` и только затем файлы;
4. проверить, что незавершённые попытки не имеют владельца и lease истёк;
5. не удалять `imports/legacy_original` без отдельного решения о происхождении.

## Проверка

```bash
cargo test --locked --all-targets --all-features --test import
```

Тест открывает backup как новую базу, проверяет версию схемы и наличие проекта. Сквозной `scripts/e2e.sh` проверяет сохранение истории после рестарта.
