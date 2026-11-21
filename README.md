# LasTest

Внутренняя платформа на Rust для разведки и проверок в разрешённом scope. Один бинарник `lastest` запускает API, worker и CLI. Результаты и очередь хранятся в SQLite, а web-интерфейс встроен в бинарник.

## Установка и обновление

Установите Docker и Docker Compose. Выполните команды из каталога проекта.

```bash
docker compose up -d
docker compose exec api lastest admin setup-code
```

Откройте `http://127.0.0.1:8080`, введите одноразовый код и создайте первого администратора.

Поддерживаются сборки для Linux `amd64` (Intel/AMD) и `arm64` (ARM-серверы и Linux-контейнеры на Mac с Apple Silicon).

- **amd64:** образ `ghcr.io/lasnet/lastest:dev` публикуется после тестов, сквозных Docker-проверок и отдельно проверяется установкой на чистом сервере.
- **arm64:** GitHub Actions проверяет сборку Docker-образа. Для запуска используйте локальную сборку; ARM64 пока не публикуется в общем теге `dev` и требует проверки на ARM64-хосте перед публикацией.

Доступ из сети, HTTPS, локальная сборка и перенос существующего тома описаны в [инструкции по установке](docs/install.md).

## Работа с проектами

- В web или CLI выберите проект, утвердите scope и запустите отдельную задачу либо цепочку `All in one`.
- Доступны DNS и пассивный поиск, HTTP-проверки, сбор URL, обход сайта, TCP-проверки и отчёты JSON/CSV.
- Действующие возможности и ограничения инструментов перечислены в [руководстве оператора](docs/operator.md). Проверяйте только цели, на которые у вас есть разрешение.

## Документация

- [Модель работы Project → Scope → Assets → модули](docs/product-workflow.md)
- [Контракт API](docs/api.md)
- [Импорт проектов 1.x](docs/migration.md)
- [Резервная копия, восстановление и откат](docs/rollback.md)
- [Проверки и замеры](docs/checks.md)

Исходники LasTest 1.x сохранены в теге [`v1-legacy`](https://github.com/lasnet/LasTest/tree/v1-legacy).

## Разработка

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked --release
```

Для сквозной проверки Docker используйте `./scripts/e2e.sh` с `LASTEST_IMAGE`, указывающим на digest образа. Инструкции для работы с кодом находятся в [AGENTS.md](AGENTS.md).
