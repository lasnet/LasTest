# LasTest 2.0

Внутренняя платформа на Rust для разведки и проверок в разрешённом scope. Один бинарник `lastest` запускает API, worker и CLI. Результаты и очередь хранятся в SQLite, а web-интерфейс встроен в бинарник.

## Установка и обновление

Образ для Linux `amd64` собирается из `dev` и публикуется в GitHub Container Registry после тестов. В [инструкции по установке](docs/v2/install.md) есть вход в GHCR, первый запуск Compose, создание администратора и переход с локально собранного образа. Для установки на сервере нужны Docker и Compose v2.

## Работа с проектами

- В web или CLI выберите проект, утвердите scope и запустите отдельную задачу либо цепочку `All in one`.
- Доступны DNS и пассивный поиск, HTTP-проверки, сбор URL, обход сайта, TCP-проверки и отчёты JSON/CSV.
- Действующие возможности и ограничения инструментов перечислены в [руководстве оператора](docs/v2/operator.md). Проверяйте только цели, на которые у вас есть разрешение.

## Документация

- [Контракт API](docs/v2/api.md)
- [Импорт проектов 1.x](docs/v2/migration.md)
- [Резервная копия, восстановление и откат](docs/v2/rollback.md)
- [Проверки и замеры](docs/v2/checks.md)

Исходники LasTest 1.x сохранены в теге [`v1-legacy`](https://github.com/lasnet/LasTest/tree/v1-legacy).

## Разработка

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked --release
```

Для сквозной проверки Docker используйте `./scripts/v2-e2e.sh` с `LASTEST_IMAGE`, указывающим на digest образа. Инструкции для работы с кодом находятся в [AGENTS.md](AGENTS.md).
