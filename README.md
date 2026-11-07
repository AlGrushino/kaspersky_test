# Information Exchange Service

REST-сервис для обмена информацией об угрозах. Реализован на Go по OpenAPI-спецификации из `api/openapi.yaml`: позволяет создавать, получать и полностью обновлять записи об угрозах по MD5-хешу.

## Возможности

- `GET /info/{md5}`, `POST /info`, `PUT /info/{md5}`.
- Дополненная модель угрозы: описание, критичность, тип, статус, семейство, источник, достоверность, теги, SHA-256, размер и тип файла, даты обнаружения.
- Валидация MD5/SHA-256, enum-значений, длины строк, диапазона `confidence`, тегов и порядка дат.
- `PUT` — полная замена: отсутствующие опциональные поля сбрасываются, MD5 изменить нельзя.
- MD5 и SHA-256 нормализуются в lower-case, `created_at`/`updated_at` управляются сервером.
- Единый формат ошибок `ErrorResponse`.
- Служебные эндпоинты `/healthz` и `/readyz`.
- Request ID, структурированные логи (`log/slog`), recovery, rate-limit по IP.
- Опциональная авторизация по `X-API-Key` для `POST`/`PUT`.
- Опциональный TLS.
- Ограничение размера тела запроса (1 MiB), проверка `Content-Type`, запрет неизвестных JSON-полей.
- Graceful shutdown по `SIGINT`/`SIGTERM`.
- Unit- и интеграционные тесты, Docker-образ и `docker compose`.

## Стек

| Компонент | Технология |
|---|---|
| Язык | Go 1.26 |
| HTTP | `go-chi/chi/v5`, `net/http` |
| OpenAPI | `oapi-codegen/v2` (models, chi-server, strict-server) |
| БД | PostgreSQL 16, `jackc/pgx/v5` + `pgxpool` |
| Миграции | `pressly/goose/v3`, embedded SQL |
| Логирование | `log/slog` |
| Rate limit | `golang.org/x/time/rate` |
| Тесты | `testing`, `testify`, `testcontainers-go` |

## Архитектура

```
cmd/server            — точка входа, конфигурация, graceful shutdown, миграции
internal/api          — HTTP-транспорт: сгенерированный код, handlers, middleware,
                        health-check, ограничения тела запроса
internal/service      — бизнес-логика, валидация и нормализация перед repository
internal/repository   — интерфейс хранилища и Postgres-реализация
internal/domain       — доменная модель, enum-типы, ошибки, валидация
internal/config       — загрузка конфигурации из env
migrations            — embedded SQL-миграции goose
api/openapi.yaml      — OpenAPI-спецификация
```

Сгенерированный код (`internal/api/generated.go`) коммитится, поэтому для сборки не требуется установленный генератор.

## Быстрый старт

```bash
docker compose up --build -d
```

Сервис будет доступен на `http://localhost:8080`, PostgreSQL — на `localhost:5432`.

Проверка:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

Остановка:

```bash
docker compose down          # остановить
docker compose down -v       # остановить и удалить данные PostgreSQL
```

## Локальный запуск

Требования: Go 1.26+ и доступный PostgreSQL.

```bash
export DATABASE_URL='postgres://postgres:postgres@localhost:5432/threats?sslmode=disable'
make run
```

Или напрямую:

```bash
go run ./cmd/server
```

По умолчанию сервер слушает `:8080` и применяет миграции при старте.

## Конфигурация

Все параметры задаются через переменные окружения.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `HTTP_ADDR` | `:8080` | Адрес и порт HTTP-сервера |
| `DATABASE_URL` | — | Строка подключения к PostgreSQL (обязательна) |
| `RUN_MIGRATIONS` | `true` | Применять миграции при старте |
| `RATE_LIMIT_RPS` | `10` | Запросов в секунду на IP |
| `RATE_LIMIT_BURST` | `20` | Размер burst для rate-limit |
| `API_KEY` | — | Если задан, `POST`/`PUT` требуют заголовок `X-API-Key` |
| `TLS_CERT_FILE` | — | Путь к TLS-сертификату (вместе с ключом) |
| `TLS_KEY_FILE` | — | Путь к TLS-ключу (вместе с сертификатом) |
| `LOG_LEVEL` | `info` | Уровень логов: `debug`, `info`, `warn`, `error` |

`TLS_CERT_FILE` и `TLS_KEY_FILE` должны задаваться вместе — тогда сервер стартует с HTTPS.

## API

### Эндпоинты

| Метод | Путь | Успех | Ошибки |
|---|---|---|---|
| `GET` | `/info/{md5}` | `200` + `ThreatResponse` | `400`, `404`, `500` |
| `POST` | `/info` | `201` + `Location` + `ThreatResponse` | `400`, `409`, `500` |
| `PUT` | `/info/{md5}` | `200` + `ThreatResponse` | `400`, `404`, `500` |
| `GET` | `/healthz` | `200` | — |
| `GET` | `/readyz` | `200` | `503` |

Дополнительные ответы при включённых защитах: `401` при неверном `X-API-Key`, `413` при слишком большом теле, `415` при неверном `Content-Type`, `429` при превышении rate-limit.

### Модель угрозы

Поля `ThreatCreateRequest` / `ThreatUpdateRequest` / `ThreatResponse`:

| Поле | Тип | Примечание |
|---|---|---|
| `md5` | string | `^[a-fA-F0-9]{32}$`, первичный ключ, только при создании |
| `name` | string | Обязательно, 1..255 символов |
| `description` | string | До 4096 символов |
| `severity` | enum | `low`, `medium`, `high`, `critical` |
| `type` | enum | `trojan`, `virus`, `worm`, `ransomware`, `spyware`, `adware`, `rootkit`, `miner`, `other` |
| `status` | enum | `active`, `inactive`, `false_positive`, `archived` |
| `family` | string | До 255 символов |
| `source` | string | До 255 символов |
| `confidence` | integer | `0..100` |
| `tags` | array string | До 20 уникальных тегов, каждый 1..64 символа |
| `sha256` | string | `^[a-fA-F0-9]{64}$` |
| `file_size` | int64 | `>= 0` |
| `file_type` | string | До 128 символов |
| `first_seen_at` | date-time | Не позже `last_seen_at` |
| `last_seen_at` | date-time | Не раньше `first_seen_at` |
| `created_at` | date-time | Только в ответе, управляется сервером |
| `updated_at` | date-time | Только в ответе, управляется сервером |

### Примеры

Создание:

```bash
curl -i -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{
    "md5": "D41D8CD98F00B204E9800998ECF8427E",
    "name": "Trojan.Win32.Generic",
    "description": "Вредоносная программа, перехватывающая пользовательский ввод.",
    "severity": "high",
    "type": "trojan",
    "status": "active",
    "family": "Generic",
    "source": "Kaspersky Threat Intelligence",
    "confidence": 95,
    "tags": ["windows", "executable"],
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_size": 102400,
    "file_type": "application/x-dosexec",
    "first_seen_at": "2026-01-15T10:30:00Z",
    "last_seen_at": "2026-02-20T18:45:00Z"
  }'
```

Ответ `201 Created` с заголовком `Location: /info/d41d8cd98f00b204e9800998ecf8427e` и телом `ThreatResponse`. MD5 в ответе будет в lower-case.

Получение:

```bash
curl http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

Обновление (полная замена):

```bash
curl -i -X PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Trojan.Win32.Agent",
    "severity": "critical",
    "status": "active"
  }'
```

Все поля, отсутствующие в `PUT`-запросе, сбрасываются (`null`, пустой массив тегов и т.д.). `md5` берётся из пути и не меняется, `created_at` сохраняется, `updated_at` обновляется сервером.

Если задан `API_KEY`, для `POST`/`PUT` добавьте заголовок:

```bash
-H "X-API-Key: $API_KEY"
```

### Ошибки

```json
{
  "message": "threat not found",
  "details": "not found: md5 d41d8cd98f00b204e9800998ecf8427e"
}
```

`message` — краткое описание, `details` — дополнительная информация (может отсутствовать).

## Миграции

Миграции лежат в `migrations/` и встроены в бинарник через `embed`. Используется goose; при `RUN_MIGRATIONS=true` (по умолчанию) они применяются при старте сервиса.

```bash
RUN_MIGRATIONS=false go run ./cmd/server   # отключить автоприменение
```

## Кодогенерация

После изменения `api/openapi.yaml` перегенерируйте код:

```bash
make generate
# или
go generate ./...
```

`oapi-codegen` подключён как tool-зависимость Go, отдельная установка не нужна. Результат — `internal/api/generated.go`; он коммитится.

## Тесты

```bash
make test               # unit-тесты с -race
make test-integration   # интеграционные тесты с -tags=integration
```

Unit-тесты покрывают валидацию domain, service с fake repository и HTTP-handlers через `httptest`.

Интеграционные тесты поднимают PostgreSQL через testcontainers и проверяют repository и end-to-end API. Если Docker недоступен, они корректно пропускаются.

## Makefile

| Цель | Действие |
|---|---|
| `make build` | Сборка всех пакетов |
| `make run` | Запуск сервера через `go run` |
| `make up` | `docker compose up --build -d` |
| `make down` | `docker compose down` |
| `make vet` | `go vet ./...` |
| `make fmt` | Форматирование через `goimports` |
| `make fmt-check` | Проверка форматирования |
| `make lint` | `golangci-lint run` |
| `make test` | Unit-тесты |
| `make test-integration` | Интеграционные тесты |
| `make test.coverage` | Тесты с отчётом покрытия |
| `make test.html` | HTML-отчёт покрытия (`coverage.html`) |
| `make test.show` | Открыть HTML-отчёт в браузере |
| `make generate` | Генерация кода по OpenAPI |
| `make clean` | Очистка артефактов |
| `make deps` | `go mod tidy` |
| `make dockle` | Проверка образа через Dockle |
| `make help` | Список доступных команд (цель по умолчанию) |

## Безопасность

- Тело запроса ограничено 1 MiB (`413 Request Entity Too Large`).
- `Content-Type` для `POST`/`PUT` должен начинаться с `application/json` (`415` иначе).
- Неизвестные JSON-поля отклоняются (`400`).
- Rate-limit по IP: `429` и заголовок `Retry-After`.
- Опциональная авторизация `X-API-Key`.
- Опциональный TLS.
- Контейнер работает под non-root пользователем.

## Структура проекта

```
.
├── api/
│   └── openapi.yaml
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── api/
│   │   ├── generated.go
│   │   ├── handlers.go
│   │   ├── middleware.go
│   │   ├── bodyguard.go
│   │   └── health.go
│   ├── config/
│   ├── domain/
│   ├── repository/
│   │   └── postgres/
│   └── service/
├── migrations/
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── oapi-codegen.yaml
```

## CI

GitHub Actions (`.github/workflows/ci.yaml`) выполняет:

- проверку форматирования (`goimports`);
- линтер `golangci-lint`;
- unit-тесты;
- интеграционные тесты с testcontainers;
- сборку Docker-образа и проверку через Dockle.

## Лицензия

MIT. См. [LICENSE](LICENSE).
