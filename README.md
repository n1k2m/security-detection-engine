# Security Detection Engine

Модульная система для анализа событий информационной безопасности, обнаружения подозрительной активности и выявления потенциальных угроз.

Планируемые источники данных:

- Linux Authentication Logs
- Windows Event Logs и Sysmon
- PCAP-файлы и сетевой трафик

## Текущее состояние

- **Core**: базовая структура проекта, конфигурация приложения и общая модель нормализованного события безопасности `SecurityEvent`.
- **Linux SSH Authentication Log Analyzer**: чтение Linux auth logs, разбор событий SSH-аутентификации и их преобразование в `SecurityEvent`.

## Назначение Core

- Единая модель события `SecurityEvent`, независимая от источника данных.
- Загрузка конфигурации приложения из переменных окружения.
- Общие перечисления: источники событий (`EventSource`) и уровни важности (`Severity`).

## Linux SSH Authentication Log Analyzer

Анализирует записи sshd из `/var/log/auth.log` (Debian/Ubuntu) и `/var/log/secure` (RHEL):

- `Failed password ...` — неудачная аутентификация (`ssh_authentication_failed`, в том числе для invalid user);
- `Accepted password/publickey/... ...` — успешная аутентификация (`ssh_authentication_success`).

Конвейер состоит из трёх компонентов:

- `collectors` — построчное чтение файла без загрузки в память;
- `parsers` — разбор строки в структурированную запись `SshAuthRecord`;
- `normalization` — преобразование записи в `SecurityEvent`.

Точка входа — `analyze_ssh_log(path, year=..., tz=...)`. Год и часовой пояс передаются явно, так как syslog-метка времени их не содержит:

```python
from datetime import UTC
from security_detection_engine.analyzer import analyze_ssh_log

result = analyze_ssh_log("auth.log", year=2024, tz=UTC)
print(result.events, result.unsupported_lines, result.invalid_lines)
```

## Технологии

- Python 3.11
- Pydantic 2 / pydantic-settings — модели данных, валидация, конфигурация
- pytest — тестирование
- Ruff — проверка и форматирование кода

## Требования к окружению

- Python 3.11
- Виртуальное окружение (рекомендуется)

## Установка

```bash
python -m venv .venv
source .venv/Scripts/activate  # Windows (Git Bash)
# source .venv/bin/activate    # Linux/macOS

pip install -e ".[dev]"
```

## Конфигурация

Настройки задаются переменными окружения с префиксом `SDE_`:

| Переменная      | По умолчанию                 | Описание           |
|-----------------|------------------------------|--------------------|
| `SDE_APP_NAME`  | `security-detection-engine`  | Название приложения |
| `SDE_VERSION`   | `0.1.0`                      | Версия             |
| `SDE_LOG_LEVEL` | `INFO`                       | Уровень логирования |

## Запуск тестов

```bash
pytest
```

## Проверка кода

```bash
ruff check .
ruff format --check .
```

## Структура проекта

```
security-detection-engine/
├── src/
│   └── security_detection_engine/
│       ├── __init__.py
│       ├── analyzer.py        # Точка входа анализа SSH-логов
│       ├── config.py          # Конфигурация приложения
│       ├── collectors/        # Чтение лог-файлов
│       ├── models/            # Модель SecurityEvent
│       ├── parsers/           # Разбор строк логов
│       └── normalization/     # Преобразование в SecurityEvent
├── tests/                     # Автоматизированные тесты
├── .gitignore
├── pyproject.toml
└── README.md
```
