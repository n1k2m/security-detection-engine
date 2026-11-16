# Security Detection Engine

Модульная система для анализа событий информационной безопасности, обнаружения подозрительной активности и выявления потенциальных угроз.

Планируемые источники данных:

- Linux Authentication Logs
- Windows Event Logs и Sysmon
- PCAP-файлы и сетевой трафик

## Текущее состояние

Реализован первый этап — **Core**: базовая структура проекта, конфигурация приложения и общая модель нормализованного события безопасности `SecurityEvent`. На этой модели будут строиться последующие компоненты: парсеры, нормализация, Detection Engine, Correlation Engine и Alerting.

## Назначение Core

- Единая модель события `SecurityEvent`, независимая от источника данных.
- Загрузка конфигурации приложения из переменных окружения.
- Общие перечисления: источники событий (`EventSource`) и уровни важности (`Severity`).

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
│       ├── config.py          # Конфигурация приложения
│       └── models/
│           ├── __init__.py
│           └── event.py       # Модель SecurityEvent
├── tests/                     # Автоматизированные тесты
├── .gitignore
├── pyproject.toml
└── README.md
```
