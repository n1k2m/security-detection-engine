import pytest
from pydantic import ValidationError

from security_detection_engine.config import LogLevel, Settings, get_settings


def test_default_settings():
    settings = Settings()

    assert settings.app_name == "security-detection-engine"
    assert settings.version == "0.1.0"
    assert settings.log_level is LogLevel.INFO


def test_settings_overridden_by_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SDE_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("SDE_APP_NAME", "custom-name")

    settings = Settings()

    assert settings.log_level is LogLevel.DEBUG
    assert settings.app_name == "custom-name"


def test_invalid_log_level_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SDE_LOG_LEVEL", "CHATTERBOX")

    with pytest.raises(ValidationError):
        Settings()


def test_get_settings_returns_settings_instance():
    settings = get_settings()

    assert isinstance(settings, Settings)
