# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

from panlab.settings import Settings, load_settings


def test_configured_with_api_key() -> None:
    settings = Settings(host="203.0.113.3", api_key="fwtest-key-not-real")
    assert settings.configured
    assert settings.uses_api_key
    assert not settings.uses_password


def test_configured_with_user_password() -> None:
    settings = Settings(host="203.0.113.3", username="panlab-auto", password="fwtest-pass-not-real")
    assert settings.configured
    assert settings.uses_password
    assert not settings.uses_api_key


def test_placeholder_password_is_not_configured() -> None:
    settings = Settings(
        host="203.0.113.3",
        username="panlab-auto",
        password="replace-with-password",
    )
    assert not settings.configured


def test_redacted_strips_secrets() -> None:
    settings = Settings(host="203.0.113.3", api_key="super-secret-key", password="super-secret-pass")
    text = settings.redacted("failed auth super-secret-key or super-secret-pass")
    assert "super-secret-key" not in text
    assert "super-secret-pass" not in text
    assert "***" in text


def test_load_settings_from_explicit_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PANOS_HOST", raising=False)
    monkeypatch.delenv("PANOS_API_KEY", raising=False)
    monkeypatch.delenv("PANOS_USER", raising=False)
    monkeypatch.delenv("PANOS_PASSWORD", raising=False)
    env = tmp_path / ".env"
    env.write_text(
        "PANOS_HOST=203.0.113.3\nPANOS_USER=panlab-auto\nPANOS_PASSWORD=only-in-test\n",
        encoding="utf-8",
    )
    settings = load_settings(env)
    assert settings.host == "203.0.113.3"
    assert settings.username == "panlab-auto"
    assert settings.uses_password
    # The test file is local and temporary; do not print settings.password.
