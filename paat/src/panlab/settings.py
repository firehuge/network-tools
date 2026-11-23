# SPDX-License-Identifier: Apache-2.0
"""Load firewall connection settings from the environment or a local .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from panlab.paths import repo_root

PLACEHOLDER_KEY = "replace-with-api-key"
PLACEHOLDER_PASSWORD = "replace-with-password"


@dataclass(frozen=True)
class Settings:
    host: str
    api_key: str = ""
    username: str = ""
    password: str = ""
    vsys: str = "vsys1"
    timeout: int = 180

    @property
    def uses_api_key(self) -> bool:
        return bool(self.api_key and self.api_key != PLACEHOLDER_KEY)

    @property
    def uses_password(self) -> bool:
        return bool(
            self.username
            and self.password
            and self.password != PLACEHOLDER_PASSWORD
        )

    @property
    def configured(self) -> bool:
        return bool(self.host) and (self.uses_api_key or self.uses_password)

    def redacted(self, text: str) -> str:
        """Strip secrets out of a string before printing it."""
        result = text
        for secret in (self.api_key, self.password):
            if secret and secret not in {PLACEHOLDER_KEY, PLACEHOLDER_PASSWORD} and secret in result:
                result = result.replace(secret, "***")
        return result


def _load_env_files(env_file: Path | str | None = None) -> None:
    """Load .env files. Later calls do not override a value already in the environment."""
    load_dotenv()  # cwd .env
    load_dotenv(repo_root() / ".env")
    load_dotenv(Path.home() / "panlab" / ".env")
    if env_file is not None:
        load_dotenv(Path(env_file), override=True)


def load_settings(env_file: Path | str | None = None) -> Settings:
    """Load settings. Never print or log the API key or password."""
    _load_env_files(env_file)
    timeout_raw = os.environ.get("PANOS_TIMEOUT", "180").strip() or "180"
    try:
        timeout = int(timeout_raw)
    except ValueError:
        timeout = 180
    username = (
        os.environ.get("PANOS_USER", "").strip()
        or os.environ.get("PANOS_USERNAME", "").strip()
    )
    return Settings(
        host=os.environ.get("PANOS_HOST", "").strip(),
        api_key=os.environ.get("PANOS_API_KEY", "").strip(),
        username=username,
        password=os.environ.get("PANOS_PASSWORD", "").strip(),
        vsys=os.environ.get("PANOS_VSYS", "vsys1").strip() or "vsys1",
        timeout=timeout,
    )


def connect(settings: Settings):
    """Return a panos Firewall handle. Secrets are not logged."""
    try:
        from panos.firewall import Firewall
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise RuntimeError(
            "pan-os-python is not installed. pip install -r requirements.txt"
        ) from exc
    if not settings.configured:
        raise RuntimeError(
            "Set PANOS_HOST and either PANOS_API_KEY or PANOS_USER plus "
            "PANOS_PASSWORD in the environment or a .env file "
            "(preferred path on a server: /etc/paat/paat.env). "
            "See .env.example."
        )
    kwargs = {
        "hostname": settings.host,
        "vsys": settings.vsys,
        "timeout": settings.timeout,
    }
    if settings.uses_api_key:
        kwargs["api_key"] = settings.api_key
    else:
        kwargs["api_username"] = settings.username
        kwargs["api_password"] = settings.password
    return Firewall(**kwargs)
