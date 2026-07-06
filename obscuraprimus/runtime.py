from __future__ import annotations

import json
import logging
import sys
from pathlib import Path


APP_DIR_NAME = "ObscuraPrimusData"
DEFAULT_CONFIG = {
    "theme": "dark",
    "last_directory": "",
    "default_compress": True,
    "default_adaptive": False,
    "default_spread": False,
    "first_run_complete": False,
    "update_repo": "The-Swarm-Corporation/ObscuraPrimus",
}


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def portable_data_dir() -> Path:
    path = app_base_dir() / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_path() -> Path:
    return portable_data_dir() / "config.json"


def log_path() -> Path:
    return portable_data_dir() / "obscuraprimus.log"


def load_config() -> dict:
    path = config_path()
    if not path.exists():
        config = dict(DEFAULT_CONFIG)
        save_config(config)
        return config
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return _validate_config(loaded)
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_CONFIG)


def save_config(config: dict) -> None:
    path = config_path()
    path.write_text(json.dumps(_validate_config(config), indent=2, sort_keys=True), encoding="utf-8")


def configure_logging() -> Path:
    path = log_path()
    logging.basicConfig(
        filename=path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return path


def _validate_config(config: dict) -> dict:
    if not isinstance(config, dict):
        return dict(DEFAULT_CONFIG)
    clean = dict(DEFAULT_CONFIG)
    if config.get("theme") in {"dark", "high_contrast"}:
        clean["theme"] = config["theme"]
    if isinstance(config.get("last_directory"), str):
        clean["last_directory"] = config["last_directory"]
    for key in ("default_compress", "default_adaptive", "default_spread"):
        if isinstance(config.get(key), bool):
            clean[key] = config[key]
    if isinstance(config.get("first_run_complete"), bool):
        clean["first_run_complete"] = config["first_run_complete"]
    if isinstance(config.get("update_repo"), str):
        clean["update_repo"] = config["update_repo"].strip()
    return clean
