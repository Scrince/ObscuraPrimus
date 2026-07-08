from __future__ import annotations

import importlib.util
import json
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AnalyzerPlugin:
    name: str
    extensions: tuple[str, ...]
    description: str
    version: str = "builtin"
    entry_point: str = ""
    root: str = ""

    def matches(self, path: str | Path) -> bool:
        return Path(path).suffix.lower() in self.extensions


BUILTIN_ANALYZERS = (
    AnalyzerPlugin("core", ("*",), "Magic bytes, hashes, entropy, strings, IOCs, and metadata."),
    AnalyzerPlugin("media", (".png", ".jpg", ".jpeg", ".bmp", ".wav"), "Media structure, LSB, histogram, and waveform summaries."),
    AnalyzerPlugin("document", (".pdf", ".docx", ".xlsx", ".pptx"), "PDF and Office document inspection."),
    AnalyzerPlugin("malware-triage", (".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".py"), "PE and script triage."),
)


def available_plugins() -> list[AnalyzerPlugin]:
    return list(BUILTIN_ANALYZERS) + discover_plugins()


def discover_plugins(directory: str | Path | None = None) -> list[AnalyzerPlugin]:
    from .runtime import portable_data_dir

    root = Path(directory) if directory else portable_data_dir() / "plugins"
    if not root.exists():
        return []
    plugins = []
    for manifest_path in root.rglob("plugin.json"):
        validation = validate_manifest(manifest_path)
        if not validation["valid"]:
            continue
        data = validation["manifest"]
        plugins.append(
            AnalyzerPlugin(
                data["name"],
                tuple(data.get("extensions", ["*"])),
                data.get("description", ""),
                data.get("version", ""),
                data.get("entry_point", ""),
                str(manifest_path.parent),
            )
        )
    return plugins


def validate_manifest(path: str | Path) -> dict:
    manifest_path = Path(path)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"valid": False, "error": str(exc), "manifest": {}}
    required = {"schema", "name", "version", "entry_point"}
    missing = sorted(required - set(data))
    if missing:
        return {"valid": False, "error": f"Missing fields: {', '.join(missing)}", "manifest": data}
    if data["schema"] != "obscuraprimus.analyzer-plugin.v1":
        return {"valid": False, "error": "Unsupported plugin schema.", "manifest": data}
    entry = manifest_path.parent / data["entry_point"]
    if not entry.exists():
        return {"valid": False, "error": "Plugin entry point does not exist.", "manifest": data}
    return {"valid": True, "error": "", "manifest": data}


def run_plugin(plugin: AnalyzerPlugin, path: str | Path, timeout: int = 30) -> dict:
    if not plugin.entry_point or not plugin.root:
        return {"plugin": plugin.name, "findings": [], "risk_delta": 0, "elapsed": 0}
    start = time.time()
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_run_plugin_inline, plugin, str(path))
        result = future.result(timeout=timeout)
        result.setdefault("plugin", plugin.name)
        result["elapsed"] = round(time.time() - start, 3)
        return result
    except TimeoutError:
        return {"plugin": plugin.name, "error": f"Plugin timed out after {timeout} seconds.", "findings": [], "risk_delta": 0}
    except Exception as exc:
        return {"plugin": plugin.name, "error": str(exc), "findings": [], "risk_delta": 0}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def run_matching_plugins(path: str | Path, directory: str | Path | None = None, timeout: int = 30) -> list[dict]:
    results = []
    for plugin in discover_plugins(directory):
        if "*" in plugin.extensions or plugin.matches(path):
            results.append(run_plugin(plugin, path, timeout))
    return results


def _run_plugin_inline(plugin: AnalyzerPlugin, path: str) -> dict:
    entry = Path(plugin.root) / plugin.entry_point
    spec = importlib.util.spec_from_file_location(f"obp_plugin_{plugin.name}", entry)
    if not spec or not spec.loader:
        raise ValueError("Unable to load plugin entry point.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "analyze_file"):
        raise ValueError("Plugin does not expose analyze_file(path).")
    result = module.analyze_file(path)
    if not isinstance(result, dict):
        raise ValueError("Plugin analyze_file(path) must return a dict.")
    return result
