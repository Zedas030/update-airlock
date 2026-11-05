"""Read and write Home Assistant YAML (with !include, !secret, ... tags) without losing the tags,
and find out which integrations a configuration actually uses.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml


class Tagged:
    def __init__(self, tag: str, value):
        self.tag, self.value = tag, value

    def __repr__(self):
        return f"Tagged({self.tag!r}, {self.value!r})"


class _Loader(yaml.SafeLoader):
    pass


class _Dumper(yaml.SafeDumper):
    pass


def _construct(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return Tagged(node.tag, loader.construct_scalar(node))
    if isinstance(node, yaml.SequenceNode):
        return Tagged(node.tag, loader.construct_sequence(node, deep=True))
    return Tagged(node.tag, loader.construct_mapping(node, deep=True))


def _represent(dumper, data: Tagged):
    if isinstance(data.value, list):
        return dumper.represent_sequence(data.tag, data.value)
    if isinstance(data.value, dict):
        return dumper.represent_mapping(data.tag, data.value)
    return dumper.represent_scalar(data.tag, str(data.value), style="")


_Loader.add_multi_constructor("!", _construct)
_Dumper.add_representer(Tagged, _represent)


def load(text: str):
    return yaml.load(text, Loader=_Loader)


def dump(data) -> str:
    return yaml.dump(data, Dumper=_Dumper, allow_unicode=True, sort_keys=False, default_flow_style=False)


# Top-level keys of configuration.yaml that are not integrations
NON_INTEGRATION_KEYS = {"homeassistant", "default_config", "frontend", "logger", "recorder", "http", "lovelace"}


def _platforms(value, out: set[str]) -> None:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("platform"), str):
                out.add(item["platform"])
    elif isinstance(value, dict) and isinstance(value.get("platform"), str):
        out.add(value["platform"])


def used_integrations(config_dir: Path) -> dict[str, list[str]]:
    """Integrations in use, by source.

    config_entries: active (not disabled) config entries from .storage/core.config_entries
    disabled:       config entries that exist but are disabled (reported, but not matched by default)
    yaml:           top-level keys and `platform:` entries in configuration.yaml (includes are not followed
                    except the usual automation/script/scene files, which hold no integrations)
    custom:         custom_components/* (their domains)
    """
    out = {"config_entries": set(), "disabled": set(), "yaml": set(), "custom": set()}
    ce = config_dir / ".storage" / "core.config_entries"
    if ce.exists():
        for e in json.loads(ce.read_text(encoding="utf-8"))["data"]["entries"]:
            (out["disabled"] if e.get("disabled_by") else out["config_entries"]).add(e["domain"])
    cy = config_dir / "configuration.yaml"
    if cy.exists():
        try:
            data = load(cy.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            data = {}
        if isinstance(data, dict):
            for k, v in data.items():
                base = str(k).split(" ")[0]
                if base not in NON_INTEGRATION_KEYS:
                    out["yaml"].add(base)
                _platforms(v, out["yaml"])
            if "default_config" in data:
                out["yaml"].add("default_config")
    cc = config_dir / "custom_components"
    if cc.is_dir():
        for d in cc.iterdir():
            if (d / "manifest.json").exists():
                try:
                    out["custom"].add(json.loads((d / "manifest.json").read_text(encoding="utf-8"))["domain"])
                except (ValueError, KeyError):
                    out["custom"].add(d.name)
    out["disabled"] -= out["config_entries"]
    return {k: sorted(v) for k, v in out.items()}
