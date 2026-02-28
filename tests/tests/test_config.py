"""
Tests for scanner/config.py — all branches.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from scanner.config import (
    CONFIG_FILE,
    NuclearConfig,
    CustomPattern,
    _apply_env,
    load_config,
    save_default_config,
    set_config_value,
)


# ── load_config ───────────────────────────────────────────────────────────────

class TestLoadConfig:
    def test_returns_defaults_when_file_missing(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.toml")
        assert cfg.format == "text"
        assert cfg.severity == "LOW"
        assert cfg.fail_on == "HIGH"
        assert cfg.history is False
        assert cfg.commits == 50

    def test_reads_format_from_file(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[defaults]\nformat = "json"\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.format == "json"

    def test_reads_severity_from_file(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[defaults]\nseverity = "HIGH"\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.severity == "HIGH"

    def test_reads_fail_on_from_file(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[defaults]\nfail_on = "CRITICAL"\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.fail_on == "CRITICAL"

    def test_reads_history_from_file(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[defaults]\nhistory = true\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.history is True

    def test_reads_commits_from_file(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[defaults]\ncommits = 100\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.commits == 100

    def test_partial_file_uses_defaults_for_missing(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[defaults]\nformat = "sarif"\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.format == "sarif"
        assert cfg.severity == "LOW"  # default
        assert cfg.fail_on == "HIGH"  # default

    def test_reads_thresholds(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[thresholds]\ncritical = 15\nhigh = 10\nmedium = 6\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.threshold_critical == 15
        assert cfg.threshold_high == 10
        assert cfg.threshold_medium == 6

    def test_reads_output_file(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[output]\nfile = "report.json"\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.output_file == "report.json"

    def test_reads_output_timestamp(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[output]\ntimestamp = true\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg.output_timestamp is True

    def test_reads_extra_ignore(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[ignore]\nextra_ignore = ["my_placeholder", "internal"]\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert "my_placeholder" in cfg.extra_ignore
        assert "internal" in cfg.extra_ignore

    def test_reads_extra_skip_extensions(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[ignore]\nextra_skip_extensions = [".backup"]\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert ".backup" in cfg.extra_skip_extensions

    def test_reads_extra_skip_dirs(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[ignore]\nextra_skip_dirs = ["terraform", "infra"]\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert "terraform" in cfg.extra_skip_dirs

    def test_reads_custom_patterns(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text(
            '[[patterns.custom]]\nname = "Corp Token"\nregex = "CORP_[A-Z0-9]{32}"\nscore = 8\ncategory = "api_key"\n',
            encoding="utf-8"
        )
        cfg = load_config(cfg_file)
        assert len(cfg.custom_patterns) == 1
        assert cfg.custom_patterns[0].name == "Corp Token"
        assert cfg.custom_patterns[0].score == 8

    def test_custom_pattern_missing_name_skipped(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[[patterns.custom]]\nregex = "CORP_[A-Z0-9]{32}"\n', encoding="utf-8")
        cfg = load_config(cfg_file)
        assert len(cfg.custom_patterns) == 0

    def test_invalid_toml_warns_and_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text("this is not valid toml <<<>>>", encoding="utf-8")
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            cfg = load_config(cfg_file)
        # Should return defaults without raising
        assert cfg.format == "text"

    def test_returns_nuclear_config_instance(self, tmp_path):
        cfg = load_config(tmp_path / "missing.toml")
        assert isinstance(cfg, NuclearConfig)


# ── _apply_env ────────────────────────────────────────────────────────────────

class TestApplyEnv:
    def test_nuclear_format_overrides(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_FORMAT", "json")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.format == "json"

    def test_nuclear_severity_overrides(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_SEVERITY", "critical")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.severity == "CRITICAL"

    def test_nuclear_fail_on_overrides(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_FAIL_ON", "low")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.fail_on == "LOW"

    def test_nuclear_history_true(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_HISTORY", "true")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.history is True

    def test_nuclear_history_1(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_HISTORY", "1")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.history is True

    def test_nuclear_history_false(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_HISTORY", "false")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.history is False

    def test_nuclear_commits_overrides(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_COMMITS", "200")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.commits == 200

    def test_nuclear_commits_invalid_ignored(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_COMMITS", "not_a_number")
        cfg = NuclearConfig(commits=50)
        _apply_env(cfg)
        assert cfg.commits == 50

    def test_nuclear_output_overrides(self, monkeypatch):
        monkeypatch.setenv("NUCLEAR_OUTPUT", "/tmp/report.json")
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.output_file == "/tmp/report.json"

    def test_env_overrides_file_config(self, tmp_path, monkeypatch):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text('[defaults]\nformat = "text"\n', encoding="utf-8")
        monkeypatch.setenv("NUCLEAR_FORMAT", "sarif")
        cfg = load_config(cfg_file)
        assert cfg.format == "sarif"

    def test_no_env_vars_leaves_defaults(self, monkeypatch):
        for k in ("NUCLEAR_FORMAT", "NUCLEAR_SEVERITY", "NUCLEAR_FAIL_ON",
                  "NUCLEAR_HISTORY", "NUCLEAR_COMMITS", "NUCLEAR_OUTPUT"):
            monkeypatch.delenv(k, raising=False)
        cfg = NuclearConfig()
        _apply_env(cfg)
        assert cfg.format == "text"


# ── save_default_config ───────────────────────────────────────────────────────

class TestSaveDefaultConfig:
    def test_creates_file_when_missing(self, tmp_path):
        cfg_path = tmp_path / "nuclear" / "config.toml"
        result = save_default_config(cfg_path)
        assert result.exists()

    def test_creates_parent_dirs(self, tmp_path):
        cfg_path = tmp_path / "a" / "b" / "c" / "config.toml"
        save_default_config(cfg_path)
        assert cfg_path.exists()

    def test_does_not_overwrite_existing(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text("my custom content\n", encoding="utf-8")
        save_default_config(cfg_path)
        assert cfg_path.read_text(encoding="utf-8") == "my custom content\n"

    def test_returns_path(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        result = save_default_config(cfg_path)
        assert result == cfg_path

    def test_created_file_is_valid_toml(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        save_default_config(cfg_path)
        # load_config should parse it without warning
        cfg = load_config(cfg_path)
        assert isinstance(cfg, NuclearConfig)


# ── set_config_value ──────────────────────────────────────────────────────────

class TestSetConfigValue:
    def test_sets_format_value(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        save_default_config(cfg_path)
        set_config_value("format", "json", cfg_path)
        cfg = load_config(cfg_path)
        assert cfg.format == "json"

    def test_sets_severity_value(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        save_default_config(cfg_path)
        set_config_value("severity", "HIGH", cfg_path)
        cfg = load_config(cfg_path)
        assert cfg.severity == "HIGH"

    def test_sets_commits_integer(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        save_default_config(cfg_path)
        set_config_value("commits", "100", cfg_path)
        cfg = load_config(cfg_path)
        assert cfg.commits == 100

    def test_sets_history_boolean(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        save_default_config(cfg_path)
        set_config_value("history", "true", cfg_path)
        cfg = load_config(cfg_path)
        assert cfg.history is True

    def test_unknown_key_raises_value_error(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        save_default_config(cfg_path)
        with pytest.raises(ValueError, match="Unknown config key"):
            set_config_value("unknown_key", "value", cfg_path)

    def test_creates_file_if_missing(self, tmp_path):
        cfg_path = tmp_path / "config.toml"
        set_config_value("format", "sarif", cfg_path)
        assert cfg_path.exists()
        cfg = load_config(cfg_path)
        assert cfg.format == "sarif"
