import json
from pathlib import Path

from afw_hermes.config import load_config


def test_env_values(tmp_path):
    cfg = load_config(
        env={
            "AFW_CONSOLE_URL": "https://console.example/",
            "AFW_AGENT_TOKEN": "tok",
            "AFW_AGENT_NAME": "daniel-bot",
            "AFW_CA_FILE": "/etc/afw/ca.pem",
            "AFW_STATE_DIR": str(tmp_path),
            "AFW_HOOK_TIMEOUT_MS": "30",
        },
        search=False,
    )
    assert cfg.console_url == "https://console.example"
    assert cfg.agent_token == "tok"
    assert cfg.agent_name == "daniel-bot"
    assert cfg.ca_file == "/etc/afw/ca.pem"
    assert cfg.state_dir == Path(tmp_path)
    assert cfg.hook_timeout == 0.03


def test_hook_timeout_is_capped_at_50ms(tmp_path):
    cfg = load_config(env={"AFW_STATE_DIR": str(tmp_path), "AFW_HOOK_TIMEOUT_MS": "5000"}, search=False)
    assert cfg.hook_timeout <= 0.05


def test_yaml_file_then_env_override(tmp_path):
    f = tmp_path / "afw-hermes.yaml"
    f.write_text(
        "# comment\nconsole_url: \"https://from-file\"\nagent_token: filetok\nagent_name: from-file\n"
        "policy_refresh_secs: 30\n"
    )
    cfg = load_config(env={"AFW_HERMES_CONFIG": str(f), "AFW_AGENT_NAME": "from-env",
                           "AFW_STATE_DIR": str(tmp_path)})
    assert cfg.console_url == "https://from-file"
    assert cfg.agent_token == "filetok"
    assert cfg.agent_name == "from-env"
    assert cfg.policy_refresh_interval == 30


def test_json_file(tmp_path):
    f = tmp_path / "afw-hermes.json"
    f.write_text(json.dumps({"console_url": "https://j", "agent_name": "j-bot"}))
    cfg = load_config(env={"AFW_HERMES_CONFIG": str(f), "AFW_STATE_DIR": str(tmp_path)})
    assert cfg.console_url == "https://j"
    assert cfg.agent_name == "j-bot"


def test_file_found_in_hermes_home(tmp_path):
    (tmp_path / "afw-hermes.yaml").write_text("agent_name: home-bot\n")
    cfg = load_config(env={"HERMES_HOME": str(tmp_path)})
    assert cfg.agent_name == "home-bot"
    assert cfg.state_dir != tmp_path / "afw"  # state kept outside HERMES_HOME (ADR 0015)


def test_defaults_without_anything(tmp_path):
    cfg = load_config(env={"HERMES_HOME": str(tmp_path)})
    assert cfg.console_url is None
    assert cfg.agent_name  # hostname fallback
    assert cfg.policy_refresh_interval == 60
