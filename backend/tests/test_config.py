from rerouter.config import load_config


def test_env_and_toml(tmp_path):
    toml = tmp_path / "r.toml"
    toml.write_text('netflow_port = 9995\n[router]\ndriver = "openwrt"\nhost = "10.0.0.1"\n'
                    'key_file = "~/.ssh/id"\n')
    cfg = load_config({"REROUTER_CONFIG": str(toml), "REROUTER_DATA_DIR": str(tmp_path / "d"),
                       "REROUTER_ROUTER_PORT": "2222", "REROUTER_NETFLOW_ENABLED": "false",
                       "REROUTER_SIMULATE_TRAFFIC": "yes"})
    assert cfg.netflow_port == 9995 and cfg.netflow_enabled is False
    assert cfg.router.driver == "openwrt" and cfg.router.port == 2222
    assert not cfg.router.key_file.startswith("~")
    assert cfg.simulation_enabled is True
