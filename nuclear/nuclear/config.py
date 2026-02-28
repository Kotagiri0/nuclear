def load_config():
    import json
    from pathlib import Path

    config_path = Path(__file__).parent / 'config.json'
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)