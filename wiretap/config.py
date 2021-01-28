from os import path
from pydantic import BaseSettings, Field
from pathlib import Path


class Settings(BaseSettings):
    base_path: str = path.expanduser('~/.config/wiretap')
    pkey_path: str = path.expanduser('~/.ssh/id_rsa')
    config_file: str = str(Path(base_path, 'config.json').absolute())
    inventory_file: str = str(Path(base_path, 'inventory.json').absolute())
    hash_file: str = str(Path(base_path, 'hashes.json').absolute())
    metric_file: str = str(Path(base_path, 'metrics.jsonl').absolute())

    INFLUX_TOKEN: str = "wE2MepBauGjKasjUy-B4kr74gaUkHuHwg37gcegQksA8zmiWqZ6QwV3t7NsD6-HrD6ljJtIrIJtfMtl2y4Gulg=="
    INFLUX_ORG: str = "test"
    INFLUX_BUCKET: str = "wiretap"
    INFLUX_HOST: str = "http://localhost:8086"

    COLLECTION_INTERVAL: int = Field(60, description="Approx. interval in seconds between metric collection")
    HEALTH_INTERVAL: int = Field(60, description="Approx. interval in seconds between health check")


settings = Settings()
