from os import path
from pydantic import BaseSettings, Field
from pathlib import Path


class Settings(BaseSettings):
    base_path: str = "."
    key_path: str = "~/.ssh/id_rsa"
    pkey_path: str = path.expanduser(key_path)
    config_file: str = str(Path(base_path, "config.json").absolute())
    inventory_file: str = str(Path(base_path, "inventory.json").absolute())
    hash_file: str = str(Path(base_path, "hashes.json").absolute())
    metric_file: str = str(Path(base_path, "metrics.jsonl").absolute())

    INFLUX_TOKEN: str
    INFLUX_ORG: str
    INFLUX_BUCKET_PREFIX: str
    INFLUX_HOST: str

    COLLECTION_INTERVAL: int = Field(
        60, description="Approx. interval in seconds between metric collection"
    )
    HEALTH_INTERVAL: int = Field(
        60, description="Approx. interval in seconds between health check"
    )

    class Config:
        env_file = "wiretap.env"
        env_file_encoding = "utf-8"


settings = Settings()
