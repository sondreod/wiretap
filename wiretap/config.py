from os import path
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    base_path: str = path.expanduser('~/.config/wiretap/')
    pkey_path: str = path.expanduser('~/.ssh/id_rsa')
    hash_path: str = f'{base_path}seen_hashes'
    config_file: str = Field('/opt/wiretap/config.json', env='WT_CONFIG_FILE')
    inventory_file: str = Field(f'{base_path}inventory.json', env='WT_INVENTORY')

    INFLUX_TOKEN: str = "wE2MepBauGjKasjUy-B4kr74gaUkHuHwg37gcegQksA8zmiWqZ6QwV3t7NsD6-HrD6ljJtIrIJtfMtl2y4Gulg=="
    INFLUX_ORG: str = "test"
    INFLUX_BUCKET: str = "wiretap"

    INTERVAL: int = Field(60, description="Approx. interval in seconds between metric collection")


settings = Settings()
