from pydantic import BaseModel, Field
from typing import Callable, Union, Any, Optional


class Server(BaseModel):
    name: str
    host: str = Field(
        ..., regex=r"[a-z0-9\.\-]{3,100}", description="Domain name or IP"
    )
    username: str = Field("ubuntu")


class Record(BaseModel):
    timestamp: int = Field(..., alias="__REALTIME_TIMESTAMP")


class LogRecord(Record):
    message: str = Field(..., alias="MESSAGE")
    transport: str = Field(..., alias="_TRANSPORT")
    hostname: str = Field(..., alias="_HOSTNAME")
    boot_id: str = Field(..., alias="_BOOT_ID")
    cursor: str = Field(..., alias="__CURSOR")


class Metric(BaseModel):
    tag: str
    time: int
    value: Any
    unit: Optional[str]
    agg_type: str = Field(
        "mean",
        description="The aggregation function (if any) to use when downsampling metrics",
    )
    name: Optional[str]
