from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=2, max_length=63)
    client: str = ""
    description: str = ""


class ScopeUpdateRequest(BaseModel):
    domains: list[str] | None = None
    ips: list[str] | None = None
    replace: bool = False


class CreateJobRequest(BaseModel):
    task_type: str
    params: dict[str, Any] = Field(default_factory=dict)


class ApiMessage(BaseModel):
    message: str

