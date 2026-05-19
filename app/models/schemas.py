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
    exclusions: list[str] | None = None
    replace: bool = False


class CreateJobRequest(BaseModel):
    task_type: str
    params: dict[str, Any] = Field(default_factory=dict)


class LoginRequest(BaseModel):
    username: str = Field(min_length=2, max_length=128)
    password: str = Field(min_length=1, max_length=4096)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=2, max_length=128)
    password: str = Field(min_length=12, max_length=4096)
    role: str = "analyst"


class UpdateUserRequest(BaseModel):
    password: str | None = Field(default=None, min_length=12, max_length=4096)
    role: str | None = None
    is_active: bool | None = None


class ApiMessage(BaseModel):
    message: str
