from pydantic import BaseModel, Field, EmailStr
from typing import Any

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class IntegrationIn(BaseModel):
    config: dict[str, Any]
    enabled: bool = True

class GenerateConfigIn(BaseModel):
    name: str
    vendor: str = "Custom"
    base_url: str
    auth_type: str = "none"
    endpoints: list[dict] = Field(default_factory=list)
    mapping: dict = Field(default_factory=dict)
    incremental: dict = Field(default_factory=lambda: {"enabled": False, "strategy": "full"})

class TestConfigIn(BaseModel):
    config: dict[str, Any]
