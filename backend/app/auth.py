from dataclasses import dataclass
from fastapi import Header, HTTPException
from .models import Role


@dataclass(frozen=True)
class Identity:
    username: str
    role: Role


def identity(x_user: str = Header("demo-agent"), x_role: Role = Header(Role.AGENT)) -> Identity:
    return Identity(username=x_user.strip()[:80] or "anonymous", role=x_role)


def require_admin(user: Identity) -> None:
    if user.role is not Role.ADMIN:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "Administrator role required"})

