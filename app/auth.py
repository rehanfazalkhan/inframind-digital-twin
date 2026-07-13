from __future__ import annotations

import jwt
from fastapi import HTTPException

from .config import Settings
from .models import Principal


def authenticate(authorization: str | None, settings: Settings, development_role: str) -> Principal:
    if not settings.is_production:
        return Principal(subject="local-development-user", roles={development_role})
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required.")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        jwks = jwt.PyJWKClient(f"{settings.issuer.rstrip('/')}/discovery/v2.0/keys")
        key = jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=settings.audience, issuer=settings.issuer)
    except jwt.PyJWTError as error:
        raise HTTPException(status_code=401, detail="Invalid access token.") from error
    return Principal(subject=claims.get("oid") or claims.get("sub") or "unknown", roles=set(claims.get("roles", [])) | set(claims.get("groups", [])))
