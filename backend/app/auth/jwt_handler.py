from datetime import datetime, timedelta
from typing import Optional
import hashlib
import logging
import secrets
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from app.config import settings
from app import db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class User(BaseModel):
    username: str
    email: str
    role: str
    full_name: str
    disabled: Optional[bool] = False
    must_reset_password: Optional[bool] = False

def get_password_hash(password: str) -> str:
    """Secure PBKDF2-HMAC-SHA256 password hashing (independent of bcrypt/passlib version bugs)"""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against PBKDF2 hashed password"""
    try:
        salt, key = hashed_password.split("$")
        check_key = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return secrets.compare_digest(key, check_key.hex())
    except Exception:
        return False

DEFAULT_ACCOUNTS_CONFIG = [
    {
        "username": settings.ADMIN_USERNAME or "soc_admin",
        "full_name": "SOC Lead Engineer",
        "email": "soc-admin@cybersecurity.corp",
        "role": "admin",
    },
    {
        "username": "analyst",
        "full_name": "Tier-2 SOC Analyst",
        "email": "analyst@cybersecurity.corp",
        "role": "analyst",
    },
    {
        "username": "tier1_analyst",
        "full_name": "Tier-1 SOC Investigator",
        "email": "tier1@cybersecurity.corp",
        "role": "analyst",
    },
]

def init_default_users() -> None:
    """
    Seed the default accounts, once, on first run against an empty database.

    Accounts now live in SQLite, so this is genuinely a first-run action: after the
    initial seed the accounts and their chosen passwords survive restarts, and no
    new temporary credentials are printed. Previously the store was a dict, so every
    restart reseeded and reprinted fresh passwords, silently invalidating whatever
    the user had set.
    """
    auth_logger = logging.getLogger("warden.auth")
    db.init_db()

    newly_generated = []
    for account in DEFAULT_ACCOUNTS_CONFIG:
        username = account["username"]
        if not db.user_exists(username):
            raw_password = secrets.token_urlsafe(12)
            db.create_user(
                username=username,
                hashed_password=get_password_hash(raw_password),
                role=account["role"],
                full_name=account["full_name"],
                email=account["email"],
                must_reset_password=True,
            )
            newly_generated.append((username, account["role"], raw_password))

    if newly_generated:
        banner = "\n" + "=" * 80 + "\n"
        banner += "[SECURITY NOTICE] New accounts created with random temporary credentials.\n"
        banner += "Each user MUST reset their password on first login via the portal.\n"
        banner += "These are shown once and are not recoverable from the database.\n"
        banner += "-" * 80 + "\n"
        for username, role, pwd in newly_generated:
            banner += f"  Username: {username:<18} | Role: {role:<10} | Temporary Password: {pwd}\n"
        banner += "=" * 80 + "\n"
        auth_logger.warning(banner)
        try:
            print(banner)
        except Exception:
            pass
    else:
        auth_logger.info("User accounts loaded from the database; no new credentials issued.")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def require_role(*allowed_roles: str):
    """
    Dependency that gates an endpoint on the caller's role.

    Roles were defined and issued from the start but never checked, so any
    authenticated account could execute containment actions or change platform
    settings. The role is read from the user store inside get_current_user, so a
    forged claim in the token cannot satisfy this check.
    """
    async def _guard(current_user: "User" = Depends(get_current_user)) -> "User":
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This action requires one of the following roles: "
                    f"{', '.join(allowed_roles)}. Your role is '{current_user.role}'."
                ),
            )
        return current_user
    return _guard


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "analyst")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
        
    user_dict = db.get_user(token_data.username)
    if user_dict is None:
        # A validly-signed token for an unknown subject is NOT a valid session. Previously
        # this branch fabricated a User from the token's own claims, which meant anyone able
        # to mint a token (e.g. with a default or leaked SECRET_KEY) could authenticate as
        # any username with any role. External SSO, if added later, must provision the user
        # into the store at login rather than being trusted to assert identity here.
        auth_logger = logging.getLogger("warden.auth")
        auth_logger.warning(
            f"Rejected token for unknown subject '{token_data.username}' "
            f"(claimed role '{token_data.role}'). Possible forged token."
        )
        raise credentials_exception

    if user_dict.get("disabled", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")

    # Role comes from the user store, never from the token, so a tampered or stale claim
    # cannot escalate privileges. Build explicitly so storage columns such as
    # hashed_password never leak into an API response model.
    return User(
        username=user_dict["username"],
        email=user_dict.get("email", ""),
        role=user_dict.get("role", "analyst"),
        full_name=user_dict.get("full_name", ""),
        disabled=user_dict.get("disabled", False),
        must_reset_password=user_dict.get("must_reset_password", False),
    )
