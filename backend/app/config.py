import logging as _logging
from pydantic_settings import BaseSettings
from typing import Optional, List

class Settings(BaseSettings):
    # Application Config
    APP_NAME: str = "Warden"
    APP_ENV: str = "production"
    DEBUG: bool = False
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    # "*" combined with allow_credentials lets any website drive this API using a
    # logged-in analyst's session. Default to the local dev origins and set explicitly
    # for any real deployment.
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # JWT Authentication
    # No usable default: a shipped signing key is a public key. Blank here means
    # "generate an ephemeral one for local dev" and "refuse to start" in production.
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12 # 12 hours
    ADMIN_USERNAME: str = "soc_admin"
    ADMIN_PASSWORD: Optional[str] = "SentinelAdmin2026!"
    
    # Azure Sentinel & Azure Resource Manager Config
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    AZURE_RESOURCE_GROUP_NAME: Optional[str] = None
    AZURE_WORKSPACE_NAME: Optional[str] = None
    AZURE_WORKSPACE_ID: Optional[str] = None # Log Analytics Workspace ID
    USE_MANAGED_IDENTITY: bool = False
    
    # Durable storage. Relative paths resolve against backend/, so the working
    # directory does not decide where the database lives. Mount this path as a
    # volume in Docker/Kubernetes or the data is lost with the container.
    DATABASE_PATH: str = "data/soc_agent.db"

    # Simulation / Demo Mode (allows running standalone without live Azure credentials)
    DEMO_MODE: bool = True
    
    # LLM Settings (Supports Azure OpenAI, OpenAI, or compatible APIs)
    LLM_PROVIDER: str = "azure_openai" # "azure_openai", "openai", "custom"
    OPENAI_API_KEY: Optional[str] = None
    AZURE_OPENAI_ENDPOINT: Optional[str] = None
    AZURE_OPENAI_API_KEY: Optional[str] = None
    AZURE_OPENAI_API_VERSION: str = "2024-02-15-preview"
    AZURE_OPENAI_DEPLOYMENT_NAME: str = ""
    # When enabled the model writes its own KQL and follows leads, instead of
    # summarising a fixed set of hunts. Costs more tokens per incident.
    ENABLE_ADAPTIVE_INVESTIGATION: bool = True
    LLM_ROUTING_MODE: str = "hybrid" # "hybrid", "always_mini", "always_astra"
    FAST_MODEL_NAME: str = ""
    REASONING_MODEL_NAME: str = ""
    
    # Threat Intelligence API Keys & Providers
    ABUSEIPDB_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ENABLE_MICROSOFT_THREAT_INTEL: bool = True
    MDTI_API_KEY: Optional[str] = None
    
    # Auto-Triage & Polling Settings
    ENABLE_AUTO_POLLING: bool = False
    POLL_INTERVAL_SECONDS: int = 120
    AUTO_POST_COMMENTS_TO_SENTINEL: bool = True
    AUTO_CLOSE_FALSE_POSITIVES: bool = False
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()


# ---------------------------------------------------------------------------
# JWT signing key safety
#
# Any signing key committed to a public repository is known to everyone who has
# read it, and anyone holding it can mint a token for any username and role. The
# values below have all shipped in this repo at some point (config default,
# .env.example, docker-compose.yml, aks/secret.yaml), so they are treated as
# compromised regardless of where they are set.
# ---------------------------------------------------------------------------
_PUBLICLY_KNOWN_KEYS = {
    "",
    "sentinel-super-secret-key-change-in-production-2026",
    "replace-with-a-secure-random-secret-key-in-production",
    "change-to-a-secure-random-secret-key-for-jwt",
}

if settings.SECRET_KEY.strip() in _PUBLICLY_KNOWN_KEYS:
    if settings.APP_ENV.strip().lower() in {"production", "prod", "staging"}:
        raise RuntimeError(
            "SECRET_KEY is unset or set to a value published in this repository, and "
            f"APP_ENV is '{settings.APP_ENV}'. Refusing to start: anyone with the public "
            "key could forge an admin session. Generate one with\n"
            "    python -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
            "and set SECRET_KEY in your environment or .env file."
        )

    # Non-production: run, but with a per-process random key rather than a known one.
    # Tokens do not survive a restart, which matches the in-memory user store anyway.
    import secrets as _secrets

    settings.SECRET_KEY = _secrets.token_urlsafe(48)
    _logging.getLogger("warden.config").warning(
        "SECRET_KEY was not set. Generated an ephemeral development key; all sessions "
        "will be invalidated on restart. Set SECRET_KEY in .env for a stable key."
    )
