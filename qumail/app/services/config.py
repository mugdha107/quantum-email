import os
from dataclasses import dataclass
from dotenv import load_dotenv


@dataclass
class KMConfig:
    base_url: str
    client_id: str
    peer_id: str
    default_key_length: int
    integrity_secret: str


@dataclass
class SMTPConfig:
    host: str
    port: int
    username: str
    password: str
    use_starttls: bool


@dataclass
class IMAPConfig:
    host: str
    port: int
    username: str
    password: str
    use_ssl: bool


@dataclass
class AppConfig:
    log_level: str
    km: KMConfig
    smtp: SMTPConfig
    imap: IMAPConfig
    key_cache_path: str
    key_cache_password: str
    use_cached_when_offline: bool
    db_path: str


def load_config() -> AppConfig:
    load_dotenv()
    km = KMConfig(
        base_url=os.getenv("KM_BASE_URL", "http://127.0.0.1:5001"),
        client_id=os.getenv("KM_CLIENT_ID", "Alice"),
        peer_id=os.getenv("KM_PEER_ID", "Bob"),
        default_key_length=int(os.getenv("KM_DEFAULT_KEY_LENGTH", "4096")),
        integrity_secret=os.getenv("KM_INTEGRITY_SECRET", "change_this_demo_secret"),
    )
    smtp = SMTPConfig(
        host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
        port=int(os.getenv("SMTP_PORT", "587")),
        username=os.getenv("SMTP_USERNAME", ""),
        password=os.getenv("SMTP_PASSWORD", ""),
        use_starttls=os.getenv("SMTP_USE_STARTTLS", "true").lower() == "true",
    )
    imap = IMAPConfig(
        host=os.getenv("IMAP_HOST", "imap.gmail.com"),
        port=int(os.getenv("IMAP_PORT", "993")),
        username=os.getenv("IMAP_USERNAME", ""),
        password=os.getenv("IMAP_PASSWORD", ""),
        use_ssl=os.getenv("IMAP_USE_SSL", "true").lower() == "true",
    )
    return AppConfig(
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        km=km,
        smtp=smtp,
        imap=imap,
        key_cache_path=os.getenv("KEY_CACHE_PATH", ".qumail_cache.json"),
        key_cache_password=os.getenv("KEY_CACHE_PASSWORD", "change_this_cache_password"),
        use_cached_when_offline=os.getenv("USE_CACHED_KEYS_WHEN_OFFLINE", "true").lower() == "true",
        db_path=os.getenv("DB_PATH", ".qumail.db"),
    )
