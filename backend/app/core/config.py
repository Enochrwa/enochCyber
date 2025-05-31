import os
import psutil
from scapy.all import get_if_list
import logging
from pydantic import AnyHttpUrl
from typing import List
from pydantic_settings import BaseSettings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_default_network_interface():
    """Dynamically determines the default network interface."""
    try:
        interfaces = psutil.net_if_addrs()
        scapy_interfaces = get_if_list() # Get scapy's list for cross-reference if needed

        priority_interfaces = ['Ethernet', 'Wi-Fi', 'en0', 'eth0']

        # First pass: Look for priority interfaces that are up and have an IP
        for name in priority_interfaces:
            if name in interfaces:
                for addr in interfaces[name]:
                    if addr.family == psutil.AF_LINK: # Check link layer status
                        stats = psutil.net_if_stats().get(name)
                        if stats and stats.isup:
                             # Check for IP address
                            for snicaddr in interfaces[name]:
                                if snicaddr.family == psutil.AF_INET or snicaddr.family == psutil.AF_INET6: # AF_INET is IPv4, AF_INET6 is IPv6
                                    logger.info(f"Priority interface found: {name}")
                                    return name

        # Second pass: Look for any non-loopback interface that is up and has an IP
        for name, addrs in interfaces.items():
            stats = psutil.net_if_stats().get(name)
            if stats and stats.isup and not stats.flags & psutil.IFF_LOOPBACK:
                for addr in addrs:
                    if addr.family == psutil.AF_INET or addr.family == psutil.AF_INET6:
                        logger.info(f"Fallback interface found: {name}")
                        return name

        logger.warning("No suitable network interface found. Falling back to default.")
    except Exception as e:
        logger.error(f"Error detecting network interface: {e}. Falling back to default.")

    # Last resort fallback
    if "eth0" in get_if_list():
        return "eth0"
    if "Wi-Fi" in get_if_list():
        return "Wi-Fi"
    return "eth0" # Absolute fallback if no specific interface is detected by Scapy either

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cybersecurity Monitoring System"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Real-time network threat detection API"

    DATABASE_NAME: str = "security.db"
    ECYBER_DATA_PATH: str = os.environ.get("ECYBER_DATA_PATH")

    if ECYBER_DATA_PATH:
        SQLALCHEMY_DATABASE_URL: str = f"sqlite+aiosqlite:///{os.path.join(ECYBER_DATA_PATH, DATABASE_NAME)}"
    else:
        SQLALCHEMY_DATABASE_URL: str = f"sqlite+aiosqlite:///./{DATABASE_NAME}"

    # For PostgreSQL use:
    # DATABASE_URL: PostgresDsn = "postgresql+asyncpg://user:password@localhost/dbname"

    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    REQUIRE_SOCKET_AUTH: bool = True
    # PROJECT_NAME is already defined above, ensure it's not duplicated if merged from old.
    # PROJECT_NAME: str = "CyberWatch" # This line seems redundant or conflicting
    NETWORK_INTERFACE: str = get_default_network_interface()
    DEBUG: bool = False
    DOCS: bool = False  # Disable in production
    PRODUCTION: bool = True

    # Redis for production scaling
    REDIS_URL: str = "redis://localhost:6379/0"

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
