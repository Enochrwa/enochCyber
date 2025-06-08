from fastapi import Depends
from app.services.monitoring.sniffer import PacketSniffer
from app.services.prevention.firewall import FirewallManager
from app.services.detection.signature import SignatureEngine
from app.database import get_db
from fastapi import Request

# app/dependencies.py
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import AsyncSessionLocal




def get_packet_sniffer(request: Request) -> PacketSniffer:
    """Get the packet sniffer instance"""
    return request.app.state.sniffer


def get_firewall(request: Request) -> FirewallManager:
    """Get the firewall manager instance"""
    return request.app.state.firewall


def get_signature_engine(request: Request) -> SignatureEngine:
    """Get the signature engine instance"""
    return request.app.state.signature_engine

from redis.asyncio import Redis as AsyncRedis # Or just Redis if using older redis-py

async def get_redis_client(request: Request) -> AsyncRedis:
    if not hasattr(request.app.state, 'redis_client') or request.app.state.redis_client is None:
        raise RuntimeError("Redis client not available in app state. Ensure it's initialized in main.py lifespan.")
    return request.app.state.redis_client
