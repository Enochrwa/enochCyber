from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from typing import List, Dict
from datetime import datetime, timedelta
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..services.detection.signature import SignatureEngine
from ..database import get_db
from ..models.log import NetworkLog
from ..models.user import User
from ..core.security import get_current_active_user
from ..utils.geo_utils import get_country_from_ip
from ..schemas.rule import ThreatSignatureRuleCreate # Added

router = APIRouter()
signature_engine = SignatureEngine()


@router.get("/", response_model=List[Dict])
async def get_threats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),  # Added
    limit: int = 100,
    severity: str = None,
    time_range: str = "24h",
):
    """Get detected threats with filtering options"""
    # Calculate time filter
    if time_range == "1h":
        time_filter = datetime.utcnow() - timedelta(hours=1)
    elif time_range == "24h":
        time_filter = datetime.utcnow() - timedelta(hours=24)
    elif time_range == "7d":
        time_filter = datetime.utcnow() - timedelta(days=7)
    else:
        time_filter = datetime.utcnow() - timedelta(hours=24)

    # Build base query
    stmt = (
        select(NetworkLog)
        .where(NetworkLog.timestamp >= time_filter)
        .order_by(desc(NetworkLog.timestamp))
    )

    # Apply severity filter if provided
    if severity:
        stmt = stmt.where(NetworkLog.threat_type.ilike(f"%{severity}%"))

    # Execute query
    result = await db.execute(stmt.limit(limit))
    threats = result.scalars().all()

    return [
        {
            "id": threat.id,
            "timestamp": threat.timestamp.isoformat(),
            "threat_type": threat.threat_type,
            "source_ip": threat.source_ip,
            "destination_ip": threat.destination_ip,
            "protocol": threat.protocol,
            "raw_data": (
                threat.raw_data[:500] + "..."
                if len(threat.raw_data) > 500
                else threat.raw_data
            ),
        }
        for threat in threats
    ]


@router.get("/rules/", response_model=List[Dict]) # Added trailing slash
async def get_signature_rules(current_user: User = Depends(get_current_active_user)):  # Added current_user
    """Get all signature-based detection rules"""
    return signature_engine.get_rules()


@router.post("/rules/")
async def add_signature_rule(rule: ThreatSignatureRuleCreate, current_user: User = Depends(get_current_active_user)):
    """Add a new signature rule"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")

    # Assuming signature_engine.add_rule expects a dict
    # The actual structure expected by signature_engine.add_rule might need adjustment
    # if it's not just a flat dictionary of these fields.
    if signature_engine.add_rule(rule.dict()):
        return JSONResponse(
            content={"status": "success", "message": "Rule added successfully"},
            status_code=status.HTTP_201_CREATED,
        )
    else:
        # Consider more specific error if add_rule returns False for known reasons (e.g. duplicate name)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to add rule. Invalid rule data or rule already exists.")


@router.get("/summary/", response_model=Dict)
async def get_threat_summary(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):  # Added current_user
    """Get threat summary statistics"""
    # Last 24 hours
    time_filter = datetime.utcnow() - timedelta(hours=24)

    # Total threats count
    total_result = await db.execute(
        select(func.count())
        .select_from(NetworkLog)
        .where(NetworkLog.timestamp >= time_filter)
    )
    total_threats = total_result.scalar_one()

    # Group by threat type
    threat_types_result = await db.execute(
        select(NetworkLog.threat_type, func.count(NetworkLog.id).label("count"))
        .where(NetworkLog.timestamp >= time_filter)
        .group_by(NetworkLog.threat_type)
    )
    threat_types = threat_types_result.all()

    return {
        "total_threats": total_threats,
        "threat_types": [{"type": t[0], "count": t[1]} for t in threat_types],
        "time_range": "24h",
    }


@router.get("/geolocated/", response_model=List[Dict]) # Added trailing slash
async def get_geolocated_threats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),  # Added
    limit: int = 100,
    hours: int = 24,
):
    """
    Get recent threats with geolocation data for their source IPs.
    Note: GeoLite2-Country database provides country-level accuracy.
    City and precise coordinates would require GeoLite2-City database.
    """
    time_filter = datetime.utcnow() - timedelta(hours=hours)

    # Fetch recent threats that likely have an external source IP
    # We might want to add more specific filtering here if possible,
    # e.g., to exclude private IP ranges if not relevant for geolocation.
    stmt = (
        select(
            NetworkLog.source_ip,
            NetworkLog.timestamp,
            NetworkLog.threat_type,
            NetworkLog.meta.op("->>")("severity").label("severity") # Example if severity is in a JSON meta field
            # If severity is a direct column: NetworkLog.severity
        )
        .where(NetworkLog.timestamp >= time_filter)
        .where(NetworkLog.source_ip.isnot(None)) # Ensure source_ip exists
        .order_by(desc(NetworkLog.timestamp))
        .limit(limit)
    )

    result = await db.execute(stmt)
    threats_from_db = result.all() # Using .all() to get all columns

    geolocated_threats = []
    for threat in threats_from_db:
        country = get_country_from_ip(threat.source_ip)

        # As GeoLite2-Country only provides country, lat/lon/city will be placeholders.
        # If GeoLite2-City were used, geo_utils would be updated to return these.
        geolocated_threats.append({
            "source_ip": threat.source_ip,
            "latitude": None,  # Placeholder - requires GeoLite2-City
            "longitude": None, # Placeholder - requires GeoLite2-City
            "city": None,      # Placeholder - requires GeoLite2-City
            "country": country,
            "timestamp": threat.timestamp.isoformat(),
            "threat_type": threat.threat_type,
            "severity": threat.severity if hasattr(threat, 'severity') and threat.severity else "Unknown" # Handle if severity is not always present
        })

    return geolocated_threats
