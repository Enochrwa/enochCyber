from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from app.services.monitoring.sniffer import PacketSniffer
from app.core.dependencies import get_packet_sniffer
from utils.get_system_info import get_system_info, get_network_interfaces
from ..models.user import User  # Added
from ..core.security import get_current_active_user  # Added

router = APIRouter()


@router.get("/stats/", response_model=dict) # Added trailing slash
async def get_system_stats(
    sniffer: PacketSniffer = Depends(get_packet_sniffer),
    current_user: User = Depends(get_current_active_user)  # Added
):
    """Get current system statistics"""
    # The get_packet_sniffer dependency might already handle auth.
    # Adding current_user here for explicit protection of this endpoint.
    if not current_user.is_superuser: # Or a different role if some stats are non-sensitive
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required for system stats")
    return sniffer.get_stats()


@router.get("/system_info/") # Added trailing slash
def system_status(current_user: User = Depends(get_current_active_user)):  # Added current_user
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")
    return get_system_info()

@router.get("/interfaces/") # Added trailing slash
def get_interfaces(current_user: User = Depends(get_current_active_user)):  # Added current_user
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")
    return get_network_interfaces()
