from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
import datetime

# Firewall Rule Schemas
class FirewallRuleBase(BaseModel):
    name: Optional[str] = None
    action: Optional[str] = None # ALLOW, DENY
    direction: Optional[str] = None # IN, OUT, BOTH
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None # TCP, UDP, ICMP, ANY
    is_active: Optional[bool] = None

class FirewallRuleResponse(FirewallRuleBase):
    id: int
    created_at: Optional[datetime.datetime] = None
    updated_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

class PaginatedFirewallRuleResponse(BaseModel):
    total: int
    rules: List[FirewallRuleResponse]

# IDS Rule Schemas
class IDSRuleBase(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    action: Optional[str] = None # alert, drop, etc.
    protocol: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[str] = None # Can be 'any' or a number
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None # Can be 'any' or a number
    pattern: Optional[str] = None
    content_modifiers: Optional[Dict[str, Any]] = None # JSON field
    threshold: Optional[int] = None
    window: Optional[int] = None
    active: Optional[bool] = None
    severity: Optional[str] = None # low, medium, high, critical

class IDSRuleResponse(IDSRuleBase):
    id: int
    created_at: Optional[datetime.datetime] = None
    updated_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

class PaginatedIDSRuleResponse(BaseModel):
    total: int
    rules: List[IDSRuleResponse]

# Threat Signature Rule Schemas
class ThreatSignatureRuleBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=100, description="Unique name for the signature rule")
    pattern: str = Field(..., min_length=1, description="The signature pattern to match (e.g., regex, string)")
    action: str = Field(default="alert", description="Action to take on match (e.g., alert, block)")
    severity: str = Field(default="medium", description="Severity of the threat (e.g., low, medium, high, critical)")
    description: Optional[str] = Field(None, max_length=255, description="Optional description for the rule")
    protocol: Optional[str] = Field(None, description="Protocol to match (e.g., TCP, UDP, HTTP)")
    is_active: bool = Field(default=True, description="Whether the rule is active")

class ThreatSignatureRuleCreate(ThreatSignatureRuleBase):
    pass

class ThreatSignatureRule(ThreatSignatureRuleBase):
    id: int
    created_at: datetime.datetime
    updated_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True
