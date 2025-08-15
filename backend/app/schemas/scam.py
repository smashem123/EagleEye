"""
Pydantic schemas for API request/response validation
"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator


class LocationBase(BaseModel):
    country: Optional[str] = None
    state_province: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class LocationCreate(LocationBase):
    pass


class Location(LocationBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True


class DataSourceBase(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = None
    api_endpoint: Optional[str] = None
    api_key_required: bool = False
    rate_limit_per_hour: int = 1000
    sync_frequency_minutes: int = 30
    is_active: bool = True


class DataSourceCreate(DataSourceBase):
    pass


class DataSource(DataSourceBase):
    id: int
    last_sync: Optional[datetime] = None
    last_successful_sync: Optional[datetime] = None
    is_healthy: bool = True
    error_count: int = 0
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True


class ScamReportBase(BaseModel):
    title: str = Field(..., max_length=500)
    description: Optional[str] = None
    scam_type: str = Field(..., max_length=100)
    severity_score: float = Field(0.0, ge=0.0, le=10.0)
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    urls: Optional[List[str]] = None
    phone_numbers: Optional[List[str]] = None
    email_addresses: Optional[List[str]] = None
    first_reported: datetime
    
    @validator('urls', 'phone_numbers', 'email_addresses', pre=True)
    def validate_lists(cls, v):
        if v is None:
            return []
        return v


class ScamReportCreate(ScamReportBase):
    source_id: int
    location_id: Optional[int] = None


class ScamReportUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    scam_type: Optional[str] = Field(None, max_length=100)
    severity_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    is_verified: Optional[bool] = None
    urls: Optional[List[str]] = None
    phone_numbers: Optional[List[str]] = None
    email_addresses: Optional[List[str]] = None


class ScamReport(ScamReportBase):
    id: int
    source_id: int
    location_id: Optional[int] = None
    source_reference: Optional[str] = None
    is_verified: bool = False
    last_updated: datetime
    created_at: datetime
    
    # Related objects
    source: Optional[DataSource] = None
    location: Optional[Location] = None
    
    class Config:
        orm_mode = True


class UserReportBase(BaseModel):
    title: str = Field(..., max_length=500)
    description: str
    scam_type: str = Field(..., max_length=100)
    reported_url: Optional[str] = Field(None, max_length=1000)
    reported_phone: Optional[str] = Field(None, max_length=50)
    reported_email: Optional[str] = Field(None, max_length=255)
    reporter_email: Optional[str] = Field(None, max_length=255)
    reporter_location: Optional[str] = Field(None, max_length=255)


class UserReportCreate(UserReportBase):
    pass


class UserReport(UserReportBase):
    id: int
    is_verified: bool = False
    verification_notes: Optional[str] = None
    upvotes: int = 0
    downvotes: int = 0
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True


class ScamFeedQuery(BaseModel):
    """Query parameters for scam feed endpoint"""
    limit: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0)
    scam_type: Optional[str] = None
    country: Optional[str] = None
    state_province: Optional[str] = None
    city: Optional[str] = None
    min_severity: Optional[float] = Field(None, ge=0.0, le=10.0)
    verified_only: bool = False
    hours_back: Optional[int] = Field(24, ge=1, le=168)  # Max 1 week back


class ScamFeedResponse(BaseModel):
    """Response format for scam feed"""
    scams: List[ScamReport]
    total_count: int
    page_info: Dict[str, Any]
    filters_applied: Dict[str, Any]
