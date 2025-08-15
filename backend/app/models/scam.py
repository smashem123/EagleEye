"""
Database models for scam intelligence data
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class ScamReport(Base):
    """Main table for storing scam reports from various sources"""
    __tablename__ = "scam_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Basic scam information
    title = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=True)
    scam_type = Column(String(100), nullable=False, index=True)  # phishing, robocall, fake_website, etc.
    
    # Source information
    source_id = Column(Integer, ForeignKey("data_sources.id"), nullable=False)
    source_reference = Column(String(255), nullable=True)  # External ID from source API
    
    # Location data
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=True)
    
    # Threat assessment
    severity_score = Column(Float, default=0.0)  # 0-10 scale
    confidence_score = Column(Float, default=0.0)  # 0-1 scale
    is_verified = Column(Boolean, default=False)
    
    # URLs and contact info involved in scam
    urls = Column(JSON, nullable=True)  # List of malicious URLs
    phone_numbers = Column(JSON, nullable=True)  # List of scam phone numbers
    email_addresses = Column(JSON, nullable=True)  # List of scam emails
    
    # Metadata
    first_reported = Column(DateTime(timezone=True), nullable=False)
    last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    source = relationship("DataSource", back_populates="scam_reports")
    location = relationship("Location", back_populates="scam_reports")


class Location(Base):
    """Geographic location data for scam reports"""
    __tablename__ = "locations"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Geographic identifiers
    country = Column(String(100), nullable=True, index=True)
    state_province = Column(String(100), nullable=True, index=True)
    city = Column(String(100), nullable=True, index=True)
    postal_code = Column(String(20), nullable=True, index=True)
    
    # Coordinates for mapping
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scam_reports = relationship("ScamReport", back_populates="location")


class DataSource(Base):
    """Configuration and tracking for external data sources"""
    __tablename__ = "data_sources"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Source identification
    name = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    api_endpoint = Column(String(500), nullable=True)
    
    # API configuration
    api_key_required = Column(Boolean, default=False)
    rate_limit_per_hour = Column(Integer, default=1000)
    
    # Sync tracking
    last_sync = Column(DateTime(timezone=True), nullable=True)
    last_successful_sync = Column(DateTime(timezone=True), nullable=True)
    sync_frequency_minutes = Column(Integer, default=30)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_healthy = Column(Boolean, default=True)
    error_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    scam_reports = relationship("ScamReport", back_populates="source")


class ScamCategory(Base):
    """Predefined categories for scam classification"""
    __tablename__ = "scam_categories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    parent_category_id = Column(Integer, ForeignKey("scam_categories.id"), nullable=True)
    
    # Display properties
    color_hex = Column(String(7), default="#FF6B6B")  # For UI visualization
    icon_name = Column(String(50), default="alert-triangle")
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Self-referential relationship for subcategories
    parent = relationship("ScamCategory", remote_side=[id], backref="subcategories")


class UserReport(Base):
    """Community-submitted scam reports"""
    __tablename__ = "user_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Report content
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    scam_type = Column(String(100), nullable=False)
    
    # Contact information involved
    reported_url = Column(String(1000), nullable=True)
    reported_phone = Column(String(50), nullable=True)
    reported_email = Column(String(255), nullable=True)
    
    # Reporter information (optional/anonymous)
    reporter_email = Column(String(255), nullable=True)
    reporter_location = Column(String(255), nullable=True)
    
    # Verification status
    is_verified = Column(Boolean, default=False)
    verification_notes = Column(Text, nullable=True)
    upvotes = Column(Integer, default=0)
    downvotes = Column(Integer, default=0)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
