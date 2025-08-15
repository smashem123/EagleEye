"""
CRUD operations for scam-related database models
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
from app.models.scam import ScamReport, Location, DataSource, UserReport
from app.schemas.scam import (
    ScamReportCreate, 
    ScamReportUpdate, 
    UserReportCreate,
    ScamFeedQuery
)


class ScamReportCRUD:
    """CRUD operations for ScamReport model"""
    
    def create(self, db: Session, *, obj_in: ScamReportCreate) -> ScamReport:
        """Create a new scam report"""
        db_obj = ScamReport(**obj_in.dict())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj
    
    def get(self, db: Session, id: int) -> Optional[ScamReport]:
        """Get scam report by ID"""
        return db.query(ScamReport).filter(ScamReport.id == id).first()
    
    def get_multi(
        self, 
        db: Session, 
        *, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[ScamReport]:
        """Get multiple scam reports with pagination"""
        return (
            db.query(ScamReport)
            .order_by(desc(ScamReport.created_at))
            .offset(skip)
            .limit(limit)
            .all()
        )
    
    def get_feed(
        self, 
        db: Session, 
        *, 
        query_params: ScamFeedQuery
    ) -> Dict[str, Any]:
        """Get scam feed with advanced filtering"""
        
        # Base query
        base_query = db.query(ScamReport)
        
        # Apply filters
        filters = []
        
        # Time filter
        if query_params.hours_back:
            time_threshold = datetime.utcnow() - timedelta(hours=query_params.hours_back)
            filters.append(ScamReport.created_at >= time_threshold)
        
        # Scam type filter
        if query_params.scam_type:
            filters.append(ScamReport.scam_type == query_params.scam_type)
        
        # Severity filter
        if query_params.min_severity is not None:
            filters.append(ScamReport.severity_score >= query_params.min_severity)
        
        # Verification filter
        if query_params.verified_only:
            filters.append(ScamReport.is_verified == True)
        
        # Location filters (join with Location table)
        location_filters = []
        if query_params.country:
            location_filters.append(Location.country == query_params.country)
        if query_params.state_province:
            location_filters.append(Location.state_province == query_params.state_province)
        if query_params.city:
            location_filters.append(Location.city == query_params.city)
        
        if location_filters:
            base_query = base_query.join(Location)
            filters.extend(location_filters)
        
        # Apply all filters
        if filters:
            base_query = base_query.filter(and_(*filters))
        
        # Get total count
        total_count = base_query.count()
        
        # Apply pagination and ordering
        scams = (
            base_query
            .order_by(desc(ScamReport.created_at))
            .offset(query_params.offset)
            .limit(query_params.limit)
            .all()
        )
        
        return {
            "scams": scams,
            "total_count": total_count,
            "page_info": {
                "limit": query_params.limit,
                "offset": query_params.offset,
                "has_next": (query_params.offset + query_params.limit) < total_count,
                "has_prev": query_params.offset > 0
            },
            "filters_applied": query_params.dict(exclude_unset=True)
        }
    
    def update(
        self, 
        db: Session, 
        *, 
        db_obj: ScamReport, 
        obj_in: ScamReportUpdate
    ) -> ScamReport:
        """Update a scam report"""
        update_data = obj_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_obj, field, value)
        
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj
    
    def delete(self, db: Session, *, id: int) -> ScamReport:
        """Delete a scam report"""
        obj = db.query(ScamReport).get(id)
        db.delete(obj)
        db.commit()
        return obj
    
    def get_by_source_reference(
        self, 
        db: Session, 
        *, 
        source_id: int, 
        source_reference: str
    ) -> Optional[ScamReport]:
        """Get scam report by source and external reference ID"""
        return (
            db.query(ScamReport)
            .filter(
                and_(
                    ScamReport.source_id == source_id,
                    ScamReport.source_reference == source_reference
                )
            )
            .first()
        )
    
    def get_recent_by_type(
        self, 
        db: Session, 
        *, 
        scam_type: str, 
        hours: int = 24, 
        limit: int = 50
    ) -> List[ScamReport]:
        """Get recent scams by type"""
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        return (
            db.query(ScamReport)
            .filter(
                and_(
                    ScamReport.scam_type == scam_type,
                    ScamReport.created_at >= time_threshold
                )
            )
            .order_by(desc(ScamReport.created_at))
            .limit(limit)
            .all()
        )


class LocationCRUD:
    """CRUD operations for Location model"""
    
    def create(self, db: Session, *, location_data: Dict[str, Any]) -> Location:
        """Create a new location"""
        db_obj = Location(**location_data)
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj
    
    def get_or_create(self, db: Session, *, location_data: Dict[str, Any]) -> Location:
        """Get existing location or create new one"""
        # Try to find existing location
        query = db.query(Location)
        
        if location_data.get("country"):
            query = query.filter(Location.country == location_data["country"])
        if location_data.get("state_province"):
            query = query.filter(Location.state_province == location_data["state_province"])
        if location_data.get("city"):
            query = query.filter(Location.city == location_data["city"])
        if location_data.get("postal_code"):
            query = query.filter(Location.postal_code == location_data["postal_code"])
        
        existing = query.first()
        if existing:
            return existing
        
        # Create new location if not found
        return self.create(db, location_data=location_data)


class DataSourceCRUD:
    """CRUD operations for DataSource model"""
    
    def get_active_sources(self, db: Session) -> List[DataSource]:
        """Get all active data sources"""
        return (
            db.query(DataSource)
            .filter(DataSource.is_active == True)
            .all()
        )
    
    def update_sync_status(
        self, 
        db: Session, 
        *, 
        source_id: int, 
        success: bool, 
        error_message: Optional[str] = None
    ) -> DataSource:
        """Update sync status for a data source"""
        source = db.query(DataSource).get(source_id)
        if source:
            source.last_sync = datetime.utcnow()
            if success:
                source.last_successful_sync = datetime.utcnow()
                source.is_healthy = True
                source.error_count = 0
                source.last_error = None
            else:
                source.error_count += 1
                source.last_error = error_message
                # Mark as unhealthy after 3 consecutive failures
                if source.error_count >= 3:
                    source.is_healthy = False
            
            db.add(source)
            db.commit()
            db.refresh(source)
        
        return source


class UserReportCRUD:
    """CRUD operations for UserReport model"""
    
    def create(self, db: Session, *, obj_in: UserReportCreate) -> UserReport:
        """Create a new user report"""
        db_obj = UserReport(**obj_in.dict())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj
    
    def get_pending_verification(self, db: Session, *, limit: int = 50) -> List[UserReport]:
        """Get user reports pending verification"""
        return (
            db.query(UserReport)
            .filter(UserReport.is_verified == False)
            .order_by(desc(UserReport.created_at))
            .limit(limit)
            .all()
        )
    
    def upvote(self, db: Session, *, report_id: int) -> UserReport:
        """Add upvote to user report"""
        report = db.query(UserReport).get(report_id)
        if report:
            report.upvotes += 1
            db.add(report)
            db.commit()
            db.refresh(report)
        return report
    
    def downvote(self, db: Session, *, report_id: int) -> UserReport:
        """Add downvote to user report"""
        report = db.query(UserReport).get(report_id)
        if report:
            report.downvotes += 1
            db.add(report)
            db.commit()
            db.refresh(report)
        return report


# Create instances
scam_report = ScamReportCRUD()
location = LocationCRUD()
data_source = DataSourceCRUD()
user_report = UserReportCRUD()
