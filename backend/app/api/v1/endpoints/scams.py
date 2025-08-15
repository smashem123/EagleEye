"""
API endpoints for scam intelligence data
"""
from typing import List, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.crud import scam_report, user_report
from app.schemas.scam import (
    ScamReport,
    ScamReportCreate,
    ScamReportUpdate,
    UserReport,
    UserReportCreate,
    ScamFeedQuery,
    ScamFeedResponse
)

router = APIRouter()


@router.get("/feed", response_model=ScamFeedResponse)
def get_scam_feed(
    *,
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=500, description="Number of scams to return"),
    offset: int = Query(0, ge=0, description="Number of scams to skip"),
    scam_type: str = Query(None, description="Filter by scam type"),
    country: str = Query(None, description="Filter by country"),
    state_province: str = Query(None, description="Filter by state/province"),
    city: str = Query(None, description="Filter by city"),
    min_severity: float = Query(None, ge=0.0, le=10.0, description="Minimum severity score"),
    verified_only: bool = Query(False, description="Only return verified scams"),
    hours_back: int = Query(24, ge=1, le=168, description="Hours back to search (max 1 week)")
) -> Any:
    """
    Get live scam feed with filtering options
    """
    query_params = ScamFeedQuery(
        limit=limit,
        offset=offset,
        scam_type=scam_type,
        country=country,
        state_province=state_province,
        city=city,
        min_severity=min_severity,
        verified_only=verified_only,
        hours_back=hours_back
    )
    
    result = scam_report.get_feed(db, query_params=query_params)
    
    return ScamFeedResponse(
        scams=result["scams"],
        total_count=result["total_count"],
        page_info=result["page_info"],
        filters_applied=result["filters_applied"]
    )


@router.get("/{scam_id}", response_model=ScamReport)
def get_scam(
    *,
    db: Session = Depends(get_db),
    scam_id: int
) -> Any:
    """
    Get specific scam by ID
    """
    scam = scam_report.get(db, id=scam_id)
    if not scam:
        raise HTTPException(status_code=404, detail="Scam not found")
    return scam


@router.get("/", response_model=List[ScamReport])
def get_scams(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
) -> Any:
    """
    Get scams with basic pagination
    """
    scams = scam_report.get_multi(db, skip=skip, limit=limit)
    return scams


@router.post("/", response_model=ScamReport)
def create_scam(
    *,
    db: Session = Depends(get_db),
    scam_in: ScamReportCreate
) -> Any:
    """
    Create new scam report (for data ingestion services)
    """
    scam = scam_report.create(db, obj_in=scam_in)
    return scam


@router.put("/{scam_id}", response_model=ScamReport)
def update_scam(
    *,
    db: Session = Depends(get_db),
    scam_id: int,
    scam_in: ScamReportUpdate
) -> Any:
    """
    Update scam report
    """
    scam = scam_report.get(db, id=scam_id)
    if not scam:
        raise HTTPException(status_code=404, detail="Scam not found")
    
    scam = scam_report.update(db, db_obj=scam, obj_in=scam_in)
    return scam


@router.get("/type/{scam_type}", response_model=List[ScamReport])
def get_scams_by_type(
    *,
    db: Session = Depends(get_db),
    scam_type: str,
    hours: int = Query(24, ge=1, le=168, description="Hours back to search"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of results")
) -> Any:
    """
    Get recent scams by type
    """
    scams = scam_report.get_recent_by_type(
        db, scam_type=scam_type, hours=hours, limit=limit
    )
    return scams


# User-submitted reports endpoints
@router.post("/reports/", response_model=UserReport)
def submit_user_report(
    *,
    db: Session = Depends(get_db),
    report_in: UserReportCreate
) -> Any:
    """
    Submit a community scam report
    """
    report = user_report.create(db, obj_in=report_in)
    return report


@router.get("/reports/pending", response_model=List[UserReport])
def get_pending_reports(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200)
) -> Any:
    """
    Get user reports pending verification (admin endpoint)
    """
    reports = user_report.get_pending_verification(db, limit=limit)
    return reports


@router.post("/reports/{report_id}/upvote", response_model=UserReport)
def upvote_report(
    *,
    db: Session = Depends(get_db),
    report_id: int
) -> Any:
    """
    Upvote a user report
    """
    report = user_report.upvote(db, report_id=report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.post("/reports/{report_id}/downvote", response_model=UserReport)
def downvote_report(
    *,
    db: Session = Depends(get_db),
    report_id: int
) -> Any:
    """
    Downvote a user report
    """
    report = user_report.downvote(db, report_id=report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
