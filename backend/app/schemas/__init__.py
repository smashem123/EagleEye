"""
Pydantic schemas for ScamSwatter API
"""
from .scam import (
    Location,
    LocationCreate,
    DataSource,
    DataSourceCreate,
    ScamReport,
    ScamReportCreate,
    ScamReportUpdate,
    UserReport,
    UserReportCreate,
    ScamFeedQuery,
    ScamFeedResponse
)

__all__ = [
    "Location",
    "LocationCreate",
    "DataSource", 
    "DataSourceCreate",
    "ScamReport",
    "ScamReportCreate",
    "ScamReportUpdate",
    "UserReport",
    "UserReportCreate",
    "ScamFeedQuery",
    "ScamFeedResponse"
]
