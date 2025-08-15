"""
Database models for ScamSwatter
"""
from .scam import ScamReport, Location, DataSource, ScamCategory, UserReport

__all__ = [
    "ScamReport",
    "Location", 
    "DataSource",
    "ScamCategory",
    "UserReport"
]
