"""
API source integrations for EagleEye CLI

This module provides various data sources for scam intelligence:
- Base classes and interfaces
- Mock/test sources  
- Phishing databases (OpenPhish, URLVoid, PyOpenDB)
- Government APIs (FTC, FCC)
"""

# Base classes
from .base import ScamSource, ScamSourceError

# Mock and test sources
from .mock import MockSource

# Phishing and malware databases
from .openphish import OpenPhishSource
from .urlvoid import URLVoidSource
from .pyopdb import PyOpenPhishDB

# Government data sources
from .ftc_dnc import FTCDNCClient, FTCComplaint
from .fcc_complaints import FCCComplaintsClient, FCCComplaint

__all__ = [
    # Base classes
    'ScamSource',
    'ScamSourceError',
    
    # Mock sources
    'MockSource',
    
    # Phishing databases
    'OpenPhishSource',
    'URLVoidSource', 
    'PyOpenPhishDB',
    
    # Government sources
    'FTCDNCClient',
    'FTCComplaint',
    'FCCComplaintsClient',
    'FCCComplaint',
]
