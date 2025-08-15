"""
API source integrations for ScamSwatter CLI
"""
from .base import ScamSource, ScamSourceError
from .phishtank import PhishTankSource
from .urlvoid import URLVoidSource
from .mock import MockSource

__all__ = [
    "ScamSource",
    "ScamSourceError", 
    "PhishTankSource",
    "URLVoidSource",
    "MockSource"
]
