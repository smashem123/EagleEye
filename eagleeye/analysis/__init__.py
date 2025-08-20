"""
Text analysis and NLP modules for EagleEye
Real-time scam content detection and analysis
"""
from .text_analyzer import TextAnalyzer, ScamTextResult
from .content_scraper import ContentScraper
from .nlp_pipeline import NLPPipeline
from .voice_analyzer import VoiceAnalyzer
from .caller_id import CallerIDVerifier, CallerIDResult
from .link_scanner import LinkScanner, LinkScanResult
from .geolocation import GeolocationService, LocationData
from .trend_analyzer import TrendAnalyzer, TrendData, HotspotData

__all__ = [
    'TextAnalyzer',
    'ScamTextResult', 
    'ContentScraper',
    'NLPPipeline',
    'VoiceAnalyzer',
    'CallerIDVerifier',
    'CallerIDResult',
    'LinkScanner',
    'LinkScanResult',
    'GeolocationService',
    'LocationData',
    'TrendAnalyzer',
    'TrendData',
    'HotspotData'
]
