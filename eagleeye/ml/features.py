"""
Feature extraction for machine learning models
"""
import re
import string
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from urllib.parse import urlparse
import phonenumbers
from phonenumbers import geocoder, carrier, timezone

from ..logging_config import LoggerMixin
from ..exceptions import ValidationError, AnalysisError


@dataclass
class TextFeatures:
    """Text-based features for scam detection"""
    
    # Basic text statistics
    char_count: int = 0
    word_count: int = 0
    sentence_count: int = 0
    avg_word_length: float = 0.0
    
    # Language patterns
    uppercase_ratio: float = 0.0
    digit_ratio: float = 0.0
    punctuation_ratio: float = 0.0
    special_char_ratio: float = 0.0
    
    # Scam indicators
    urgency_words: int = 0
    money_words: int = 0
    threat_words: int = 0
    contact_words: int = 0
    
    # Communication patterns
    exclamation_count: int = 0
    question_count: int = 0
    caps_sequences: int = 0
    
    # Suspicious patterns
    phone_numbers: int = 0
    email_addresses: int = 0
    urls: int = 0
    suspicious_domains: int = 0
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary for ML models"""
        return {
            'char_count': float(self.char_count),
            'word_count': float(self.word_count),
            'sentence_count': float(self.sentence_count),
            'avg_word_length': self.avg_word_length,
            'uppercase_ratio': self.uppercase_ratio,
            'digit_ratio': self.digit_ratio,
            'punctuation_ratio': self.punctuation_ratio,
            'special_char_ratio': self.special_char_ratio,
            'urgency_words': float(self.urgency_words),
            'money_words': float(self.money_words),
            'threat_words': float(self.threat_words),
            'contact_words': float(self.contact_words),
            'exclamation_count': float(self.exclamation_count),
            'question_count': float(self.question_count),
            'caps_sequences': float(self.caps_sequences),
            'phone_numbers': float(self.phone_numbers),
            'email_addresses': float(self.email_addresses),
            'urls': float(self.urls),
            'suspicious_domains': float(self.suspicious_domains)
        }


@dataclass
class URLFeatures:
    """URL-based features for scam detection"""
    
    # Basic URL structure
    url_length: int = 0
    domain_length: int = 0
    path_length: int = 0
    query_length: int = 0
    
    # Domain characteristics
    subdomain_count: int = 0
    tld_length: int = 0
    is_ip_address: bool = False
    has_port: bool = False
    
    # Suspicious patterns
    digit_ratio_domain: float = 0.0
    hyphen_count: int = 0
    suspicious_keywords: int = 0
    
    # Security indicators
    uses_https: bool = False
    has_suspicious_tld: bool = False
    is_shortened_url: bool = False
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary for ML models"""
        return {
            'url_length': float(self.url_length),
            'domain_length': float(self.domain_length), 
            'path_length': float(self.path_length),
            'query_length': float(self.query_length),
            'subdomain_count': float(self.subdomain_count),
            'tld_length': float(self.tld_length),
            'is_ip_address': float(self.is_ip_address),
            'has_port': float(self.has_port),
            'digit_ratio_domain': self.digit_ratio_domain,
            'hyphen_count': float(self.hyphen_count),
            'suspicious_keywords': float(self.suspicious_keywords),
            'uses_https': float(self.uses_https),
            'has_suspicious_tld': float(self.has_suspicious_tld),
            'is_shortened_url': float(self.is_shortened_url)
        }


@dataclass 
class PhoneFeatures:
    """Phone number-based features for scam detection"""
    
    # Basic characteristics
    is_valid: bool = False
    country_code: Optional[str] = None
    number_type: Optional[str] = None
    
    # Geographic indicators
    geographic_region: Optional[str] = None
    timezone_count: int = 0
    
    # Carrier information
    carrier_name: Optional[str] = None
    is_mobile: bool = False
    is_voip: bool = False
    
    # Suspicious patterns
    is_premium_rate: bool = False
    is_toll_free: bool = False
    has_unusual_pattern: bool = False
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary for ML models"""
        return {
            'is_valid': float(self.is_valid),
            'timezone_count': float(self.timezone_count),
            'is_mobile': float(self.is_mobile),
            'is_voip': float(self.is_voip),
            'is_premium_rate': float(self.is_premium_rate),
            'is_toll_free': float(self.is_toll_free),
            'has_unusual_pattern': float(self.has_unusual_pattern)
        }


class FeatureExtractor(LoggerMixin):
    """Main feature extraction class"""
    
    def __init__(self):
        # Define scam-related keywords
        self.urgency_words = {
            'urgent', 'immediate', 'emergency', 'asap', 'hurry', 'quick', 'fast',
            'deadline', 'expires', 'limited', 'act now', 'hurry up', 'time sensitive'
        }
        
        self.money_words = {
            'money', 'cash', 'payment', 'deposit', 'transfer', 'wire', 'bank',
            'account', 'credit', 'debit', 'loan', 'debt', 'fee', 'charge',
            'refund', 'reward', 'prize', 'million', 'thousand', 'dollars',
            'bitcoin', 'cryptocurrency', 'paypal', 'venmo', 'investment'
        }
        
        self.threat_words = {
            'arrest', 'police', 'court', 'legal', 'lawsuit', 'sue', 'jail',
            'prison', 'warrant', 'investigation', 'suspended', 'blocked',
            'terminated', 'consequences', 'penalty', 'fine', 'seizure'
        }
        
        self.contact_words = {
            'call', 'phone', 'contact', 'reply', 'respond', 'email', 'text',
            'message', 'click', 'visit', 'go to', 'link', 'website', 'portal'
        }
        
        self.suspicious_domains = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link',
            'rebrand.ly', 'buff.ly', 'bl.ink', 'cutt.ly'
        }
        
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.stream', '.racing', '.loan', '.bid', '.country', '.review'
        }
        
        # Regex patterns
        self.phone_pattern = re.compile(r'(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}|\b[0-9]{10}\b)')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.caps_sequence_pattern = re.compile(r'[A-Z]{3,}')
    
    def extract_text_features(self, text: str) -> TextFeatures:
        """Extract features from text content"""
        try:
            if not text or not isinstance(text, str):
                return TextFeatures()
            
            features = TextFeatures()
            
            # Basic statistics
            features.char_count = len(text)
            words = text.split()
            features.word_count = len(words)
            sentences = re.split(r'[.!?]+', text)
            features.sentence_count = len([s for s in sentences if s.strip()])
            features.avg_word_length = np.mean([len(word) for word in words]) if words else 0.0
            
            # Character ratios
            if features.char_count > 0:
                features.uppercase_ratio = sum(1 for c in text if c.isupper()) / features.char_count
                features.digit_ratio = sum(1 for c in text if c.isdigit()) / features.char_count
                features.punctuation_ratio = sum(1 for c in text if c in string.punctuation) / features.char_count
                features.special_char_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / features.char_count
            
            # Scam indicators
            text_lower = text.lower()
            features.urgency_words = sum(1 for word in self.urgency_words if word in text_lower)
            features.money_words = sum(1 for word in self.money_words if word in text_lower)
            features.threat_words = sum(1 for word in self.threat_words if word in text_lower)
            features.contact_words = sum(1 for word in self.contact_words if word in text_lower)
            
            # Communication patterns
            features.exclamation_count = text.count('!')
            features.question_count = text.count('?')
            features.caps_sequences = len(self.caps_sequence_pattern.findall(text))
            
            # Extract contact information
            features.phone_numbers = len(self.phone_pattern.findall(text))
            features.email_addresses = len(self.email_pattern.findall(text))
            features.urls = len(self.url_pattern.findall(text))
            
            # Check for suspicious domains
            urls = self.url_pattern.findall(text)
            features.suspicious_domains = sum(1 for url in urls 
                                           if any(domain in url for domain in self.suspicious_domains))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Failed to extract text features: {e}")
            raise AnalysisError(f"Text feature extraction failed: {e}", analysis_type="text_features", cause=e)
    
    def extract_url_features(self, url: str) -> URLFeatures:
        """Extract features from URL"""
        try:
            if not url or not isinstance(url, str):
                return URLFeatures()
            
            features = URLFeatures()
            parsed = urlparse(url)
            
            # Basic structure
            features.url_length = len(url)
            features.domain_length = len(parsed.netloc) if parsed.netloc else 0
            features.path_length = len(parsed.path) if parsed.path else 0
            features.query_length = len(parsed.query) if parsed.query else 0
            
            # Domain characteristics
            if parsed.netloc:
                domain_parts = parsed.netloc.split('.')
                features.subdomain_count = max(0, len(domain_parts) - 2)
                features.tld_length = len(domain_parts[-1]) if domain_parts else 0
                features.is_ip_address = self._is_ip_address(parsed.netloc)
                features.has_port = ':' in parsed.netloc
                
                # Suspicious patterns
                domain_digits = sum(1 for c in parsed.netloc if c.isdigit())
                features.digit_ratio_domain = domain_digits / len(parsed.netloc) if parsed.netloc else 0.0
                features.hyphen_count = parsed.netloc.count('-')
                
                # Check for suspicious keywords and TLDs
                features.suspicious_keywords = self._count_suspicious_keywords(url)
                features.has_suspicious_tld = any(tld in parsed.netloc for tld in self.suspicious_tlds)
                features.is_shortened_url = any(domain in parsed.netloc for domain in self.suspicious_domains)
            
            # Security indicators
            features.uses_https = parsed.scheme == 'https'
            
            return features
            
        except Exception as e:
            self.logger.error(f"Failed to extract URL features: {e}")
            raise AnalysisError(f"URL feature extraction failed: {e}", analysis_type="url_features", cause=e)
    
    def extract_phone_features(self, phone: str) -> PhoneFeatures:
        """Extract features from phone number"""
        try:
            if not phone or not isinstance(phone, str):
                return PhoneFeatures()
            
            features = PhoneFeatures()
            
            try:
                # Parse phone number
                parsed_number = phonenumbers.parse(phone, None)
                features.is_valid = phonenumbers.is_valid_number(parsed_number)
                
                if features.is_valid:
                    # Basic information
                    features.country_code = str(parsed_number.country_code)
                    number_type = phonenumbers.number_type(parsed_number)
                    features.number_type = str(number_type)
                    
                    # Geographic information
                    features.geographic_region = geocoder.description_for_number(parsed_number, "en")
                    timezones = timezone.time_zones_for_number(parsed_number)
                    features.timezone_count = len(timezones)
                    
                    # Carrier information
                    features.carrier_name = carrier.name_for_number(parsed_number, "en")
                    
                    # Number type analysis
                    features.is_mobile = number_type == phonenumbers.PhoneNumberType.MOBILE
                    features.is_voip = number_type == phonenumbers.PhoneNumberType.VOIP
                    features.is_premium_rate = number_type == phonenumbers.PhoneNumberType.PREMIUM_RATE
                    features.is_toll_free = number_type == phonenumbers.PhoneNumberType.TOLL_FREE
                    
                    # Pattern analysis
                    features.has_unusual_pattern = self._analyze_phone_pattern(phone)
                
            except phonenumbers.NumberParseException:
                features.is_valid = False
            
            return features
            
        except Exception as e:
            self.logger.error(f"Failed to extract phone features: {e}")
            raise AnalysisError(f"Phone feature extraction failed: {e}", analysis_type="phone_features", cause=e)
    
    def extract_combined_features(self, 
                                text: Optional[str] = None,
                                url: Optional[str] = None, 
                                phone: Optional[str] = None) -> Dict[str, float]:
        """Extract and combine all features into a single feature vector"""
        try:
            combined_features = {}
            
            # Text features
            if text:
                text_features = self.extract_text_features(text)
                text_dict = text_features.to_dict()
                combined_features.update({f"text_{k}": v for k, v in text_dict.items()})
            
            # URL features
            if url:
                url_features = self.extract_url_features(url)
                url_dict = url_features.to_dict()
                combined_features.update({f"url_{k}": v for k, v in url_dict.items()})
            
            # Phone features
            if phone:
                phone_features = self.extract_phone_features(phone)
                phone_dict = phone_features.to_dict()
                combined_features.update({f"phone_{k}": v for k, v in phone_dict.items()})
            
            return combined_features
            
        except Exception as e:
            self.logger.error(f"Failed to extract combined features: {e}")
            raise AnalysisError(f"Combined feature extraction failed: {e}", analysis_type="combined_features", cause=e)
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    def _count_suspicious_keywords(self, url: str) -> int:
        """Count suspicious keywords in URL"""
        suspicious_keywords = [
            'secure', 'verify', 'account', 'update', 'confirm', 'login',
            'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'facebook', 'twitter', 'suspended', 'locked', 'expired'
        ]
        
        url_lower = url.lower()
        return sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    
    def _analyze_phone_pattern(self, phone: str) -> bool:
        """Analyze phone number for unusual patterns"""
        # Remove formatting
        digits_only = re.sub(r'[^\d]', '', phone)
        
        if len(digits_only) < 10:
            return True
        
        # Check for repetitive patterns
        if len(set(digits_only)) < 3:  # Too few unique digits
            return True
        
        # Check for sequential numbers
        sequential_count = 0
        for i in range(len(digits_only) - 1):
            if abs(int(digits_only[i]) - int(digits_only[i+1])) == 1:
                sequential_count += 1
        
        if sequential_count > len(digits_only) * 0.7:  # Too many sequential digits
            return True
        
        return False