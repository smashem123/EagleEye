"""
Real-time text analysis for scam detection
Advanced NLP and ML-based content analysis
"""
import re
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib

try:
    import spacy
    from textblob import TextBlob
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False


class ScamType(Enum):
    """Types of scam content detected"""
    PHISHING = "phishing"
    ROMANCE = "romance"
    INVESTMENT = "investment"
    TECH_SUPPORT = "tech_support"
    LOTTERY = "lottery"
    ADVANCE_FEE = "advance_fee"
    IDENTITY_THEFT = "identity_theft"
    CRYPTOCURRENCY = "cryptocurrency"
    FAKE_CHARITY = "fake_charity"
    UNKNOWN = "unknown"


@dataclass
class ScamTextResult:
    """Result of text analysis for scam detection"""
    text_hash: str
    content: str
    scam_type: ScamType
    confidence: float
    risk_score: float
    sentiment_score: float
    urgency_score: float
    entities: List[Dict[str, Any]]
    suspicious_patterns: List[str]
    language: str
    detected_at: datetime
    source_url: Optional[str] = None
    source_type: str = "text"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'text_hash': self.text_hash,
            'content': self.content[:500],  # Truncate for storage
            'scam_type': self.scam_type.value,
            'confidence': self.confidence,
            'risk_score': self.risk_score,
            'sentiment_score': self.sentiment_score,
            'urgency_score': self.urgency_score,
            'entities': self.entities,
            'suspicious_patterns': self.suspicious_patterns,
            'language': self.language,
            'detected_at': self.detected_at.isoformat(),
            'source_url': self.source_url,
            'source_type': self.source_type
        }


class TextAnalyzer:
    """Advanced text analyzer for scam detection"""
    
    def __init__(self):
        self.nlp = None
        self._init_nlp()
        
        # Enhanced scam patterns with weights
        self.scam_patterns = {
            'urgency': {
                'patterns': [
                    r'urgent.*action.*required',
                    r'immediate.*response.*needed',
                    r'expires?.*today',
                    r'limited.*time.*offer',
                    r'act.*now.*or.*lose',
                    r'final.*notice',
                    r'last.*chance',
                    r'time.*sensitive',
                    r'within.*24.*hours',
                    r'before.*midnight',
                    r'deadline.*approaching'
                ],
                'weight': 2.0
            },
            'impersonation': {
                'patterns': [
                    r'(amazon|paypal|microsoft|apple|google|facebook|netflix|spotify).*security',
                    r'(bank|credit.*card|account).*suspended',
                    r'irs.*tax.*refund',
                    r'social.*security.*administration',
                    r'medicare.*benefits',
                    r'government.*grant',
                    r'federal.*trade.*commission',
                    r'department.*of.*justice',
                    r'your.*bank.*account',
                    r'credit.*monitoring.*service',
                    r'fraud.*protection.*department'
                ],
                'weight': 3.0
            },
            'authority_claims': {
                'patterns': [
                    r'authorized.*representative',
                    r'official.*notice',
                    r'legal.*department',
                    r'compliance.*officer',
                    r'security.*team',
                    r'fraud.*prevention',
                    r'account.*verification.*department',
                    r'customer.*protection.*service',
                    r'identity.*theft.*prevention'
                ],
                'weight': 2.5
            },
            'financial': {
                'patterns': [
                    r'refund', r'tax return', r'inheritance', r'lottery', r'prize',
                    r'million dollars?', r'wire transfer', r'bank account', r'credit card',
                    r'social security', r'routing number', r'pin number'
                ],
                'weight': 1.5
            },
            'emotional': {
                'patterns': [
                    r'congratulations', r'you(?:\'ve| have) won', r'selected winner',
                    r'help me', r'dying', r'cancer', r'orphan', r'refugee',
                    r'love you', r'soulmate', r'destiny'
                ],
                'weight': 1.0
            }
        }
        
        self.tech_support_patterns = [
            r'microsoft support', r'apple support', r'google support',
            r'virus detected', r'malware found', r'computer infected',
            r'call this number', r'remote access', r'teamviewer',
            r'windows defender', r'security warning'
        ]
        
        self.investment_patterns = [
            r'guaranteed return', r'risk[- ]free', r'double your money',
            r'cryptocurrency', r'bitcoin', r'forex', r'trading',
            r'investment opportunity', r'insider information',
            r'get rich quick', r'passive income'
        ]
        
        # Entity patterns for fake organizations
        self.fake_entities = {
            'banks': [
                r'security department', r'fraud department', r'verification team',
                r'account services', r'customer security'
            ],
            'government': [
                r'irs', r'social security administration', r'department of treasury',
                r'homeland security', r'immigration services'
            ],
            'tech_companies': [
                r'microsoft security', r'apple security', r'google security',
                r'amazon security', r'paypal security'
            ]
        }
    
    def _init_nlp(self):
        """Initialize NLP models"""
        if SPACY_AVAILABLE:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                # Fallback to basic analysis if model not available
                self.nlp = None
    
    def _get_text_hash(self, text: str) -> str:
        """Generate hash for text deduplication"""
        return hashlib.sha256(text.encode()).hexdigest()[:16]
    
    async def analyze_text(self, 
                          content: str, 
                          source_url: Optional[str] = None,
                          source_type: str = "text") -> ScamTextResult:
        """Analyze text content for scam indicators"""
        
        text_hash = self._get_text_hash(content)
        
        # Basic preprocessing
        content_clean = self._preprocess_text(content)
        
        # Detect language
        language = self._detect_language(content_clean)
        
        # Analyze sentiment
        sentiment_score = self._analyze_sentiment(content_clean)
        
        # Calculate urgency score
        urgency_score = self._calculate_urgency_score(content_clean)
        
        # Extract entities
        entities = self._extract_entities(content_clean)
        
        # Detect suspicious patterns
        suspicious_patterns = self._detect_patterns(content_clean)
        
        # Determine scam type and confidence
        scam_type, confidence = self._classify_scam_type(
            content_clean, suspicious_patterns, entities
        )
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(
            confidence, sentiment_score, urgency_score, 
            len(suspicious_patterns), len(entities)
        )
        
        return ScamTextResult(
            text_hash=text_hash,
            content=content,
            scam_type=scam_type,
            confidence=confidence,
            risk_score=risk_score,
            sentiment_score=sentiment_score,
            urgency_score=urgency_score,
            entities=entities,
            suspicious_patterns=suspicious_patterns,
            language=language,
            detected_at=datetime.now(),
            source_url=source_url,
            source_type=source_type
        )
    
    def _preprocess_text(self, text: str) -> str:
        """Clean and preprocess text"""
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        # Remove special characters but keep basic punctuation
        text = re.sub(r'[^\w\s.,!?@$%-]', '', text)
        return text.strip()
    
    def _detect_language(self, text: str) -> str:
        """Detect text language"""
        try:
            blob = TextBlob(text)
            return blob.detect_language()
        except:
            return "en"  # Default to English
    
    def _analyze_sentiment(self, text: str) -> float:
        """Analyze sentiment polarity (-1 to 1)"""
        try:
            blob = TextBlob(text)
            return blob.sentiment.polarity
        except:
            return 0.0
    
    def _calculate_urgency_score(self, text: str) -> float:
        """Calculate urgency score based on patterns"""
        urgency_score = 0.0
        text_lower = text.lower()
        
        for pattern in self.scam_patterns['urgency']['patterns']:
            matches = len(re.findall(pattern, text_lower))
            urgency_score += matches * 0.2
        
        # Time-based urgency indicators
        time_patterns = [
            r'\d+\s*(?:hour|minute|day)s?',
            r'today', r'tonight', r'now', r'asap'
        ]
        
        for pattern in time_patterns:
            if re.search(pattern, text_lower):
                urgency_score += 0.3
        
        return min(urgency_score, 1.0)
    
    def _extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extract named entities and suspicious entities"""
        entities = []
        
        if self.nlp:
            doc = self.nlp(text)
            for ent in doc.ents:
                entities.append({
                    'text': ent.text,
                    'label': ent.label_,
                    'start': ent.start_char,
                    'end': ent.end_char,
                    'confidence': 0.8
                })
        
        # Extract financial entities
        financial_patterns = [
            (r'\$[\d,]+(?:\.\d{2})?', 'MONEY'),
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'CREDIT_CARD'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            (r'\b\d{9,12}\b', 'ACCOUNT_NUMBER')
        ]
        
        for pattern, label in financial_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                entities.append({
                    'text': match.group(),
                    'label': label,
                    'start': match.start(),
                    'end': match.end(),
                    'confidence': 0.9
                })
        
        return entities
    
    def _detect_patterns(self, text: str) -> List[str]:
        """Detect suspicious patterns in text"""
        patterns_found = []
        text_lower = text.lower()
        
        # Check all pattern categories
        for category, pattern_data in self.scam_patterns.items():
            for pattern in pattern_data['patterns']:
                if re.search(pattern, text_lower):
                    patterns_found.append(f"{category}:{pattern}")
        
        # Check tech support patterns
        for pattern in self.tech_support_patterns:
            if re.search(pattern, text_lower):
                patterns_found.append(f"tech_support:{pattern}")
        
        # Check investment patterns
        for pattern in self.investment_patterns:
            if re.search(pattern, text_lower):
                patterns_found.append(f"investment:{pattern}")
        
        # Check for fake entities
        for entity_type, patterns in self.fake_entities.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    patterns_found.append(f"fake_entity:{entity_type}:{pattern}")
        
        return patterns_found
    
    def _classify_scam_type(self, 
                           text: str, 
                           patterns: List[str], 
                           entities: List[Dict]) -> Tuple[ScamType, float]:
        """Classify scam type and calculate confidence"""
        
        text_lower = text.lower()
        confidence = 0.0
        
        # Pattern-based classification
        pattern_scores = {
            ScamType.PHISHING: 0,
            ScamType.TECH_SUPPORT: 0,
            ScamType.INVESTMENT: 0,
            ScamType.ROMANCE: 0,
            ScamType.LOTTERY: 0,
            ScamType.ADVANCE_FEE: 0
        }
        
        for pattern in patterns:
            if pattern.startswith('urgency:') or pattern.startswith('authority:'):
                pattern_scores[ScamType.PHISHING] += 0.3
            elif pattern.startswith('tech_support:'):
                pattern_scores[ScamType.TECH_SUPPORT] += 0.4
            elif pattern.startswith('investment:'):
                pattern_scores[ScamType.INVESTMENT] += 0.4
            elif pattern.startswith('emotional:'):
                if 'love' in pattern or 'soulmate' in pattern:
                    pattern_scores[ScamType.ROMANCE] += 0.4
                elif 'won' in pattern or 'prize' in pattern:
                    pattern_scores[ScamType.LOTTERY] += 0.4
            elif pattern.startswith('financial:'):
                if 'inheritance' in pattern or 'million' in pattern:
                    pattern_scores[ScamType.ADVANCE_FEE] += 0.3
                else:
                    pattern_scores[ScamType.PHISHING] += 0.2
        
        # Keyword-based classification
        if any(word in text_lower for word in ['bitcoin', 'crypto', 'trading']):
            pattern_scores[ScamType.CRYPTOCURRENCY] += 0.3
        
        if any(word in text_lower for word in ['charity', 'donation', 'help']):
            pattern_scores[ScamType.FAKE_CHARITY] += 0.2
        
        # Find highest scoring type
        max_score = max(pattern_scores.values())
        if max_score > 0.2:
            scam_type = max(pattern_scores, key=pattern_scores.get)
            confidence = min(max_score, 1.0)
        else:
            scam_type = ScamType.UNKNOWN
            confidence = 0.1
        
        # Boost confidence based on entity detection
        financial_entities = [e for e in entities if e['label'] in ['MONEY', 'CREDIT_CARD', 'SSN']]
        if financial_entities:
            confidence += 0.2
        
        return scam_type, min(confidence, 1.0)
    
    def _calculate_risk_score(self, 
                             confidence: float,
                             sentiment: float,
                             urgency: float,
                             pattern_count: int,
                             entity_count: int) -> float:
        """Calculate overall risk score (0-10)"""
        
        # Base score from confidence
        risk_score = confidence * 5
        
        # Add urgency factor
        risk_score += urgency * 2
        
        # Add pattern density factor
        pattern_factor = min(pattern_count * 0.3, 2.0)
        risk_score += pattern_factor
        
        # Add entity factor
        entity_factor = min(entity_count * 0.2, 1.0)
        risk_score += entity_factor
        
        # Sentiment factor (negative sentiment increases risk)
        if sentiment < -0.2:
            risk_score += abs(sentiment) * 1.5
        
        return min(risk_score, 10.0)
    
    async def batch_analyze(self, 
                           texts: List[str],
                           source_urls: Optional[List[str]] = None) -> List[ScamTextResult]:
        """Analyze multiple texts in batch"""
        results = []
        
        for i, text in enumerate(texts):
            source_url = source_urls[i] if source_urls and i < len(source_urls) else None
            result = await self.analyze_text(text, source_url)
            results.append(result)
            
            # Small delay to prevent overwhelming
            await asyncio.sleep(0.01)
        
        return results
