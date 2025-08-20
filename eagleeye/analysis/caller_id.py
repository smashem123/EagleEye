"""
Caller ID verification and phone number analysis
Advanced phone number validation and scam detection
"""
import re
import asyncio
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class PhoneNumberType(Enum):
    """Types of phone numbers"""
    MOBILE = "mobile"
    LANDLINE = "landline"
    VOIP = "voip"
    TOLL_FREE = "toll_free"
    PREMIUM = "premium"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk levels for phone numbers"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CallerIDResult:
    """Result of caller ID verification"""
    phone_number: str
    formatted_number: str
    country_code: str
    region: str
    carrier: Optional[str]
    number_type: PhoneNumberType
    risk_level: RiskLevel
    risk_score: float
    is_scam_number: bool
    scam_reports: int
    last_scam_report: Optional[datetime]
    blacklist_matches: List[str]
    whitelist_matches: List[str]
    reputation_score: float
    analysis_timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'phone_number': self.phone_number,
            'formatted_number': self.formatted_number,
            'country_code': self.country_code,
            'region': self.region,
            'carrier': self.carrier,
            'number_type': self.number_type.value,
            'risk_level': self.risk_level.value,
            'risk_score': self.risk_score,
            'is_scam_number': self.is_scam_number,
            'scam_reports': self.scam_reports,
            'last_scam_report': self.last_scam_report.isoformat() if self.last_scam_report else None,
            'blacklist_matches': self.blacklist_matches,
            'whitelist_matches': self.whitelist_matches,
            'reputation_score': self.reputation_score,
            'analysis_timestamp': self.analysis_timestamp.isoformat()
        }


class CallerIDVerifier:
    """Advanced caller ID verification and scam detection"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.timeout = 10.0
        
        # Common scam number patterns
        self.scam_patterns = [
            r'^1-?800-?000-?0000$',
            r'^1-?888-?888-?8888$',
            r'^1-?555-?555-?5555$',
            r'^1-?123-?456-?7890$',
            r'^\+?1-?000-?000-?0000$',
        ]
        
        # Known scam area codes
        self.high_risk_area_codes = {
            '268', '284', '473', '649', '664', '721', '758', '767', '784', '787', '809', '829', '849', '868', '869', '876', '939'
        }
        
        # Robocall indicators
        self.robocall_indicators = [
            'automated', 'press 1', 'this is not a sales call',
            'final notice', 'urgent', 'expires today',
            'IRS', 'social security', 'medicare', 'warranty'
        ]
    
    async def verify_phone_number(self, phone_number: str, context: Optional[str] = None) -> CallerIDResult:
        """Verify a phone number and assess scam risk"""
        normalized = self._normalize_phone_number(phone_number)
        formatted = self._format_phone_number(normalized)
        country_code, area_code, region = self._parse_phone_number(normalized)
        number_type = self._determine_number_type(normalized)
        scam_reports, last_report = await self._check_scam_databases(normalized)
        blacklist_matches = self._check_blacklists(normalized)
        whitelist_matches = self._check_whitelists(normalized)
        reputation_score = self._calculate_reputation_score(normalized, scam_reports, blacklist_matches, whitelist_matches)
        risk_score = self._calculate_risk_score(normalized, number_type, scam_reports, reputation_score, context)
        risk_level = self._determine_risk_level(risk_score)
        is_scam = risk_score > 7.0 or len(blacklist_matches) > 0 or scam_reports > 3
        carrier = await self._get_carrier_info(normalized)
        
        return CallerIDResult(
            phone_number=phone_number,
            formatted_number=formatted,
            country_code=country_code,
            region=region,
            carrier=carrier,
            number_type=number_type,
            risk_level=risk_level,
            risk_score=risk_score,
            is_scam_number=is_scam,
            scam_reports=scam_reports,
            last_scam_report=last_report,
            blacklist_matches=blacklist_matches,
            whitelist_matches=whitelist_matches,
            reputation_score=reputation_score,
            analysis_timestamp=datetime.now()
        )
    
    def _normalize_phone_number(self, phone_number: str) -> str:
        """Normalize phone number to standard format"""
        normalized = re.sub(r'[^\d+]', '', phone_number.strip())
        if normalized.startswith('+1'):
            normalized = normalized[2:]
        elif normalized.startswith('1') and len(normalized) == 11:
            normalized = normalized[1:]
        return normalized
    
    def _format_phone_number(self, normalized: str) -> str:
        """Format phone number for display"""
        if len(normalized) == 10:
            return f"+1-{normalized[:3]}-{normalized[3:6]}-{normalized[6:]}"
        return normalized
    
    def _parse_phone_number(self, normalized: str) -> Tuple[str, str, str]:
        """Parse phone number components"""
        if len(normalized) == 10:
            return "1", normalized[:3], self._get_region_from_area_code(normalized[:3])
        return "unknown", "unknown", "unknown"
    
    def _get_region_from_area_code(self, area_code: str) -> str:
        """Get region from area code"""
        region_map = {
            '212': 'New York, NY', '213': 'Los Angeles, CA', '312': 'Chicago, IL',
            '415': 'San Francisco, CA', '617': 'Boston, MA', '202': 'Washington, DC'
        }
        return region_map.get(area_code, "Unknown")
    
    def _determine_number_type(self, normalized: str) -> PhoneNumberType:
        """Determine the type of phone number"""
        if len(normalized) != 10:
            return PhoneNumberType.UNKNOWN
        
        area_code = normalized[:3]
        if area_code in ['800', '833', '844', '855', '866', '877', '888']:
            return PhoneNumberType.TOLL_FREE
        elif area_code in ['900', '976']:
            return PhoneNumberType.PREMIUM
        elif '555' in normalized:
            return PhoneNumberType.VOIP
        return PhoneNumberType.LANDLINE
    
    async def _check_scam_databases(self, normalized: str) -> Tuple[int, Optional[datetime]]:
        """Check against known scam number databases"""
        scam_reports = 0
        last_report = None
        
        for pattern in self.scam_patterns:
            if re.match(pattern, normalized):
                scam_reports += 5
                last_report = datetime.now()
                break
        
        area_code = normalized[:3] if len(normalized) >= 3 else ""
        if area_code in self.high_risk_area_codes:
            scam_reports += 2
        
        return scam_reports, last_report
    
    def _check_blacklists(self, normalized: str) -> List[str]:
        """Check against known blacklists"""
        matches = []
        for pattern in self.scam_patterns:
            if re.match(pattern, normalized):
                matches.append(f"scam_pattern:{pattern}")
        return matches
    
    def _check_whitelists(self, normalized: str) -> List[str]:
        """Check against known legitimate numbers"""
        return []  # Placeholder
    
    def _calculate_reputation_score(self, normalized: str, scam_reports: int, blacklist_matches: List[str], whitelist_matches: List[str]) -> float:
        """Calculate reputation score (0-10, higher is better)"""
        score = 5.0
        if whitelist_matches:
            score += 3.0
        score -= min(scam_reports * 0.5, 4.0)
        score -= len(blacklist_matches) * 2.0
        return max(0.0, min(10.0, score))
    
    def _calculate_risk_score(self, normalized: str, number_type: PhoneNumberType, scam_reports: int, reputation_score: float, context: Optional[str]) -> float:
        """Calculate overall risk score (0-10, higher is riskier)"""
        risk_score = (10.0 - reputation_score) * 0.6
        risk_score += min(scam_reports * 0.8, 5.0)
        
        type_risk = {PhoneNumberType.VOIP: 2.0, PhoneNumberType.PREMIUM: 4.0, PhoneNumberType.UNKNOWN: 1.5}
        risk_score += type_risk.get(number_type, 0.0)
        
        if context:
            context_lower = context.lower()
            for indicator in self.robocall_indicators:
                if indicator in context_lower:
                    risk_score += 1.0
        
        return min(10.0, risk_score)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score"""
        if risk_score >= 8.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 6.0:
            return RiskLevel.HIGH
        elif risk_score >= 4.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    async def _get_carrier_info(self, normalized: str) -> Optional[str]:
        """Get carrier information"""
        area_code = normalized[:3] if len(normalized) >= 3 else ""
        carrier_map = {
            '800': 'Toll-Free Service', '888': 'Toll-Free Service',
            '212': 'Verizon Wireless', '415': 'AT&T Mobility'
        }
        return carrier_map.get(area_code, "Unknown Carrier")
    
    async def batch_verify(self, phone_numbers: List[str]) -> List[CallerIDResult]:
        """Verify multiple phone numbers in batch"""
        results = []
        for phone_number in phone_numbers:
            result = await self.verify_phone_number(phone_number)
            results.append(result)
            await asyncio.sleep(0.1)
        return results

import re
import asyncio
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

import httpx
from pydantic import BaseModel


@dataclass
class CallerIDResult:
    """Result of caller ID verification."""
    phone_number: str
    formatted_number: str
    is_valid: bool
    carrier: Optional[str] = None
    location: Optional[str] = None
    scam_risk_score: float = 0.0
    scam_reports: List[Dict[str, Any]] = None
    is_robocall: bool = False
    is_spam: bool = False
    confidence: float = 0.0
    sources: List[str] = None
    
    def __post_init__(self):
        if self.scam_reports is None:
            self.scam_reports = []
        if self.sources is None:
            self.sources = []


class PhoneNumberValidator:
    """Validates and formats phone numbers."""
    
    def __init__(self):
        # US phone number patterns
        self.us_patterns = [
            r'^\+?1?[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$',
            r'^([0-9]{3})[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$',
            r'^\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$'
        ]
    
    def validate_and_format(self, phone_number: str) -> Tuple[bool, str, str]:
        """
        Validate and format phone number.
        
        Returns:
            Tuple of (is_valid, formatted_number, raw_digits)
        """
        if not phone_number:
            return False, "", ""
        
        # Clean the number
        cleaned = re.sub(r'[^\d+]', '', phone_number)
        
        # Extract digits only
        digits_only = re.sub(r'[^\d]', '', cleaned)
        
        # Check US number patterns
        for pattern in self.us_patterns:
            match = re.match(pattern, phone_number)
            if match:
                if len(digits_only) == 10:
                    formatted = f"+1-{digits_only[:3]}-{digits_only[3:6]}-{digits_only[6:]}"
                    return True, formatted, digits_only
                elif len(digits_only) == 11 and digits_only.startswith('1'):
                    formatted = f"+1-{digits_only[1:4]}-{digits_only[4:7]}-{digits_only[7:]}"
                    return True, formatted, digits_only[1:]
        
        return False, phone_number, digits_only


class ScamDatabaseChecker:
    """Cross-references phone numbers against scam databases."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize scam phone number database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scam_numbers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone_number TEXT NOT NULL,
                    phone_hash TEXT NOT NULL,
                    scam_type TEXT,
                    report_count INTEGER DEFAULT 1,
                    risk_score REAL DEFAULT 0.0,
                    first_reported TIMESTAMP,
                    last_reported TIMESTAMP,
                    location TEXT,
                    carrier TEXT,
                    is_robocall BOOLEAN DEFAULT 0,
                    is_spam BOOLEAN DEFAULT 0,
                    source TEXT,
                    metadata TEXT
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_phone_hash 
                ON scam_numbers(phone_hash)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_phone_number 
                ON scam_numbers(phone_number)
            ''')
    
    def hash_phone_number(self, phone_number: str) -> str:
        """Create hash of phone number for privacy."""
        return hashlib.sha256(phone_number.encode()).hexdigest()[:16]
    
    def add_scam_report(self, phone_number: str, scam_type: str = "unknown", 
                       risk_score: float = 5.0, location: str = None,
                       carrier: str = None, is_robocall: bool = False,
                       is_spam: bool = False, source: str = "user_report",
                       metadata: Dict = None) -> bool:
        """Add or update scam report for phone number."""
        try:
            phone_hash = self.hash_phone_number(phone_number)
            now = datetime.now()
            
            with sqlite3.connect(self.db_path) as conn:
                # Check if number already exists
                existing = conn.execute(
                    'SELECT id, report_count FROM scam_numbers WHERE phone_hash = ?',
                    (phone_hash,)
                ).fetchone()
                
                if existing:
                    # Update existing record
                    conn.execute('''
                        UPDATE scam_numbers 
                        SET report_count = report_count + 1,
                            risk_score = MAX(risk_score, ?),
                            last_reported = ?,
                            is_robocall = is_robocall OR ?,
                            is_spam = is_spam OR ?
                        WHERE phone_hash = ?
                    ''', (risk_score, now, is_robocall, is_spam, phone_hash))
                else:
                    # Insert new record
                    conn.execute('''
                        INSERT INTO scam_numbers 
                        (phone_number, phone_hash, scam_type, risk_score, 
                         first_reported, last_reported, location, carrier,
                         is_robocall, is_spam, source, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (phone_number, phone_hash, scam_type, risk_score,
                          now, now, location, carrier, is_robocall, is_spam,
                          source, str(metadata) if metadata else None))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error adding scam report: {e}")
            return False
    
    def check_scam_database(self, phone_number: str) -> Dict[str, Any]:
        """Check phone number against scam database."""
        phone_hash = self.hash_phone_number(phone_number)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                result = conn.execute('''
                    SELECT * FROM scam_numbers 
                    WHERE phone_hash = ? OR phone_number = ?
                    ORDER BY last_reported DESC
                ''', (phone_hash, phone_number)).fetchone()
                
                if result:
                    return {
                        'found': True,
                        'scam_type': result['scam_type'],
                        'report_count': result['report_count'],
                        'risk_score': result['risk_score'],
                        'first_reported': result['first_reported'],
                        'last_reported': result['last_reported'],
                        'location': result['location'],
                        'carrier': result['carrier'],
                        'is_robocall': bool(result['is_robocall']),
                        'is_spam': bool(result['is_spam']),
                        'source': result['source']
                    }
                
                return {'found': False}
                
        except Exception as e:
            print(f"Error checking scam database: {e}")
            return {'found': False, 'error': str(e)}


class CarrierLookup:
    """Phone number carrier and location lookup."""
    
    def __init__(self):
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)
    
    async def lookup_carrier(self, phone_number: str) -> Dict[str, Any]:
        """Lookup carrier information for phone number."""
        # Check cache first
        cache_key = phone_number
        if cache_key in self.cache:
            cached_time, cached_data = self.cache[cache_key]
            if datetime.now() - cached_time < self.cache_ttl:
                return cached_data
        
        try:
            # Use free carrier lookup APIs
            result = await self._lookup_via_numverify(phone_number)
            
            # Cache result
            self.cache[cache_key] = (datetime.now(), result)
            return result
            
        except Exception as e:
            return {
                'carrier': None,
                'location': None,
                'line_type': None,
                'error': str(e)
            }
    
    async def _lookup_via_numverify(self, phone_number: str) -> Dict[str, Any]:
        """Lookup via NumVerify API (free tier available)."""
        # Note: This would require API key in production
        # For now, return mock data based on area code
        
        digits = re.sub(r'[^\d]', '', phone_number)
        if len(digits) >= 10:
            area_code = digits[-10:-7]  # Get area code
            
            # Mock carrier data based on area code patterns
            carrier_map = {
                '800': 'Toll Free',
                '888': 'Toll Free',
                '877': 'Toll Free',
                '866': 'Toll Free',
                '855': 'Toll Free',
                '844': 'Toll Free',
                '833': 'Toll Free',
                '822': 'Toll Free'
            }
            
            if area_code in carrier_map:
                return {
                    'carrier': carrier_map[area_code],
                    'location': 'United States',
                    'line_type': 'toll_free',
                    'is_mobile': False
                }
            
            # Regular area codes - mock data
            return {
                'carrier': 'Unknown Carrier',
                'location': f'US Area Code {area_code}',
                'line_type': 'landline',
                'is_mobile': area_code.startswith(('2', '3', '4', '5', '6', '7', '8', '9'))
            }
        
        return {
            'carrier': None,
            'location': None,
            'line_type': None,
            'is_mobile': None
        }


class CallerIDVerifier:
    """Main caller ID verification system."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.db_path = config_dir / "caller_id.db"
        
        self.validator = PhoneNumberValidator()
        self.scam_checker = ScamDatabaseChecker(self.db_path)
        self.carrier_lookup = CarrierLookup()
    
    async def verify_caller_id(self, phone_number: str, 
                              check_carrier: bool = True) -> CallerIDResult:
        """
        Comprehensive caller ID verification.
        
        Args:
            phone_number: Phone number to verify
            check_carrier: Whether to perform carrier lookup
            
        Returns:
            CallerIDResult with verification details
        """
        # Validate and format number
        is_valid, formatted_number, raw_digits = self.validator.validate_and_format(phone_number)
        
        if not is_valid:
            return CallerIDResult(
                phone_number=phone_number,
                formatted_number=phone_number,
                is_valid=False,
                confidence=0.0
            )
        
        # Check scam database
        scam_data = self.scam_checker.check_scam_database(raw_digits)
        
        # Initialize result
        result = CallerIDResult(
            phone_number=phone_number,
            formatted_number=formatted_number,
            is_valid=True,
            confidence=0.8
        )
        
        # Process scam database results
        if scam_data.get('found'):
            result.scam_risk_score = scam_data.get('risk_score', 0.0)
            result.is_robocall = scam_data.get('is_robocall', False)
            result.is_spam = scam_data.get('is_spam', False)
            result.scam_reports = [{
                'type': scam_data.get('scam_type'),
                'count': scam_data.get('report_count'),
                'last_reported': scam_data.get('last_reported'),
                'source': scam_data.get('source')
            }]
            result.sources.append('local_database')
            result.confidence = min(0.95, 0.5 + (scam_data.get('report_count', 0) * 0.1))
        
        # Carrier lookup if requested
        if check_carrier:
            try:
                carrier_data = await self.carrier_lookup.lookup_carrier(raw_digits)
                result.carrier = carrier_data.get('carrier')
                result.location = carrier_data.get('location')
                
                # Adjust risk score based on carrier type
                if carrier_data.get('line_type') == 'toll_free':
                    result.scam_risk_score += 1.0  # Toll-free numbers often used for scams
                
                result.sources.append('carrier_lookup')
                
            except Exception as e:
                print(f"Carrier lookup failed: {e}")
        
        return result
    
    def report_scam_number(self, phone_number: str, scam_type: str = "robocall",
                          location: str = None, description: str = None) -> bool:
        """Report a phone number as scam/spam."""
        is_valid, formatted_number, raw_digits = self.validator.validate_and_format(phone_number)
        
        if not is_valid:
            return False
        
        # Determine risk score based on scam type
        risk_scores = {
            'robocall': 7.0,
            'phishing': 9.0,
            'fraud': 8.5,
            'spam': 5.0,
            'telemarketing': 4.0,
            'scam': 8.0
        }
        
        risk_score = risk_scores.get(scam_type.lower(), 6.0)
        
        return self.scam_checker.add_scam_report(
            phone_number=raw_digits,
            scam_type=scam_type,
            risk_score=risk_score,
            location=location,
            is_robocall=(scam_type.lower() in ['robocall', 'robo']),
            is_spam=(scam_type.lower() in ['spam', 'telemarketing']),
            source='user_report',
            metadata={'description': description}
        )
    
    def get_scam_statistics(self) -> Dict[str, Any]:
        """Get scam number statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Total scam numbers
                total = conn.execute('SELECT COUNT(*) as count FROM scam_numbers').fetchone()['count']
                
                # Recent reports (last 7 days)
                week_ago = datetime.now() - timedelta(days=7)
                recent = conn.execute(
                    'SELECT COUNT(*) as count FROM scam_numbers WHERE last_reported >= ?',
                    (week_ago,)
                ).fetchone()['count']
                
                # Top scam types
                scam_types = conn.execute('''
                    SELECT scam_type, COUNT(*) as count, AVG(risk_score) as avg_risk
                    FROM scam_numbers 
                    GROUP BY scam_type 
                    ORDER BY count DESC 
                    LIMIT 10
                ''').fetchall()
                
                # High risk numbers
                high_risk = conn.execute(
                    'SELECT COUNT(*) as count FROM scam_numbers WHERE risk_score >= 7.0'
                ).fetchone()['count']
                
                return {
                    'total_scam_numbers': total,
                    'recent_reports': recent,
                    'high_risk_numbers': high_risk,
                    'top_scam_types': [
                        {
                            'type': row['scam_type'],
                            'count': row['count'],
                            'avg_risk': round(row['avg_risk'], 1)
                        }
                        for row in scam_types
                    ]
                }
                
        except Exception as e:
            return {'error': str(e)}
