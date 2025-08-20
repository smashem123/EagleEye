"""
FTC Do Not Call (DNC) Reported Calls API integration
Access to consumer complaints about unwanted calls and robocalls
"""
import asyncio
import httpx
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from .base import ScamSource, ScamSourceError
from ..database import ScamRecord


@dataclass
class FTCComplaint:
    """FTC consumer complaint data"""
    complaint_id: str
    phone_number: str
    caller_id_name: Optional[str]
    complaint_date: datetime
    consumer_state: str
    consumer_city: Optional[str]
    subject: str
    call_type: str
    recording_played: bool
    robocall: bool
    description: str
    company_name: Optional[str]
    tags: List[str]
    
    def to_scam_record(self) -> ScamRecord:
        """Convert FTC complaint to ScamRecord"""
        severity = 6.0  # Base severity for robocalls
        if self.robocall:
            severity += 1.0
        if any(keyword in self.description.lower() for keyword in ['scam', 'fraud', 'fake']):
            severity += 2.0
        
        return ScamRecord(
            title=f"FTC Complaint: {self.subject}",
            description=self.description,
            scam_type='robocall' if self.robocall else 'unwanted_call',
            source='ftc_dnc',
            source_id=self.complaint_id,
            phone=self.phone_number,
            location=f"{self.consumer_city}, {self.consumer_state}" if self.consumer_city else self.consumer_state,
            severity=min(severity, 10.0),
            confidence=0.8,
            first_seen=self.complaint_date,
            tags=['ftc', 'consumer_complaint'] + self.tags,
            raw_data={
                'caller_id_name': self.caller_id_name,
                'call_type': self.call_type,
                'recording_played': self.recording_played,
                'company_name': self.company_name
            }
        )


class FTCDNCClient(ScamSource):
    """FTC Do Not Call Registry API client"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("ftc_dnc", api_key)
        self.base_url = "https://api.consumersentinel.gov"  # Mock URL
        self.rate_limit_delay = 2.0  # FTC has strict rate limits
        
        # Call type classifications
        self.call_types = {
            'robocall': 'Automated/Robocall',
            'live_person': 'Live Person',
            'prerecorded': 'Prerecorded Message',
            'unknown': 'Unknown'
        }
        
        # Subject categories for scam detection
        self.scam_subjects = {
            'credit_services': ['credit card', 'debt reduction', 'loan'],
            'healthcare': ['health insurance', 'medicare', 'prescription'],
            'home_security': ['home security', 'alarm system'],
            'energy': ['utility', 'electric', 'solar'],
            'auto_warranty': ['car warranty', 'vehicle warranty', 'auto warranty'],
            'charity': ['charity', 'donation', 'police fund'],
            'political': ['political', 'survey', 'poll'],
            'unknown': ['unknown', 'other']
        }
    
    def is_configured(self) -> bool:
        """Check if FTC API is configured"""
        # In production, would check for valid API credentials
        return True  # Mock implementation
    
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """Fetch recent FTC Do Not Call complaints"""
        try:
            complaints = await self._fetch_complaints(limit)
            scam_records = []
            
            for complaint in complaints:
                # Filter for scam-related complaints
                if self._is_scam_related(complaint):
                    scam_record = complaint.to_scam_record()
                    scam_records.append(scam_record)
            
            return scam_records
            
        except Exception as e:
            raise ScamSourceError(f"Failed to fetch FTC complaints: {e}")
    
    async def search_scams(self, query: str, limit: int = 50) -> List[ScamRecord]:
        """Search FTC complaints by query"""
        try:
            # Search complaints by phone number, description, or location
            complaints = await self._search_complaints(query, limit)
            scam_records = []
            
            for complaint in complaints:
                if self._is_scam_related(complaint):
                    scam_record = complaint.to_scam_record()
                    scam_records.append(scam_record)
            
            return scam_records
            
        except Exception as e:
            raise ScamSourceError(f"Failed to search FTC complaints: {e}")
    
    async def get_complaints_by_state(self, state: str, days_back: int = 30) -> List[FTCComplaint]:
        """Get complaints for a specific state"""
        try:
            return await self._fetch_complaints_by_location(state, days_back)
        except Exception as e:
            raise ScamSourceError(f"Failed to fetch state complaints: {e}")
    
    async def get_trending_numbers(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get trending reported phone numbers"""
        try:
            # Mock implementation - in production would query FTC API
            trending = []
            
            # Generate mock trending numbers
            mock_numbers = [
                "800-555-SCAM", "888-555-FAKE", "877-555-ROBO",
                "866-555-SPAM", "855-555-PHISH", "844-555-FRAUD"
            ]
            
            for i, number in enumerate(mock_numbers[:limit]):
                trending.append({
                    'phone_number': number,
                    'complaint_count': 150 - i * 10,
                    'recent_complaints': 25 - i * 2,
                    'primary_subject': list(self.scam_subjects.keys())[i % len(self.scam_subjects)],
                    'risk_score': 9.0 - i * 0.2
                })
            
            return trending
            
        except Exception as e:
            raise ScamSourceError(f"Failed to fetch trending numbers: {e}")
    
    async def _fetch_complaints(self, limit: int) -> List[FTCComplaint]:
        """Fetch complaints from FTC API (mock implementation)"""
        # In production, this would make actual API calls to FTC
        
        await asyncio.sleep(0.5)  # Simulate API delay
        
        # Generate mock complaints
        complaints = []
        base_date = datetime.now() - timedelta(days=30)
        
        for i in range(min(limit, 100)):
            complaint_date = base_date + timedelta(days=i % 30, hours=i % 24)
            
            phone_numbers = [
                "800-555-SCAM", "888-555-FAKE", "877-555-ROBO",
                "866-555-SPAM", "855-555-PHISH", "202-555-GOVT"
            ]
            
            subjects = [
                "Credit Card Services", "Auto Warranty", "Health Insurance",
                "Home Security", "Energy Services", "Charity Donation",
                "Political Survey", "Unknown/Other"
            ]
            
            descriptions = [
                "Automated message about credit card debt reduction services",
                "Robocall offering extended car warranty for vehicle",
                "Prerecorded message about health insurance enrollment",
                "Live person selling home security system installation",
                "Automated call about solar panel installation",
                "Robocall requesting charity donation for police fund"
            ]
            
            states = ["CA", "NY", "TX", "FL", "IL", "PA", "OH", "GA", "NC", "MI"]
            cities = ["Los Angeles", "New York", "Houston", "Miami", "Chicago"]
            
            complaint = FTCComplaint(
                complaint_id=f"FTC-{1000000 + i}",
                phone_number=phone_numbers[i % len(phone_numbers)],
                caller_id_name=f"CALLER-{i % 10}" if i % 3 == 0 else None,
                complaint_date=complaint_date,
                consumer_state=states[i % len(states)],
                consumer_city=cities[i % len(cities)] if i % 2 == 0 else None,
                subject=subjects[i % len(subjects)],
                call_type=list(self.call_types.keys())[i % len(self.call_types)],
                recording_played=i % 3 == 0,
                robocall=i % 2 == 0,
                description=descriptions[i % len(descriptions)],
                company_name=f"Scam Company {i % 5}" if i % 4 == 0 else None,
                tags=['automated', 'suspicious'] if i % 2 == 0 else ['telemarketer']
            )
            
            complaints.append(complaint)
        
        return complaints
    
    async def _search_complaints(self, query: str, limit: int) -> List[FTCComplaint]:
        """Search complaints by query"""
        all_complaints = await self._fetch_complaints(limit * 2)
        
        # Filter complaints based on query
        matching_complaints = []
        query_lower = query.lower()
        
        for complaint in all_complaints:
            if (query_lower in complaint.phone_number.lower() or
                query_lower in complaint.description.lower() or
                query_lower in complaint.subject.lower() or
                (complaint.consumer_state and query_lower in complaint.consumer_state.lower()) or
                (complaint.consumer_city and query_lower in complaint.consumer_city.lower())):
                matching_complaints.append(complaint)
        
        return matching_complaints[:limit]
    
    async def _fetch_complaints_by_location(self, state: str, days_back: int) -> List[FTCComplaint]:
        """Fetch complaints for specific location"""
        all_complaints = await self._fetch_complaints(200)
        
        # Filter by state and date
        cutoff_date = datetime.now() - timedelta(days=days_back)
        location_complaints = []
        
        for complaint in all_complaints:
            if (complaint.consumer_state.upper() == state.upper() and
                complaint.complaint_date >= cutoff_date):
                location_complaints.append(complaint)
        
        return location_complaints
    
    def _is_scam_related(self, complaint: FTCComplaint) -> bool:
        """Determine if complaint is scam-related"""
        scam_indicators = [
            'scam', 'fraud', 'fake', 'phishing', 'suspicious',
            'unauthorized', 'illegal', 'deceptive', 'misleading'
        ]
        
        # Check description for scam indicators
        description_lower = complaint.description.lower()
        if any(indicator in description_lower for indicator in scam_indicators):
            return True
        
        # Robocalls are generally considered suspicious
        if complaint.robocall:
            return True
        
        # Multiple complaints about same number indicate scam
        # (In production, would check against complaint frequency)
        
        # Certain subjects are high-risk
        high_risk_subjects = ['credit', 'warranty', 'insurance', 'security', 'energy']
        if any(subject in complaint.subject.lower() for subject in high_risk_subjects):
            return True
        
        return False
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for FTC API"""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    async def get_complaint_statistics(self, days_back: int = 30) -> Dict[str, Any]:
        """Get complaint statistics and trends"""
        try:
            complaints = await self._fetch_complaints(1000)  # Large sample
            
            # Filter by date range
            cutoff_date = datetime.now() - timedelta(days=days_back)
            recent_complaints = [c for c in complaints if c.complaint_date >= cutoff_date]
            
            # Calculate statistics
            total_complaints = len(recent_complaints)
            robocall_complaints = len([c for c in recent_complaints if c.robocall])
            
            # Subject breakdown
            subject_counts = {}
            for complaint in recent_complaints:
                subject = complaint.subject
                subject_counts[subject] = subject_counts.get(subject, 0) + 1
            
            # State breakdown
            state_counts = {}
            for complaint in recent_complaints:
                state = complaint.consumer_state
                state_counts[state] = state_counts.get(state, 0) + 1
            
            # Top complaint numbers
            phone_counts = {}
            for complaint in recent_complaints:
                phone = complaint.phone_number
                phone_counts[phone] = phone_counts.get(phone, 0) + 1
            
            return {
                'total_complaints': total_complaints,
                'robocall_percentage': (robocall_complaints / max(total_complaints, 1)) * 100,
                'top_subjects': sorted(subject_counts.items(), key=lambda x: x[1], reverse=True)[:5],
                'top_states': sorted(state_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                'top_numbers': sorted(phone_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                'daily_average': total_complaints / days_back,
                'analysis_date': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise ScamSourceError(f"Failed to get complaint statistics: {e}")
    
    async def check_number_complaints(self, phone_number: str) -> Dict[str, Any]:
        """Check complaint history for specific phone number"""
        try:
            # Search for complaints about this number
            complaints = await self._search_complaints(phone_number, 100)
            
            if not complaints:
                return {
                    'phone_number': phone_number,
                    'complaint_count': 0,
                    'risk_level': 'unknown',
                    'first_complaint': None,
                    'last_complaint': None,
                    'common_subjects': []
                }
            
            # Analyze complaints
            complaint_count = len(complaints)
            complaint_dates = [c.complaint_date for c in complaints]
            subjects = [c.subject for c in complaints]
            
            # Risk assessment
            if complaint_count > 50:
                risk_level = 'high'
            elif complaint_count > 10:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            # Subject analysis
            subject_counts = {}
            for subject in subjects:
                subject_counts[subject] = subject_counts.get(subject, 0) + 1
            
            common_subjects = sorted(subject_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            
            return {
                'phone_number': phone_number,
                'complaint_count': complaint_count,
                'risk_level': risk_level,
                'first_complaint': min(complaint_dates).isoformat(),
                'last_complaint': max(complaint_dates).isoformat(),
                'common_subjects': [subject for subject, count in common_subjects],
                'robocall_percentage': len([c for c in complaints if c.robocall]) / complaint_count * 100
            }
            
        except Exception as e:
            raise ScamSourceError(f"Failed to check number complaints: {e}")

import asyncio
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

import httpx
from pydantic import BaseModel


@dataclass
class FTCComplaint:
    """FTC DNC complaint record."""
    complaint_id: str
    phone_number: str
    caller_id_name: str
    date_received: datetime
    city: str
    state: str
    zip_code: str
    subject: str
    is_robocall: bool
    call_type: str
    company_name: str = None
    description: str = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'complaint_id': self.complaint_id,
            'phone_number': self.phone_number,
            'caller_id_name': self.caller_id_name,
            'date_received': self.date_received.isoformat(),
            'city': self.city,
            'state': self.state,
            'zip_code': self.zip_code,
            'subject': self.subject,
            'is_robocall': self.is_robocall,
            'call_type': self.call_type,
            'company_name': self.company_name,
            'description': self.description
        }


class FTCDNCCache:
    """Caching system for FTC DNC data."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize FTC DNC cache database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ftc_complaints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    complaint_id TEXT UNIQUE,
                    phone_number TEXT,
                    caller_id_name TEXT,
                    date_received TIMESTAMP,
                    city TEXT,
                    state TEXT,
                    zip_code TEXT,
                    subject TEXT,
                    is_robocall BOOLEAN,
                    call_type TEXT,
                    company_name TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_phone_number 
                ON ftc_complaints(phone_number)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_state_city 
                ON ftc_complaints(state, city)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_date_received 
                ON ftc_complaints(date_received)
            ''')
            
            # Cache metadata table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ftc_cache_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT UNIQUE,
                    last_updated TIMESTAMP,
                    expires_at TIMESTAMP,
                    record_count INTEGER
                )
            ''')
    
    def cache_complaints(self, complaints: List[FTCComplaint], 
                        cache_key: str, ttl_minutes: int = 30) -> bool:
        """Cache FTC complaints with TTL."""
        try:
            expires_at = datetime.now() + timedelta(minutes=ttl_minutes)
            
            with sqlite3.connect(self.db_path) as conn:
                # Insert/update complaints
                for complaint in complaints:
                    conn.execute('''
                        INSERT OR REPLACE INTO ftc_complaints 
                        (complaint_id, phone_number, caller_id_name, date_received,
                         city, state, zip_code, subject, is_robocall, call_type,
                         company_name, description, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        complaint.complaint_id, complaint.phone_number,
                        complaint.caller_id_name, complaint.date_received,
                        complaint.city, complaint.state, complaint.zip_code,
                        complaint.subject, complaint.is_robocall, complaint.call_type,
                        complaint.company_name, complaint.description, datetime.now()
                    ))
                
                # Update cache metadata
                conn.execute('''
                    INSERT OR REPLACE INTO ftc_cache_metadata 
                    (cache_key, last_updated, expires_at, record_count)
                    VALUES (?, ?, ?, ?)
                ''', (cache_key, datetime.now(), expires_at, len(complaints)))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error caching FTC complaints: {e}")
            return False
    
    def get_cached_complaints(self, cache_key: str) -> Optional[List[FTCComplaint]]:
        """Get cached complaints if not expired."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Check cache metadata
                metadata = conn.execute('''
                    SELECT * FROM ftc_cache_metadata 
                    WHERE cache_key = ? AND expires_at > ?
                ''', (cache_key, datetime.now())).fetchone()
                
                if not metadata:
                    return None
                
                # Get complaints
                rows = conn.execute('''
                    SELECT * FROM ftc_complaints 
                    WHERE updated_at >= ?
                    ORDER BY date_received DESC
                ''', (metadata['last_updated'],)).fetchall()
                
                complaints = []
                for row in rows:
                    complaints.append(FTCComplaint(
                        complaint_id=row['complaint_id'],
                        phone_number=row['phone_number'],
                        caller_id_name=row['caller_id_name'],
                        date_received=datetime.fromisoformat(row['date_received']),
                        city=row['city'],
                        state=row['state'],
                        zip_code=row['zip_code'],
                        subject=row['subject'],
                        is_robocall=bool(row['is_robocall']),
                        call_type=row['call_type'],
                        company_name=row['company_name'],
                        description=row['description']
                    ))
                
                return complaints
                
        except Exception as e:
            print(f"Error getting cached complaints: {e}")
            return None
    
    def search_complaints(self, phone_number: str = None, state: str = None,
                         city: str = None, since_days: int = 30) -> List[FTCComplaint]:
        """Search cached complaints by criteria."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = '''
                    SELECT * FROM ftc_complaints 
                    WHERE date_received >= ?
                '''
                params = [datetime.now() - timedelta(days=since_days)]
                
                if phone_number:
                    query += ' AND phone_number = ?'
                    params.append(phone_number)
                
                if state:
                    query += ' AND state = ?'
                    params.append(state.upper())
                
                if city:
                    query += ' AND city LIKE ?'
                    params.append(f'%{city}%')
                
                query += ' ORDER BY date_received DESC LIMIT 1000'
                
                rows = conn.execute(query, params).fetchall()
                
                complaints = []
                for row in rows:
                    complaints.append(FTCComplaint(
                        complaint_id=row['complaint_id'],
                        phone_number=row['phone_number'],
                        caller_id_name=row['caller_id_name'],
                        date_received=datetime.fromisoformat(row['date_received']),
                        city=row['city'],
                        state=row['state'],
                        zip_code=row['zip_code'],
                        subject=row['subject'],
                        is_robocall=bool(row['is_robocall']),
                        call_type=row['call_type'],
                        company_name=row['company_name'],
                        description=row['description']
                    ))
                
                return complaints
                
        except Exception as e:
            print(f"Error searching complaints: {e}")
            return []


class FTCDNCClient:
    """FTC Do Not Call API client."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.cache = FTCDNCCache(config_dir / "ftc_dnc.db")
        
        # FTC Consumer Sentinel API endpoints
        self.base_url = "https://api.consumersentinel.gov"
        self.complaints_endpoint = "/v1/complaints"
        
        # Rate limiting
        self.rate_limit_delay = 1.0  # seconds between requests
        self.last_request_time = 0
    
    async def _rate_limited_request(self, url: str, params: Dict = None) -> Optional[Dict]:
        """Make rate-limited HTTP request."""
        # Implement rate limiting
        current_time = asyncio.get_event_loop().time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, params=params)
                self.last_request_time = asyncio.get_event_loop().time()
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:  # Rate limited
                    await asyncio.sleep(5.0)  # Wait longer and retry
                    return await self._rate_limited_request(url, params)
                else:
                    print(f"FTC API error: {response.status_code}")
                    return None
                    
        except Exception as e:
            print(f"FTC API request failed: {e}")
            return None
    
    def _generate_cache_key(self, state: str = None, city: str = None, 
                           since_days: int = 7) -> str:
        """Generate cache key for request parameters."""
        parts = [f"since_{since_days}"]
        if state:
            parts.append(f"state_{state}")
        if city:
            parts.append(f"city_{city}")
        return "_".join(parts)
    
    async def fetch_complaints(self, state: str = None, city: str = None,
                              since_days: int = 7, use_cache: bool = True) -> List[FTCComplaint]:
        """
        Fetch FTC DNC complaints.
        
        Args:
            state: State abbreviation (e.g., 'CA', 'NY')
            city: City name
            since_days: Number of days back to fetch
            use_cache: Whether to use cached data
            
        Returns:
            List of FTC complaints
        """
        cache_key = self._generate_cache_key(state, city, since_days)
        
        # Check cache first
        if use_cache:
            cached_complaints = self.cache.get_cached_complaints(cache_key)
            if cached_complaints:
                return cached_complaints
        
        # Fetch from API
        complaints = await self._fetch_from_api(state, city, since_days)
        
        # Cache results
        if complaints:
            self.cache.cache_complaints(complaints, cache_key, ttl_minutes=30)
        
        return complaints
    
    async def _fetch_from_api(self, state: str = None, city: str = None,
                             since_days: int = 7) -> List[FTCComplaint]:
        """Fetch complaints from FTC API."""
        # Note: This is a mock implementation since the actual FTC API
        # may require authentication and have different endpoints
        
        # In a real implementation, you would:
        # 1. Get API credentials
        # 2. Make authenticated requests to FTC Consumer Sentinel API
        # 3. Parse the response format
        
        # For now, return mock data based on parameters
        complaints = []
        
        # Generate mock complaints for demonstration
        base_date = datetime.now() - timedelta(days=since_days)
        
        mock_complaints_data = [
            {
                'phone': '8005551234',
                'caller_name': 'Unknown',
                'subject': 'Robocall - Health Insurance',
                'city': city or 'New York',
                'state': state or 'NY',
                'is_robocall': True,
                'call_type': 'telemarketing'
            },
            {
                'phone': '8005555678',
                'caller_name': 'Auto Warranty',
                'subject': 'Extended Car Warranty',
                'city': city or 'Los Angeles',
                'state': state or 'CA',
                'is_robocall': True,
                'call_type': 'telemarketing'
            },
            {
                'phone': '5551234567',
                'caller_name': 'Unknown',
                'subject': 'Social Security Scam',
                'city': city or 'Chicago',
                'state': state or 'IL',
                'is_robocall': False,
                'call_type': 'scam'
            }
        ]
        
        for i, mock_data in enumerate(mock_complaints_data):
            complaint = FTCComplaint(
                complaint_id=f"FTC_{datetime.now().strftime('%Y%m%d')}_{i:04d}",
                phone_number=mock_data['phone'],
                caller_id_name=mock_data['caller_name'],
                date_received=base_date + timedelta(days=i),
                city=mock_data['city'],
                state=mock_data['state'],
                zip_code='12345',
                subject=mock_data['subject'],
                is_robocall=mock_data['is_robocall'],
                call_type=mock_data['call_type'],
                description=f"Consumer complaint about {mock_data['subject']}"
            )
            complaints.append(complaint)
        
        return complaints
    
    async def search_by_phone(self, phone_number: str) -> List[FTCComplaint]:
        """Search complaints by phone number."""
        # Clean phone number
        clean_phone = ''.join(filter(str.isdigit, phone_number))
        if len(clean_phone) == 11 and clean_phone.startswith('1'):
            clean_phone = clean_phone[1:]
        
        # Search in cache first
        cached_complaints = self.cache.search_complaints(phone_number=clean_phone)
        
        if cached_complaints:
            return cached_complaints
        
        # If not in cache, this would typically trigger an API search
        # For now, return empty list
        return []
    
    def get_trending_numbers(self, state: str = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Get trending scam numbers by complaint frequency."""
        try:
            with sqlite3.connect(self.cache.db_path) as conn:
                query = '''
                    SELECT phone_number, caller_id_name, COUNT(*) as complaint_count,
                           MAX(date_received) as last_complaint,
                           SUM(CASE WHEN is_robocall = 1 THEN 1 ELSE 0 END) as robocall_count,
                           GROUP_CONCAT(DISTINCT subject) as subjects
                    FROM ftc_complaints
                    WHERE date_received >= ?
                '''
                params = [datetime.now() - timedelta(days=30)]
                
                if state:
                    query += ' AND state = ?'
                    params.append(state.upper())
                
                query += '''
                    GROUP BY phone_number
                    HAVING complaint_count > 1
                    ORDER BY complaint_count DESC, last_complaint DESC
                    LIMIT ?
                '''
                params.append(limit)
                
                rows = conn.execute(query, params).fetchall()
                
                trending = []
                for row in rows:
                    trending.append({
                        'phone_number': row[0],
                        'caller_id_name': row[1],
                        'complaint_count': row[2],
                        'last_complaint': row[3],
                        'robocall_count': row[4],
                        'subjects': row[5].split(',') if row[5] else [],
                        'robocall_percentage': (row[4] / row[2]) * 100 if row[2] > 0 else 0
                    })
                
                return trending
                
        except Exception as e:
            print(f"Error getting trending numbers: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get FTC DNC statistics."""
        try:
            with sqlite3.connect(self.cache.db_path) as conn:
                # Total complaints
                total = conn.execute('SELECT COUNT(*) FROM ftc_complaints').fetchone()[0]
                
                # Recent complaints (last 7 days)
                week_ago = datetime.now() - timedelta(days=7)
                recent = conn.execute(
                    'SELECT COUNT(*) FROM ftc_complaints WHERE date_received >= ?',
                    (week_ago,)
                ).fetchone()[0]
                
                # Robocall percentage
                robocall_count = conn.execute(
                    'SELECT COUNT(*) FROM ftc_complaints WHERE is_robocall = 1'
                ).fetchone()[0]
                
                # Top states
                top_states = conn.execute('''
                    SELECT state, COUNT(*) as count
                    FROM ftc_complaints
                    GROUP BY state
                    ORDER BY count DESC
                    LIMIT 10
                ''').fetchall()
                
                # Top call types
                top_types = conn.execute('''
                    SELECT call_type, COUNT(*) as count
                    FROM ftc_complaints
                    GROUP BY call_type
                    ORDER BY count DESC
                    LIMIT 10
                ''').fetchall()
                
                return {
                    'total_complaints': total,
                    'recent_complaints': recent,
                    'robocall_complaints': robocall_count,
                    'robocall_percentage': (robocall_count / total * 100) if total > 0 else 0,
                    'top_states': [{'state': row[0], 'count': row[1]} for row in top_states],
                    'top_call_types': [{'type': row[0], 'count': row[1]} for row in top_types]
                }
                
        except Exception as e:
            return {'error': str(e)}
