"""
FCC Consumer Complaints API integration for unwanted calls dataset
Access to FCC consumer complaint data via Socrata API
"""
import asyncio
import httpx
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from .base import ScamSource, ScamSourceError
from ..database import ScamRecord


@dataclass
class FCCComplaint:
    """FCC consumer complaint data"""
    complaint_id: str
    date_received: datetime
    issue: str
    sub_issue: Optional[str]
    consumer_complaint_narrative: str
    company_response: Optional[str]
    company: Optional[str]
    state: str
    zip_code: Optional[str]
    phone_number: Optional[str]
    submission_method: str
    date_sent_to_company: Optional[datetime]
    company_response_to_consumer: Optional[str]
    timely_response: Optional[bool]
    consumer_disputed: Optional[bool]
    
    def to_scam_record(self) -> ScamRecord:
        """Convert FCC complaint to ScamRecord"""
        # Calculate severity based on issue type and content
        severity = 5.0  # Base severity
        
        issue_lower = self.issue.lower()
        narrative_lower = self.consumer_complaint_narrative.lower()
        
        # Increase severity for certain issues
        if 'unwanted' in issue_lower or 'robocall' in issue_lower:
            severity += 2.0
        if 'fraud' in narrative_lower or 'scam' in narrative_lower:
            severity += 3.0
        if 'harassment' in issue_lower:
            severity += 1.5
        
        # Determine scam type
        if 'robocall' in issue_lower:
            scam_type = 'robocall'
        elif 'text' in issue_lower or 'sms' in issue_lower:
            scam_type = 'spam_text'
        elif 'harassment' in issue_lower:
            scam_type = 'harassment'
        else:
            scam_type = 'unwanted_call'
        
        return ScamRecord(
            title=f"FCC Complaint: {self.issue}",
            description=self.consumer_complaint_narrative,
            scam_type=scam_type,
            source='fcc',
            source_id=self.complaint_id,
            phone=self.phone_number,
            location=f"{self.zip_code}, {self.state}" if self.zip_code else self.state,
            severity=min(severity, 10.0),
            confidence=0.75,  # FCC complaints are generally reliable
            first_seen=self.date_received,
            tags=['fcc', 'consumer_complaint', 'telecommunications'],
            raw_data={
                'sub_issue': self.sub_issue,
                'company': self.company,
                'submission_method': self.submission_method,
                'company_response': self.company_response,
                'timely_response': self.timely_response,
                'consumer_disputed': self.consumer_disputed
            }
        )


class FCCComplaintsClient(ScamSource):
    """FCC Consumer Complaints API client"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("fcc", api_key)
        self.base_url = "https://opendata.fcc.gov/api/views"
        self.dataset_id = "5fyg-hkzq"  # Consumer Complaints dataset
        self.rate_limit_delay = 1.0
        
        # Issue categories that indicate scams/unwanted calls
        self.scam_issues = {
            'Phone': [
                'Unwanted calls or texts',
                'Robocalls',
                'Call blocking',
                'Slamming and cramming'
            ],
            'Internet': [
                'Unwanted messages (spam)',
                'Phishing'
            ]
        }
        
        # Sub-issues that indicate specific scam types
        self.scam_sub_issues = [
            'Robocall', 'Auto-dialed live call', 'Recorded message',
            'Text message (SMS)', 'Multimedia message (MMS)',
            'Phishing', 'Spam', 'Harassment'
        ]
    
    def is_configured(self) -> bool:
        """Check if FCC API is configured"""
        return True  # FCC API is public, no auth required
    
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """Fetch recent FCC complaints related to scams"""
        try:
            complaints = await self._fetch_complaints(limit)
            scam_records = []
            
            for complaint in complaints:
                if self._is_scam_related(complaint):
                    scam_record = complaint.to_scam_record()
                    scam_records.append(scam_record)
            
            return scam_records
            
        except Exception as e:
            raise ScamSourceError(f"Failed to fetch FCC complaints: {e}")
    
    async def search_scams(self, query: str, limit: int = 50) -> List[ScamRecord]:
        """Search FCC complaints by query"""
        try:
            complaints = await self._search_complaints(query, limit)
            scam_records = []
            
            for complaint in complaints:
                if self._is_scam_related(complaint):
                    scam_record = complaint.to_scam_record()
                    scam_records.append(scam_record)
            
            return scam_records
            
        except Exception as e:
            raise ScamSourceError(f"Failed to search FCC complaints: {e}")
    
    async def get_complaints_by_state(self, state: str, days_back: int = 30) -> List[FCCComplaint]:
        """Get FCC complaints for specific state"""
        try:
            return await self._fetch_complaints_by_location(state, days_back)
        except Exception as e:
            raise ScamSourceError(f"Failed to fetch state complaints: {e}")
    
    async def get_robocall_trends(self, days_back: int = 30) -> Dict[str, Any]:
        """Get robocall complaint trends"""
        try:
            complaints = await self._fetch_complaints(1000)
            
            # Filter for robocall complaints
            robocall_complaints = [
                c for c in complaints 
                if 'robocall' in c.issue.lower() or 'robocall' in c.consumer_complaint_narrative.lower()
            ]
            
            # Filter by date
            cutoff_date = datetime.now() - timedelta(days=days_back)
            recent_robocalls = [
                c for c in robocall_complaints 
                if c.date_received >= cutoff_date
            ]
            
            # Analyze trends
            daily_counts = {}
            for complaint in recent_robocalls:
                day_key = complaint.date_received.strftime('%Y-%m-%d')
                daily_counts[day_key] = daily_counts.get(day_key, 0) + 1
            
            # State breakdown
            state_counts = {}
            for complaint in recent_robocalls:
                state = complaint.state
                state_counts[state] = state_counts.get(state, 0) + 1
            
            # Company breakdown
            company_counts = {}
            for complaint in recent_robocalls:
                if complaint.company:
                    company = complaint.company
                    company_counts[company] = company_counts.get(company, 0) + 1
            
            return {
                'total_robocall_complaints': len(recent_robocalls),
                'daily_average': len(recent_robocalls) / days_back,
                'daily_counts': daily_counts,
                'top_states': sorted(state_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                'top_companies': sorted(company_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                'analysis_period_days': days_back,
                'analysis_date': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise ScamSourceError(f"Failed to get robocall trends: {e}")
    
    async def _fetch_complaints(self, limit: int) -> List[FCCComplaint]:
        """Fetch complaints from FCC Socrata API (mock implementation)"""
        # In production, this would make actual API calls to FCC Socrata API
        # URL would be something like: f"{self.base_url}/{self.dataset_id}/data.json"
        
        await asyncio.sleep(0.3)  # Simulate API delay
        
        # Generate mock FCC complaints
        complaints = []
        base_date = datetime.now() - timedelta(days=60)
        
        issues = [
            "Unwanted calls or texts",
            "Robocalls", 
            "Call blocking",
            "Slamming and cramming",
            "Unwanted messages (spam)",
            "Phishing"
        ]
        
        sub_issues = [
            "Robocall", "Auto-dialed live call", "Recorded message",
            "Text message (SMS)", "Multimedia message (MMS)",
            "Phishing", "Spam", "Harassment", None
        ]
        
        narratives = [
            "Received multiple robocalls per day from this number offering fake services",
            "Automated call claiming to be from my bank requesting personal information", 
            "Unwanted text messages with suspicious links sent multiple times daily",
            "Robocall about car warranty that I never requested, very persistent",
            "Fake tech support call claiming my computer was infected with virus",
            "Phishing call pretending to be from government agency requesting SSN",
            "Harassment calls at all hours of day and night from unknown numbers",
            "Spam text messages promoting get-rich-quick schemes"
        ]
        
        companies = [
            "Unknown", "Telemarketing Company A", "Robocall Service Inc", 
            "Spam Corp", "Fake Bank Ltd", None
        ]
        
        states = ["CA", "NY", "TX", "FL", "IL", "PA", "OH", "GA", "NC", "MI", "NJ", "VA"]
        
        submission_methods = ["Web", "Phone", "Mobile app", "Email"]
        
        for i in range(min(limit, 200)):
            complaint_date = base_date + timedelta(days=i % 60, hours=i % 24)
            
            complaint = FCCComplaint(
                complaint_id=f"FCC-{2000000 + i}",
                date_received=complaint_date,
                issue=issues[i % len(issues)],
                sub_issue=sub_issues[i % len(sub_issues)],
                consumer_complaint_narrative=narratives[i % len(narratives)],
                company_response="In progress" if i % 3 == 0 else None,
                company=companies[i % len(companies)],
                state=states[i % len(states)],
                zip_code=f"{10001 + i % 90000:05d}" if i % 2 == 0 else None,
                phone_number=f"800-555-{1000 + i % 9000:04d}" if i % 3 == 0 else None,
                submission_method=submission_methods[i % len(submission_methods)],
                date_sent_to_company=complaint_date + timedelta(days=1) if i % 4 == 0 else None,
                company_response_to_consumer="Closed with explanation" if i % 5 == 0 else None,
                timely_response=i % 3 == 0,
                consumer_disputed=i % 7 == 0
            )
            
            complaints.append(complaint)
        
        return complaints
    
    async def _search_complaints(self, query: str, limit: int) -> List[FCCComplaint]:
        """Search complaints by query"""
        all_complaints = await self._fetch_complaints(limit * 2)
        
        # Filter complaints based on query
        matching_complaints = []
        query_lower = query.lower()
        
        for complaint in all_complaints:
            if (query_lower in complaint.issue.lower() or
                query_lower in complaint.consumer_complaint_narrative.lower() or
                (complaint.phone_number and query_lower in complaint.phone_number) or
                (complaint.company and query_lower in complaint.company.lower()) or
                (complaint.state and query_lower in complaint.state.lower()) or
                (complaint.zip_code and query_lower in complaint.zip_code)):
                matching_complaints.append(complaint)
        
        return matching_complaints[:limit]
    
    async def _fetch_complaints_by_location(self, state: str, days_back: int) -> List[FCCComplaint]:
        """Fetch complaints for specific location"""
        all_complaints = await self._fetch_complaints(300)
        
        # Filter by state and date
        cutoff_date = datetime.now() - timedelta(days=days_back)
        location_complaints = []
        
        for complaint in all_complaints:
            if (complaint.state.upper() == state.upper() and
                complaint.date_received >= cutoff_date):
                location_complaints.append(complaint)
        
        return location_complaints
    
    def _is_scam_related(self, complaint: FCCComplaint) -> bool:
        """Determine if FCC complaint is scam-related"""
        
        # Check if issue is in scam categories
        for category, issues in self.scam_issues.items():
            if complaint.issue in issues:
                return True
        
        # Check sub-issue
        if complaint.sub_issue and complaint.sub_issue in self.scam_sub_issues:
            return True
        
        # Check narrative for scam indicators
        scam_keywords = [
            'scam', 'fraud', 'phishing', 'fake', 'robocall', 'spam',
            'harassment', 'unwanted', 'suspicious', 'deceptive'
        ]
        
        narrative_lower = complaint.consumer_complaint_narrative.lower()
        if any(keyword in narrative_lower for keyword in scam_keywords):
            return True
        
        return False
    
    async def get_complaint_statistics(self, days_back: int = 30) -> Dict[str, Any]:
        """Get FCC complaint statistics"""
        try:
            complaints = await self._fetch_complaints(1000)
            
            # Filter by date range
            cutoff_date = datetime.now() - timedelta(days=days_back)
            recent_complaints = [c for c in complaints if c.date_received >= cutoff_date]
            
            # Calculate statistics
            total_complaints = len(recent_complaints)
            
            # Issue breakdown
            issue_counts = {}
            for complaint in recent_complaints:
                issue = complaint.issue
                issue_counts[issue] = issue_counts.get(issue, 0) + 1
            
            # State breakdown
            state_counts = {}
            for complaint in recent_complaints:
                state = complaint.state
                state_counts[state] = state_counts.get(state, 0) + 1
            
            # Submission method breakdown
            method_counts = {}
            for complaint in recent_complaints:
                method = complaint.submission_method
                method_counts[method] = method_counts.get(method, 0) + 1
            
            # Company response analysis
            company_response_counts = {}
            for complaint in recent_complaints:
                if complaint.company_response_to_consumer:
                    response = complaint.company_response_to_consumer
                    company_response_counts[response] = company_response_counts.get(response, 0) + 1
            
            # Timely response rate
            timely_responses = len([c for c in recent_complaints if c.timely_response])
            timely_response_rate = (timely_responses / max(total_complaints, 1)) * 100
            
            # Dispute rate
            disputed_complaints = len([c for c in recent_complaints if c.consumer_disputed])
            dispute_rate = (disputed_complaints / max(total_complaints, 1)) * 100
            
            return {
                'total_complaints': total_complaints,
                'daily_average': total_complaints / days_back,
                'top_issues': sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:5],
                'top_states': sorted(state_counts.items(), key=lambda x: x[1], reverse=True)[:10],
                'submission_methods': sorted(method_counts.items(), key=lambda x: x[1], reverse=True),
                'company_responses': sorted(company_response_counts.items(), key=lambda x: x[1], reverse=True)[:5],
                'timely_response_rate': timely_response_rate,
                'dispute_rate': dispute_rate,
                'analysis_date': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise ScamSourceError(f"Failed to get FCC complaint statistics: {e}")
    
    async def get_trending_issues(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Get trending complaint issues"""
        try:
            complaints = await self._fetch_complaints(500)
            
            # Get recent and previous periods
            cutoff_recent = datetime.now() - timedelta(days=days_back)
            cutoff_previous = datetime.now() - timedelta(days=days_back * 2)
            
            recent_complaints = [c for c in complaints if c.date_received >= cutoff_recent]
            previous_complaints = [
                c for c in complaints 
                if cutoff_previous <= c.date_received < cutoff_recent
            ]
            
            # Count issues for both periods
            recent_issue_counts = {}
            for complaint in recent_complaints:
                issue = complaint.issue
                recent_issue_counts[issue] = recent_issue_counts.get(issue, 0) + 1
            
            previous_issue_counts = {}
            for complaint in previous_complaints:
                issue = complaint.issue
                previous_issue_counts[issue] = previous_issue_counts.get(issue, 0) + 1
            
            # Calculate trends
            trending_issues = []
            for issue, recent_count in recent_issue_counts.items():
                previous_count = previous_issue_counts.get(issue, 0)
                
                if previous_count > 0:
                    change_percentage = ((recent_count - previous_count) / previous_count) * 100
                else:
                    change_percentage = 100.0 if recent_count > 0 else 0.0
                
                trending_issues.append({
                    'issue': issue,
                    'recent_count': recent_count,
                    'previous_count': previous_count,
                    'change_percentage': change_percentage,
                    'trend': 'increasing' if change_percentage > 10 else 'decreasing' if change_percentage < -10 else 'stable'
                })
            
            # Sort by change percentage
            trending_issues.sort(key=lambda x: x['change_percentage'], reverse=True)
            
            return trending_issues[:10]
            
        except Exception as e:
            raise ScamSourceError(f"Failed to get trending issues: {e}")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers (FCC API doesn't require auth)"""
        return {
            "User-Agent": "EagleEye CLI/1.0"
        }

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
class FCCComplaint:
    """FCC consumer complaint record."""
    complaint_id: str
    date_received: datetime
    issue_type: str
    state: str
    zip_code: str
    phone_number: str = None
    company_name: str = None
    description: str = None
    resolution: str = None
    city: str = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'complaint_id': self.complaint_id,
            'date_received': self.date_received.isoformat(),
            'issue_type': self.issue_type,
            'state': self.state,
            'zip_code': self.zip_code,
            'phone_number': self.phone_number,
            'company_name': self.company_name,
            'description': self.description,
            'resolution': self.resolution,
            'city': self.city
        }


class FCCComplaintsCache:
    """Caching system for FCC complaints data."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize FCC complaints cache database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS fcc_complaints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    complaint_id TEXT UNIQUE,
                    date_received TIMESTAMP,
                    issue_type TEXT,
                    state TEXT,
                    zip_code TEXT,
                    phone_number TEXT,
                    company_name TEXT,
                    description TEXT,
                    resolution TEXT,
                    city TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_fcc_state_zip 
                ON fcc_complaints(state, zip_code)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_fcc_date_received 
                ON fcc_complaints(date_received)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_fcc_issue_type 
                ON fcc_complaints(issue_type)
            ''')
            
            # Cache metadata table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS fcc_cache_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT UNIQUE,
                    last_updated TIMESTAMP,
                    expires_at TIMESTAMP,
                    record_count INTEGER
                )
            ''')
    
    def cache_complaints(self, complaints: List[FCCComplaint], 
                        cache_key: str, ttl_minutes: int = 30) -> bool:
        """Cache FCC complaints with TTL."""
        try:
            expires_at = datetime.now() + timedelta(minutes=ttl_minutes)
            
            with sqlite3.connect(self.db_path) as conn:
                # Insert/update complaints
                for complaint in complaints:
                    conn.execute('''
                        INSERT OR REPLACE INTO fcc_complaints 
                        (complaint_id, date_received, issue_type, state, zip_code,
                         phone_number, company_name, description, resolution, city, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        complaint.complaint_id, complaint.date_received,
                        complaint.issue_type, complaint.state, complaint.zip_code,
                        complaint.phone_number, complaint.company_name,
                        complaint.description, complaint.resolution, complaint.city,
                        datetime.now()
                    ))
                
                # Update cache metadata
                conn.execute('''
                    INSERT OR REPLACE INTO fcc_cache_metadata 
                    (cache_key, last_updated, expires_at, record_count)
                    VALUES (?, ?, ?, ?)
                ''', (cache_key, datetime.now(), expires_at, len(complaints)))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error caching FCC complaints: {e}")
            return False
    
    def get_cached_complaints(self, cache_key: str) -> Optional[List[FCCComplaint]]:
        """Get cached complaints if not expired."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Check cache metadata
                metadata = conn.execute('''
                    SELECT * FROM fcc_cache_metadata 
                    WHERE cache_key = ? AND expires_at > ?
                ''', (cache_key, datetime.now())).fetchone()
                
                if not metadata:
                    return None
                
                # Get complaints
                rows = conn.execute('''
                    SELECT * FROM fcc_complaints 
                    WHERE updated_at >= ?
                    ORDER BY date_received DESC
                ''', (metadata['last_updated'],)).fetchall()
                
                complaints = []
                for row in rows:
                    complaints.append(FCCComplaint(
                        complaint_id=row['complaint_id'],
                        date_received=datetime.fromisoformat(row['date_received']),
                        issue_type=row['issue_type'],
                        state=row['state'],
                        zip_code=row['zip_code'],
                        phone_number=row['phone_number'],
                        company_name=row['company_name'],
                        description=row['description'],
                        resolution=row['resolution'],
                        city=row['city']
                    ))
                
                return complaints
                
        except Exception as e:
            print(f"Error getting cached FCC complaints: {e}")
            return None
    
    def search_complaints(self, state: str = None, zip_code: str = None,
                         issue_type: str = None, since_days: int = 30) -> List[FCCComplaint]:
        """Search cached complaints by criteria."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = '''
                    SELECT * FROM fcc_complaints 
                    WHERE date_received >= ?
                '''
                params = [datetime.now() - timedelta(days=since_days)]
                
                if state:
                    query += ' AND state = ?'
                    params.append(state.upper())
                
                if zip_code:
                    query += ' AND zip_code = ?'
                    params.append(zip_code)
                
                if issue_type:
                    query += ' AND issue_type LIKE ?'
                    params.append(f'%{issue_type}%')
                
                query += ' ORDER BY date_received DESC LIMIT 1000'
                
                rows = conn.execute(query, params).fetchall()
                
                complaints = []
                for row in rows:
                    complaints.append(FCCComplaint(
                        complaint_id=row['complaint_id'],
                        date_received=datetime.fromisoformat(row['date_received']),
                        issue_type=row['issue_type'],
                        state=row['state'],
                        zip_code=row['zip_code'],
                        phone_number=row['phone_number'],
                        company_name=row['company_name'],
                        description=row['description'],
                        resolution=row['resolution'],
                        city=row['city']
                    ))
                
                return complaints
                
        except Exception as e:
            print(f"Error searching FCC complaints: {e}")
            return []


class FCCComplaintsClient:
    """FCC Consumer Complaints API client using Socrata."""
    
    def __init__(self, config_dir: Path, app_token: str = None):
        self.config_dir = config_dir
        self.cache = FCCComplaintsCache(config_dir / "fcc_complaints.db")
        self.app_token = app_token
        
        # FCC Consumer Complaints Socrata API
        self.base_url = "https://opendata.fcc.gov/resource"
        self.dataset_id = "3xyp-aqkj"  # FCC Consumer Complaints dataset
        self.api_url = f"{self.base_url}/{self.dataset_id}.json"
        
        # Rate limiting
        self.rate_limit_delay = 0.5  # seconds between requests
        self.last_request_time = 0
    
    async def _rate_limited_request(self, url: str, params: Dict = None) -> Optional[List[Dict]]:
        """Make rate-limited HTTP request to Socrata API."""
        # Implement rate limiting
        current_time = asyncio.get_event_loop().time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        
        try:
            headers = {}
            if self.app_token:
                headers['X-App-Token'] = self.app_token
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, params=params, headers=headers)
                self.last_request_time = asyncio.get_event_loop().time()
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:  # Rate limited
                    await asyncio.sleep(2.0)  # Wait and retry
                    return await self._rate_limited_request(url, params)
                else:
                    print(f"FCC API error: {response.status_code}")
                    return None
                    
        except Exception as e:
            print(f"FCC API request failed: {e}")
            return None
    
    def _generate_cache_key(self, state: str = None, zip_code: str = None,
                           issue_type: str = None, since_days: int = 7) -> str:
        """Generate cache key for request parameters."""
        parts = [f"since_{since_days}"]
        if state:
            parts.append(f"state_{state}")
        if zip_code:
            parts.append(f"zip_{zip_code}")
        if issue_type:
            parts.append(f"issue_{issue_type}")
        return "_".join(parts)
    
    async def fetch_complaints(self, state: str = None, zip_code: str = None,
                              issue_type: str = None, since_days: int = 7,
                              limit: int = 1000, use_cache: bool = True) -> List[FCCComplaint]:
        """
        Fetch FCC consumer complaints.
        
        Args:
            state: State abbreviation (e.g., 'CA', 'NY')
            zip_code: ZIP code
            issue_type: Type of issue (e.g., 'Unwanted calls')
            since_days: Number of days back to fetch
            limit: Maximum number of records to fetch
            use_cache: Whether to use cached data
            
        Returns:
            List of FCC complaints
        """
        cache_key = self._generate_cache_key(state, zip_code, issue_type, since_days)
        
        # Check cache first
        if use_cache:
            cached_complaints = self.cache.get_cached_complaints(cache_key)
            if cached_complaints:
                return cached_complaints
        
        # Fetch from API
        complaints = await self._fetch_from_api(state, zip_code, issue_type, since_days, limit)
        
        # Cache results
        if complaints:
            self.cache.cache_complaints(complaints, cache_key, ttl_minutes=30)
        
        return complaints
    
    async def _fetch_from_api(self, state: str = None, zip_code: str = None,
                             issue_type: str = None, since_days: int = 7,
                             limit: int = 1000) -> List[FCCComplaint]:
        """Fetch complaints from FCC Socrata API."""
        # Build query parameters
        params = {
            '$limit': limit,
            '$order': 'date_received DESC'
        }
        
        # Build WHERE clause
        where_conditions = []
        
        # Date filter
        since_date = (datetime.now() - timedelta(days=since_days)).strftime('%Y-%m-%d')
        where_conditions.append(f"date_received >= '{since_date}'")
        
        # State filter
        if state:
            where_conditions.append(f"state = '{state.upper()}'")
        
        # ZIP code filter
        if zip_code:
            where_conditions.append(f"zip = '{zip_code}'")
        
        # Issue type filter (for unwanted calls)
        if issue_type:
            where_conditions.append(f"issue LIKE '%{issue_type}%'")
        else:
            # Default to unwanted calls related issues
            where_conditions.append("(issue LIKE '%Unwanted calls%' OR issue LIKE '%Robocalls%' OR issue LIKE '%Do Not Call%')")
        
        if where_conditions:
            params['$where'] = ' AND '.join(where_conditions)
        
        # Make API request
        data = await self._rate_limited_request(self.api_url, params)
        
        if not data:
            return []
        
        # Parse response into FCCComplaint objects
        complaints = []
        for record in data:
            try:
                # Parse date
                date_str = record.get('date_received', '')
                if date_str:
                    # Handle different date formats
                    try:
                        date_received = datetime.fromisoformat(date_str.replace('T', ' ').replace('Z', ''))
                    except:
                        date_received = datetime.strptime(date_str[:10], '%Y-%m-%d')
                else:
                    date_received = datetime.now()
                
                complaint = FCCComplaint(
                    complaint_id=record.get('complaint_id', f"FCC_{len(complaints)}"),
                    date_received=date_received,
                    issue_type=record.get('issue', 'Unknown'),
                    state=record.get('state', ''),
                    zip_code=record.get('zip', ''),
                    phone_number=record.get('phone_number'),
                    company_name=record.get('company_name'),
                    description=record.get('description'),
                    resolution=record.get('resolution'),
                    city=record.get('city')
                )
                complaints.append(complaint)
                
            except Exception as e:
                print(f"Error parsing FCC complaint record: {e}")
                continue
        
        return complaints
    
    async def get_unwanted_calls_by_location(self, state: str = None, 
                                           zip_code: str = None,
                                           since_days: int = 30) -> List[FCCComplaint]:
        """Get unwanted calls complaints by location."""
        return await self.fetch_complaints(
            state=state,
            zip_code=zip_code,
            issue_type="Unwanted calls",
            since_days=since_days,
            limit=1000
        )
    
    def get_trending_issues(self, state: str = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Get trending complaint issues by frequency."""
        try:
            with sqlite3.connect(self.cache.db_path) as conn:
                query = '''
                    SELECT issue_type, COUNT(*) as complaint_count,
                           MAX(date_received) as last_complaint,
                           GROUP_CONCAT(DISTINCT company_name) as companies
                    FROM fcc_complaints
                    WHERE date_received >= ?
                '''
                params = [datetime.now() - timedelta(days=30)]
                
                if state:
                    query += ' AND state = ?'
                    params.append(state.upper())
                
                query += '''
                    GROUP BY issue_type
                    HAVING complaint_count > 1
                    ORDER BY complaint_count DESC, last_complaint DESC
                    LIMIT ?
                '''
                params.append(limit)
                
                rows = conn.execute(query, params).fetchall()
                
                trending = []
                for row in rows:
                    trending.append({
                        'issue_type': row[0],
                        'complaint_count': row[1],
                        'last_complaint': row[2],
                        'companies': row[3].split(',') if row[3] else []
                    })
                
                return trending
                
        except Exception as e:
            print(f"Error getting trending issues: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get FCC complaints statistics."""
        try:
            with sqlite3.connect(self.cache.db_path) as conn:
                # Total complaints
                total = conn.execute('SELECT COUNT(*) FROM fcc_complaints').fetchone()[0]
                
                # Recent complaints (last 7 days)
                week_ago = datetime.now() - timedelta(days=7)
                recent = conn.execute(
                    'SELECT COUNT(*) FROM fcc_complaints WHERE date_received >= ?',
                    (week_ago,)
                ).fetchone()[0]
                
                # Unwanted calls complaints
                unwanted_calls = conn.execute('''
                    SELECT COUNT(*) FROM fcc_complaints 
                    WHERE issue_type LIKE '%Unwanted calls%' OR issue_type LIKE '%Robocalls%'
                ''').fetchone()[0]
                
                # Top states
                top_states = conn.execute('''
                    SELECT state, COUNT(*) as count
                    FROM fcc_complaints
                    WHERE state IS NOT NULL AND state != ''
                    GROUP BY state
                    ORDER BY count DESC
                    LIMIT 10
                ''').fetchall()
                
                # Top issue types
                top_issues = conn.execute('''
                    SELECT issue_type, COUNT(*) as count
                    FROM fcc_complaints
                    GROUP BY issue_type
                    ORDER BY count DESC
                    LIMIT 10
                ''').fetchall()
                
                # Top companies complained about
                top_companies = conn.execute('''
                    SELECT company_name, COUNT(*) as count
                    FROM fcc_complaints
                    WHERE company_name IS NOT NULL AND company_name != ''
                    GROUP BY company_name
                    ORDER BY count DESC
                    LIMIT 10
                ''').fetchall()
                
                return {
                    'total_complaints': total,
                    'recent_complaints': recent,
                    'unwanted_calls_complaints': unwanted_calls,
                    'unwanted_calls_percentage': (unwanted_calls / total * 100) if total > 0 else 0,
                    'top_states': [{'state': row[0], 'count': row[1]} for row in top_states],
                    'top_issues': [{'issue': row[0], 'count': row[1]} for row in top_issues],
                    'top_companies': [{'company': row[0], 'count': row[1]} for row in top_companies]
                }
                
        except Exception as e:
            return {'error': str(e)}
