"""
User reporting system for crowdsourced scam intelligence
Allows users to submit new scams for community validation and model improvement
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import sqlite3
from enum import Enum

from ..analysis import TextAnalyzer, VoiceAnalyzer
from ..database import ScamRecord


class ReportType(Enum):
    """Types of scam reports"""
    TEXT = "text"
    EMAIL = "email"
    VOICE = "voice"
    WEBSITE = "website"
    SMS = "sms"
    SOCIAL_MEDIA = "social_media"


class ReportStatus(Enum):
    """Status of user reports"""
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    INVESTIGATING = "investigating"


@dataclass
class UserReport:
    """User-submitted scam report"""
    report_id: str
    user_id: str
    report_type: ReportType
    content: str
    source_info: Dict[str, Any]
    location: Optional[str]
    timestamp: datetime
    status: ReportStatus
    confidence_score: float
    analysis_results: Dict[str, Any]
    verification_votes: int = 0
    rejection_votes: int = 0
    moderator_notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'report_id': self.report_id,
            'user_id': self.user_id,
            'report_type': self.report_type.value,
            'content': self.content,
            'source_info': self.source_info,
            'location': self.location,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status.value,
            'confidence_score': self.confidence_score,
            'analysis_results': self.analysis_results,
            'verification_votes': self.verification_votes,
            'rejection_votes': self.rejection_votes,
            'moderator_notes': self.moderator_notes
        }


class ScamReporter:
    """Handles user scam reporting and crowdsourced intelligence"""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".eagleeye" / "crowdsource.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.text_analyzer = TextAnalyzer()
        self.voice_analyzer = VoiceAnalyzer()
        
        self._init_database()
    
    def _init_database(self):
        """Initialize crowdsource database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_reports (
                    report_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source_info TEXT NOT NULL,
                    location TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    analysis_results TEXT NOT NULL,
                    verification_votes INTEGER DEFAULT 0,
                    rejection_votes INTEGER DEFAULT 0,
                    moderator_notes TEXT DEFAULT ''
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_votes (
                    vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    vote_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (report_id) REFERENCES user_reports (report_id),
                    UNIQUE(report_id, user_id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS regional_stats (
                    region TEXT PRIMARY KEY,
                    country TEXT,
                    total_reports INTEGER DEFAULT 0,
                    verified_reports INTEGER DEFAULT 0,
                    last_updated TEXT NOT NULL,
                    scam_types TEXT NOT NULL
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON user_reports(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_location ON user_reports(location)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON user_reports(status)")
    
    def _generate_report_id(self, content: str, user_id: str) -> str:
        """Generate unique report ID"""
        data = f"{content}{user_id}{datetime.now().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    async def submit_text_report(self, 
                                user_id: str,
                                content: str,
                                source_info: Dict[str, Any],
                                location: Optional[str] = None) -> UserReport:
        """Submit a text-based scam report"""
        
        # Analyze the content
        analysis_result = await self.text_analyzer.analyze_text(
            content, 
            source_type="user_report"
        )
        
        report_id = self._generate_report_id(content, user_id)
        
        report = UserReport(
            report_id=report_id,
            user_id=user_id,
            report_type=ReportType.TEXT,
            content=content,
            source_info=source_info,
            location=location,
            timestamp=datetime.now(),
            status=ReportStatus.PENDING,
            confidence_score=analysis_result.confidence,
            analysis_results=analysis_result.to_dict()
        )
        
        # Store in database
        self._store_report(report)
        
        # Update regional statistics
        if location:
            self._update_regional_stats(location, analysis_result.scam_type)
        
        return report
    
    async def submit_voice_report(self,
                                 user_id: str,
                                 audio_file_path: str,
                                 source_info: Dict[str, Any],
                                 location: Optional[str] = None) -> UserReport:
        """Submit a voice/audio scam report"""
        
        # Analyze the voice content
        voice_result = await self.voice_analyzer.analyze_audio_file(audio_file_path)
        
        content = voice_result.transcription or "Audio content (no transcription available)"
        report_id = self._generate_report_id(content, user_id)
        
        # Combine voice and text analysis
        analysis_results = voice_result.to_dict()
        if voice_result.text_analysis:
            analysis_results['text_confidence'] = voice_result.text_analysis.confidence
            scam_type = voice_result.text_analysis.scam_type
        else:
            scam_type = "unknown"
        
        report = UserReport(
            report_id=report_id,
            user_id=user_id,
            report_type=ReportType.VOICE,
            content=content,
            source_info={**source_info, 'audio_file': audio_file_path},
            location=location,
            timestamp=datetime.now(),
            status=ReportStatus.PENDING,
            confidence_score=voice_result.confidence,
            analysis_results=analysis_results
        )
        
        self._store_report(report)
        
        if location:
            self._update_regional_stats(location, scam_type)
        
        return report
    
    async def submit_website_report(self,
                                   user_id: str,
                                   url: str,
                                   description: str,
                                   location: Optional[str] = None) -> UserReport:
        """Submit a website scam report"""
        
        from ..analysis import ContentScraper
        scraper = ContentScraper()
        
        # Scrape website content
        scraped_content = await scraper.scrape_url(url)
        
        # Analyze scraped content
        content_text = scraped_content.get('content', description)
        analysis_result = await self.text_analyzer.analyze_text(
            content_text,
            source_url=url,
            source_type="reported_website"
        )
        
        report_id = self._generate_report_id(f"{url}{description}", user_id)
        
        report = UserReport(
            report_id=report_id,
            user_id=user_id,
            report_type=ReportType.WEBSITE,
            content=description,
            source_info={'url': url, 'scraped_data': scraped_content},
            location=location,
            timestamp=datetime.now(),
            status=ReportStatus.PENDING,
            confidence_score=analysis_result.confidence,
            analysis_results=analysis_result.to_dict()
        )
        
        self._store_report(report)
        
        if location:
            self._update_regional_stats(location, analysis_result.scam_type)
        
        return report
    
    def _store_report(self, report: UserReport):
        """Store report in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO user_reports 
                (report_id, user_id, report_type, content, source_info, location, 
                 timestamp, status, confidence_score, analysis_results, 
                 verification_votes, rejection_votes, moderator_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.report_id,
                report.user_id,
                report.report_type.value,
                report.content,
                json.dumps(report.source_info),
                report.location,
                report.timestamp.isoformat(),
                report.status.value,
                report.confidence_score,
                json.dumps(report.analysis_results),
                report.verification_votes,
                report.rejection_votes,
                report.moderator_notes
            ))
    
    def _update_regional_stats(self, location: str, scam_type: str):
        """Update regional statistics"""
        with sqlite3.connect(self.db_path) as conn:
            # Get existing stats
            cursor = conn.execute(
                "SELECT total_reports, scam_types FROM regional_stats WHERE region = ?",
                (location,)
            )
            result = cursor.fetchone()
            
            if result:
                total_reports, scam_types_json = result
                scam_types = json.loads(scam_types_json)
                total_reports += 1
                scam_types[scam_type] = scam_types.get(scam_type, 0) + 1
            else:
                total_reports = 1
                scam_types = {scam_type: 1}
            
            # Update stats
            conn.execute("""
                INSERT OR REPLACE INTO regional_stats 
                (region, total_reports, last_updated, scam_types)
                VALUES (?, ?, ?, ?)
            """, (
                location,
                total_reports,
                datetime.now().isoformat(),
                json.dumps(scam_types)
            ))
    
    def vote_on_report(self, report_id: str, user_id: str, vote_type: str) -> bool:
        """Vote on a report (verify or reject)"""
        if vote_type not in ['verify', 'reject']:
            return False
        
        with sqlite3.connect(self.db_path) as conn:
            try:
                # Record the vote
                conn.execute("""
                    INSERT INTO user_votes (report_id, user_id, vote_type, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (report_id, user_id, vote_type, datetime.now().isoformat()))
                
                # Update vote counts
                if vote_type == 'verify':
                    conn.execute("""
                        UPDATE user_reports 
                        SET verification_votes = verification_votes + 1
                        WHERE report_id = ?
                    """, (report_id,))
                else:
                    conn.execute("""
                        UPDATE user_reports 
                        SET rejection_votes = rejection_votes + 1
                        WHERE report_id = ?
                    """, (report_id,))
                
                # Check if report should be auto-verified/rejected
                cursor = conn.execute("""
                    SELECT verification_votes, rejection_votes 
                    FROM user_reports WHERE report_id = ?
                """, (report_id,))
                
                result = cursor.fetchone()
                if result:
                    verify_votes, reject_votes = result
                    
                    # Auto-verify with 5+ verification votes
                    if verify_votes >= 5 and verify_votes > reject_votes * 2:
                        conn.execute("""
                            UPDATE user_reports 
                            SET status = 'verified'
                            WHERE report_id = ?
                        """, (report_id,))
                    
                    # Auto-reject with 5+ rejection votes
                    elif reject_votes >= 5 and reject_votes > verify_votes * 2:
                        conn.execute("""
                            UPDATE user_reports 
                            SET status = 'rejected'
                            WHERE report_id = ?
                        """, (report_id,))
                
                return True
                
            except sqlite3.IntegrityError:
                # User already voted on this report
                return False
    
    def get_pending_reports(self, limit: int = 50) -> List[UserReport]:
        """Get pending reports for community validation"""
        reports = []
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM user_reports 
                WHERE status = 'pending'
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            for row in cursor.fetchall():
                report = UserReport(
                    report_id=row['report_id'],
                    user_id=row['user_id'],
                    report_type=ReportType(row['report_type']),
                    content=row['content'],
                    source_info=json.loads(row['source_info']),
                    location=row['location'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    status=ReportStatus(row['status']),
                    confidence_score=row['confidence_score'],
                    analysis_results=json.loads(row['analysis_results']),
                    verification_votes=row['verification_votes'],
                    rejection_votes=row['rejection_votes'],
                    moderator_notes=row['moderator_notes']
                )
                reports.append(report)
        
        return reports
    
    def get_verified_reports(self, days: int = 30, limit: int = 100) -> List[UserReport]:
        """Get verified reports for model training"""
        reports = []
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM user_reports 
                WHERE status = 'verified' AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (cutoff_date.isoformat(), limit))
            
            for row in cursor.fetchall():
                report = UserReport(
                    report_id=row['report_id'],
                    user_id=row['user_id'],
                    report_type=ReportType(row['report_type']),
                    content=row['content'],
                    source_info=json.loads(row['source_info']),
                    location=row['location'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    status=ReportStatus(row['status']),
                    confidence_score=row['confidence_score'],
                    analysis_results=json.loads(row['analysis_results']),
                    verification_votes=row['verification_votes'],
                    rejection_votes=row['rejection_votes'],
                    moderator_notes=row['moderator_notes']
                )
                reports.append(report)
        
        return reports
    
    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Get statistics for a specific user"""
        with sqlite3.connect(self.db_path) as conn:
            # User's reports
            cursor = conn.execute("""
                SELECT COUNT(*) as total_reports,
                       SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified_reports,
                       SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_reports
                FROM user_reports WHERE user_id = ?
            """, (user_id,))
            
            report_stats = cursor.fetchone()
            
            # User's votes
            cursor = conn.execute("""
                SELECT COUNT(*) as total_votes,
                       SUM(CASE WHEN vote_type = 'verify' THEN 1 ELSE 0 END) as verify_votes,
                       SUM(CASE WHEN vote_type = 'reject' THEN 1 ELSE 0 END) as reject_votes
                FROM user_votes WHERE user_id = ?
            """, (user_id,))
            
            vote_stats = cursor.fetchone()
            
            return {
                'total_reports': report_stats[0] if report_stats else 0,
                'verified_reports': report_stats[1] if report_stats else 0,
                'rejected_reports': report_stats[2] if report_stats else 0,
                'total_votes': vote_stats[0] if vote_stats else 0,
                'verify_votes': vote_stats[1] if vote_stats else 0,
                'reject_votes': vote_stats[2] if vote_stats else 0
            }
    
    async def retrain_models_with_reports(self) -> bool:
        """Retrain ML models using verified user reports"""
        verified_reports = self.get_verified_reports(days=90)
        
        if len(verified_reports) < 10:
            return False  # Need at least 10 verified reports
        
        # Prepare training data
        training_data = []
        for report in verified_reports:
            analysis = report.analysis_results
            scam_type = analysis.get('scam_type', 'unknown')
            
            if scam_type != 'unknown' and report.content:
                training_data.append((report.content, scam_type))
        
        if len(training_data) < 5:
            return False
        
        # Retrain NLP pipeline
        from ..analysis import NLPPipeline
        nlp = NLPPipeline()
        success = nlp.retrain_model(training_data)
        
        return success
