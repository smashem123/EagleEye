"""
Community validation and moderation system
Manages user reputation and report validation
"""
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import json

from .reporter import UserReport, ReportStatus


@dataclass
class UserReputation:
    """User reputation and trust score"""
    user_id: str
    trust_score: float
    reports_submitted: int
    reports_verified: int
    reports_rejected: int
    votes_cast: int
    accurate_votes: int
    moderator_level: int
    last_activity: datetime
    
    def calculate_accuracy_rate(self) -> float:
        """Calculate user's voting accuracy rate"""
        if self.votes_cast == 0:
            return 0.0
        return self.accurate_votes / self.votes_cast


class CommunityValidator:
    """Manages community validation and moderation"""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".eagleeye" / "crowdsource.db"
        self._init_community_tables()
    
    def _init_community_tables(self):
        """Initialize community validation tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_reputation (
                    user_id TEXT PRIMARY KEY,
                    trust_score REAL DEFAULT 1.0,
                    reports_submitted INTEGER DEFAULT 0,
                    reports_verified INTEGER DEFAULT 0,
                    reports_rejected INTEGER DEFAULT 0,
                    votes_cast INTEGER DEFAULT 0,
                    accurate_votes INTEGER DEFAULT 0,
                    moderator_level INTEGER DEFAULT 0,
                    last_activity TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS validation_queue (
                    queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT NOT NULL,
                    priority_score REAL DEFAULT 1.0,
                    assigned_validators TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (report_id) REFERENCES user_reports (report_id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS moderation_actions (
                    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    moderator_id TEXT NOT NULL,
                    report_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    reason TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (report_id) REFERENCES user_reports (report_id)
                )
            """)
    
    def update_user_reputation(self, user_id: str, action: str, **kwargs):
        """Update user reputation based on actions"""
        with sqlite3.connect(self.db_path) as conn:
            # Get current reputation
            cursor = conn.execute(
                "SELECT * FROM user_reputation WHERE user_id = ?", 
                (user_id,)
            )
            result = cursor.fetchone()
            
            if result:
                trust_score, reports_submitted, reports_verified, reports_rejected, \
                votes_cast, accurate_votes, moderator_level = result[1:8]
            else:
                trust_score = 1.0
                reports_submitted = reports_verified = reports_rejected = 0
                votes_cast = accurate_votes = moderator_level = 0
            
            # Update based on action
            if action == 'report_submitted':
                reports_submitted += 1
                trust_score += 0.1  # Small boost for participation
            
            elif action == 'report_verified':
                reports_verified += 1
                trust_score += 0.5  # Good boost for verified reports
            
            elif action == 'report_rejected':
                reports_rejected += 1
                trust_score -= 0.3  # Penalty for false reports
            
            elif action == 'vote_cast':
                votes_cast += 1
                trust_score += 0.05  # Small boost for voting
            
            elif action == 'accurate_vote':
                accurate_votes += 1
                trust_score += 0.2  # Boost for accurate voting
            
            elif action == 'inaccurate_vote':
                trust_score -= 0.1  # Penalty for inaccurate voting
            
            # Calculate new moderator level
            accuracy_rate = accurate_votes / max(votes_cast, 1)
            verification_rate = reports_verified / max(reports_submitted, 1)
            
            if trust_score >= 10.0 and accuracy_rate >= 0.8 and verification_rate >= 0.7:
                moderator_level = 3  # Senior moderator
            elif trust_score >= 5.0 and accuracy_rate >= 0.7 and verification_rate >= 0.6:
                moderator_level = 2  # Moderator
            elif trust_score >= 2.0 and accuracy_rate >= 0.6:
                moderator_level = 1  # Junior moderator
            else:
                moderator_level = 0  # Regular user
            
            # Ensure trust score bounds
            trust_score = max(0.0, min(trust_score, 20.0))
            
            # Update database
            conn.execute("""
                INSERT OR REPLACE INTO user_reputation 
                (user_id, trust_score, reports_submitted, reports_verified, 
                 reports_rejected, votes_cast, accurate_votes, moderator_level, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, trust_score, reports_submitted, reports_verified,
                reports_rejected, votes_cast, accurate_votes, moderator_level,
                datetime.now().isoformat()
            ))
    
    def get_user_reputation(self, user_id: str) -> Optional[UserReputation]:
        """Get user reputation data"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM user_reputation WHERE user_id = ?",
                (user_id,)
            )
            result = cursor.fetchone()
            
            if result:
                return UserReputation(
                    user_id=result['user_id'],
                    trust_score=result['trust_score'],
                    reports_submitted=result['reports_submitted'],
                    reports_verified=result['reports_verified'],
                    reports_rejected=result['reports_rejected'],
                    votes_cast=result['votes_cast'],
                    accurate_votes=result['accurate_votes'],
                    moderator_level=result['moderator_level'],
                    last_activity=datetime.fromisoformat(result['last_activity'])
                )
            return None
    
    def assign_validators(self, report_id: str, num_validators: int = 3) -> List[str]:
        """Assign trusted validators to a report"""
        with sqlite3.connect(self.db_path) as conn:
            # Get available validators (users with good reputation)
            cursor = conn.execute("""
                SELECT user_id, trust_score, moderator_level 
                FROM user_reputation 
                WHERE trust_score >= 2.0 
                ORDER BY trust_score DESC, moderator_level DESC
                LIMIT ?
            """, (num_validators * 2,))  # Get more than needed for selection
            
            available_validators = cursor.fetchall()
            
            # Select validators (prioritize moderators and high trust scores)
            selected_validators = []
            
            # First, select moderators
            for validator in available_validators:
                if validator[2] > 0 and len(selected_validators) < num_validators:
                    selected_validators.append(validator[0])
            
            # Then, select high-trust users
            for validator in available_validators:
                if validator[0] not in selected_validators and len(selected_validators) < num_validators:
                    selected_validators.append(validator[0])
            
            # Add to validation queue
            if selected_validators:
                conn.execute("""
                    INSERT INTO validation_queue 
                    (report_id, assigned_validators, created_at)
                    VALUES (?, ?, ?)
                """, (
                    report_id,
                    json.dumps(selected_validators),
                    datetime.now().isoformat()
                ))
            
            return selected_validators
    
    def get_validation_queue(self, user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get reports assigned to user for validation"""
        queue_items = []
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get reports assigned to this user
            cursor = conn.execute("""
                SELECT vq.*, ur.content, ur.report_type, ur.confidence_score, ur.timestamp
                FROM validation_queue vq
                JOIN user_reports ur ON vq.report_id = ur.report_id
                WHERE ur.status = 'pending'
                ORDER BY vq.priority_score DESC, vq.created_at ASC
                LIMIT ?
            """, (limit * 3,))  # Get more to filter
            
            for row in cursor.fetchall():
                assigned_validators = json.loads(row['assigned_validators'])
                
                if user_id in assigned_validators:
                    # Check if user already voted
                    vote_cursor = conn.execute("""
                        SELECT COUNT(*) FROM user_votes 
                        WHERE report_id = ? AND user_id = ?
                    """, (row['report_id'], user_id))
                    
                    if vote_cursor.fetchone()[0] == 0:  # User hasn't voted yet
                        queue_items.append({
                            'report_id': row['report_id'],
                            'content': row['content'][:200] + "..." if len(row['content']) > 200 else row['content'],
                            'report_type': row['report_type'],
                            'confidence_score': row['confidence_score'],
                            'timestamp': row['timestamp'],
                            'priority_score': row['priority_score']
                        })
                        
                        if len(queue_items) >= limit:
                            break
        
        return queue_items
    
    def moderate_report(self, moderator_id: str, report_id: str, action: str, reason: str = "") -> bool:
        """Moderator action on a report"""
        # Check if user is a moderator
        reputation = self.get_user_reputation(moderator_id)
        if not reputation or reputation.moderator_level == 0:
            return False
        
        with sqlite3.connect(self.db_path) as conn:
            # Record moderation action
            conn.execute("""
                INSERT INTO moderation_actions 
                (moderator_id, report_id, action_type, reason, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                moderator_id, report_id, action, reason,
                datetime.now().isoformat()
            ))
            
            # Apply action
            if action == 'approve':
                conn.execute("""
                    UPDATE user_reports 
                    SET status = 'verified', moderator_notes = ?
                    WHERE report_id = ?
                """, (f"Approved by moderator: {reason}", report_id))
            
            elif action == 'reject':
                conn.execute("""
                    UPDATE user_reports 
                    SET status = 'rejected', moderator_notes = ?
                    WHERE report_id = ?
                """, (f"Rejected by moderator: {reason}", report_id))
            
            elif action == 'investigate':
                conn.execute("""
                    UPDATE user_reports 
                    SET status = 'investigating', moderator_notes = ?
                    WHERE report_id = ?
                """, (f"Under investigation: {reason}", report_id))
            
            return True
    
    def get_community_stats(self) -> Dict[str, Any]:
        """Get community validation statistics"""
        with sqlite3.connect(self.db_path) as conn:
            # Total users
            cursor = conn.execute("SELECT COUNT(*) FROM user_reputation")
            total_users = cursor.fetchone()[0]
            
            # Active users (last 30 days)
            cutoff_date = datetime.now() - timedelta(days=30)
            cursor = conn.execute("""
                SELECT COUNT(*) FROM user_reputation 
                WHERE last_activity >= ?
            """, (cutoff_date.isoformat(),))
            active_users = cursor.fetchone()[0]
            
            # Moderators by level
            cursor = conn.execute("""
                SELECT moderator_level, COUNT(*) 
                FROM user_reputation 
                WHERE moderator_level > 0
                GROUP BY moderator_level
            """)
            moderator_counts = dict(cursor.fetchall())
            
            # Validation queue size
            cursor = conn.execute("""
                SELECT COUNT(*) FROM validation_queue vq
                JOIN user_reports ur ON vq.report_id = ur.report_id
                WHERE ur.status = 'pending'
            """)
            queue_size = cursor.fetchone()[0]
            
            # Average trust score
            cursor = conn.execute("SELECT AVG(trust_score) FROM user_reputation")
            avg_trust_score = cursor.fetchone()[0] or 0.0
            
            # Top contributors
            cursor = conn.execute("""
                SELECT user_id, trust_score, reports_verified, accurate_votes
                FROM user_reputation 
                ORDER BY trust_score DESC 
                LIMIT 5
            """)
            top_contributors = [
                {
                    'user_id': row[0][:8] + "...",  # Anonymize
                    'trust_score': row[1],
                    'reports_verified': row[2],
                    'accurate_votes': row[3]
                }
                for row in cursor.fetchall()
            ]
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'moderators': {
                    'junior': moderator_counts.get(1, 0),
                    'regular': moderator_counts.get(2, 0),
                    'senior': moderator_counts.get(3, 0)
                },
                'validation_queue_size': queue_size,
                'average_trust_score': round(avg_trust_score, 2),
                'top_contributors': top_contributors
            }
    
    def cleanup_old_queue_items(self, days: int = 7):
        """Clean up old validation queue items"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                DELETE FROM validation_queue 
                WHERE created_at < ?
            """, (cutoff_date.isoformat(),))
    
    def get_user_validation_tasks(self, user_id: str) -> List[Dict[str, Any]]:
        """Get validation tasks for a specific user"""
        return self.get_validation_queue(user_id, limit=20)
