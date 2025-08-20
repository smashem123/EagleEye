"""
Database management for EagleEye CLI
"""
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager

from .config import get_config_dir
from .logging_config import get_logger, LoggerMixin
from .exceptions import DatabaseError, ValidationError, handle_exception


@dataclass
class ScamRecord:
    """Data class for scam records"""
    id: Optional[int] = None
    title: str = ""
    description: str = ""
    scam_type: str = ""
    source: str = ""
    source_id: str = ""
    url: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    location: Optional[str] = None
    severity: float = 0.0
    confidence: float = 0.0
    first_seen: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    is_verified: bool = False
    tags: List[str] = None
    raw_data: Dict[str, Any] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.raw_data is None:
            self.raw_data = {}
        if self.first_seen is None:
            self.first_seen = datetime.utcnow()
        if self.last_updated is None:
            self.last_updated = datetime.utcnow()


class ScamDatabase(LoggerMixin):
    """SQLite database manager for scam records"""
    
    def __init__(self, db_path: Optional[Path] = None):
        try:
            self.db_path = get_config_dir() / "eagleeye.db" if db_path is None else db_path
            self.logger.info(f"Initializing database at {self.db_path}")
            self.init_database()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            handle_exception("database_init", e, self.logger)
    
    def init_database(self) -> None:
        """Initialize the database with required tables"""
        try:
            # Ensure directory exists
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            with self.get_connection() as conn:
            # Create scam_records table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scam_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    scam_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    url TEXT,
                    phone TEXT,
                    email TEXT,
                    location TEXT,
                    severity REAL DEFAULT 0.0,
                    confidence REAL DEFAULT 0.0,
                    first_seen TIMESTAMP NOT NULL,
                    last_updated TIMESTAMP NOT NULL,
                    is_verified BOOLEAN DEFAULT FALSE,
                    tags TEXT,  -- JSON array
                    raw_data TEXT,  -- JSON object
                    UNIQUE(source, source_id)
                )
            """)
            
            # Create indexes for better query performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scam_type ON scam_records(scam_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON scam_records(source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_first_seen ON scam_records(first_seen)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_location ON scam_records(location)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON scam_records(severity)")
            
            # Create cache metadata table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            
            # Create source sync tracking table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS source_sync (
                    source TEXT PRIMARY KEY,
                    last_sync TIMESTAMP,
                    last_successful_sync TIMESTAMP,
                    error_count INTEGER DEFAULT 0,
                    last_error TEXT
                )
            """)
            
        except Exception as e:
            raise DatabaseError(f"Failed to initialize database: {e}", operation="init_database", cause=e)
    
    @contextmanager
    def get_connection(self):
        """Get a database connection with proper cleanup"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Database operation failed: {e}", cause=e)
        except Exception as e:
            if conn:
                conn.rollback()
            handle_exception("database_connection", e, self.logger)
        finally:
            if conn:
                conn.close()
    
    def insert_scam(self, scam: ScamRecord) -> int:
        """Insert a new scam record, return the ID"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO scam_records (
                    title, description, scam_type, source, source_id,
                    url, phone, email, location, severity, confidence,
                    first_seen, last_updated, is_verified, tags, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scam.title, scam.description, scam.scam_type, scam.source, scam.source_id,
                scam.url, scam.phone, scam.email, scam.location, scam.severity, scam.confidence,
                scam.first_seen, scam.last_updated, scam.is_verified,
                json.dumps(scam.tags), json.dumps(scam.raw_data)
            ))
            return cursor.lastrowid
    
    def get_scam_by_id(self, scam_id: int) -> Optional[ScamRecord]:
        """Get a scam record by ID"""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM scam_records WHERE id = ?", (scam_id,)).fetchone()
            if row:
                return self._row_to_scam(row)
        return None
    
    def get_scam_by_source(self, source: str, source_id: str) -> Optional[ScamRecord]:
        """Get a scam record by source and source ID"""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scam_records WHERE source = ? AND source_id = ?",
                (source, source_id)
            ).fetchone()
            if row:
                return self._row_to_scam(row)
        return None
    
    def search_scams(
        self,
        query: Optional[str] = None,
        scam_type: Optional[str] = None,
        source: Optional[str] = None,
        location: Optional[str] = None,
        min_severity: Optional[float] = None,
        hours_back: Optional[int] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[ScamRecord]:
        """Search scam records with various filters"""
        
        sql = "SELECT * FROM scam_records WHERE 1=1"
        params = []
        
        # Text search in title and description
        if query:
            sql += " AND (title LIKE ? OR description LIKE ?)"
            search_term = f"%{query}%"
            params.extend([search_term, search_term])
        
        # Filter by scam type
        if scam_type:
            sql += " AND scam_type = ?"
            params.append(scam_type)
        
        # Filter by source
        if source:
            sql += " AND source = ?"
            params.append(source)
        
        # Filter by location
        if location:
            sql += " AND location LIKE ?"
            params.append(f"%{location}%")
        
        # Filter by minimum severity
        if min_severity is not None:
            sql += " AND severity >= ?"
            params.append(min_severity)
        
        # Filter by time range
        if hours_back:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
            sql += " AND first_seen >= ?"
            params.append(cutoff_time)
        
        # Order by most recent first
        sql += " ORDER BY first_seen DESC"
        
        # Add pagination
        sql += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self.get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_scam(row) for row in rows]
    
    def get_recent_scams(self, hours: int = 24, limit: int = 50) -> List[ScamRecord]:
        """Get recent scam records"""
        return self.search_scams(hours_back=hours, limit=limit)
    
    def get_scam_types(self) -> List[Tuple[str, int]]:
        """Get all scam types with counts"""
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT scam_type, COUNT(*) as count 
                FROM scam_records 
                GROUP BY scam_type 
                ORDER BY count DESC
            """).fetchall()
            return [(row['scam_type'], row['count']) for row in rows]
    
    def get_sources(self) -> List[Tuple[str, int]]:
        """Get all sources with counts"""
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT source, COUNT(*) as count 
                FROM scam_records 
                GROUP BY source 
                ORDER BY count DESC
            """).fetchall()
            return [(row['source'], row['count']) for row in rows]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.get_connection() as conn:
            # Total records
            total = conn.execute("SELECT COUNT(*) as count FROM scam_records").fetchone()['count']
            
            # Recent records (last 24 hours)
            cutoff = datetime.utcnow() - timedelta(hours=24)
            recent = conn.execute(
                "SELECT COUNT(*) as count FROM scam_records WHERE first_seen >= ?",
                (cutoff,)
            ).fetchone()['count']
            
            # Top scam types
            types = conn.execute("""
                SELECT scam_type, COUNT(*) as count 
                FROM scam_records 
                GROUP BY scam_type 
                ORDER BY count DESC 
                LIMIT 5
            """).fetchall()
            
            # Top sources
            sources = conn.execute("""
                SELECT source, COUNT(*) as count 
                FROM scam_records 
                GROUP BY source 
                ORDER BY count DESC 
                LIMIT 5
            """).fetchall()
            
            return {
                'total_records': total,
                'recent_records_24h': recent,
                'top_scam_types': [(row['scam_type'], row['count']) for row in types],
                'top_sources': [(row['source'], row['count']) for row in sources]
            }
    
    def cleanup_old_records(self, days: int = 30) -> int:
        """Remove old records beyond the specified days"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        with self.get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM scam_records WHERE first_seen < ?",
                (cutoff,)
            )
            return cursor.rowcount
    
    def update_source_sync(self, source: str, success: bool, error: Optional[str] = None) -> None:
        """Update source sync tracking"""
        now = datetime.utcnow()
        
        with self.get_connection() as conn:
            if success:
                conn.execute("""
                    INSERT OR REPLACE INTO source_sync 
                    (source, last_sync, last_successful_sync, error_count, last_error)
                    VALUES (?, ?, ?, 0, NULL)
                """, (source, now, now))
            else:
                # Get current error count
                row = conn.execute(
                    "SELECT error_count FROM source_sync WHERE source = ?",
                    (source,)
                ).fetchone()
                error_count = (row['error_count'] if row else 0) + 1
                
                conn.execute("""
                    INSERT OR REPLACE INTO source_sync 
                    (source, last_sync, last_successful_sync, error_count, last_error)
                    VALUES (?, ?, 
                        COALESCE((SELECT last_successful_sync FROM source_sync WHERE source = ?), ?),
                        ?, ?)
                """, (source, now, source, now, error_count, error))
    
    def get_source_sync_status(self, source: str) -> Optional[Dict[str, Any]]:
        """Get sync status for a source"""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM source_sync WHERE source = ?",
                (source,)
            ).fetchone()
            if row:
                return dict(row)
        return None
    
    def _row_to_scam(self, row: sqlite3.Row) -> ScamRecord:
        """Convert database row to ScamRecord"""
        return ScamRecord(
            id=row['id'],
            title=row['title'],
            description=row['description'],
            scam_type=row['scam_type'],
            source=row['source'],
            source_id=row['source_id'],
            url=row['url'],
            phone=row['phone'],
            email=row['email'],
            location=row['location'],
            severity=row['severity'],
            confidence=row['confidence'],
            first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
            last_updated=datetime.fromisoformat(row['last_updated']) if row['last_updated'] else None,
            is_verified=bool(row['is_verified']),
            tags=json.loads(row['tags']) if row['tags'] else [],
            raw_data=json.loads(row['raw_data']) if row['raw_data'] else {}
        )


# Global database instance
_db: Optional[ScamDatabase] = None


def get_database() -> ScamDatabase:
    """Get the global database instance"""
    global _db
    if _db is None:
        _db = ScamDatabase()
    return _db
