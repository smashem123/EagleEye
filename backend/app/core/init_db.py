"""
Database initialization script for ScamSwatter
"""
from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine
from app.models.scam import Base, DataSource, ScamCategory
from app.core.config import settings


def init_db() -> None:
    """Initialize database with tables and seed data"""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create initial data sources
    db = SessionLocal()
    try:
        # Check if data sources already exist
        existing_sources = db.query(DataSource).count()
        if existing_sources == 0:
            # Create initial data sources
            sources = [
                DataSource(
                    name="PhishTank",
                    description="Community-driven anti-phishing database",
                    api_endpoint="https://checkurl.phishtank.com/checkurl/",
                    api_key_required=True,
                    rate_limit_per_hour=1000,
                    sync_frequency_minutes=30,
                    is_active=True
                ),
                DataSource(
                    name="URLVoid",
                    description="Website reputation and safety checker",
                    api_endpoint="https://api.urlvoid.com/v1/",
                    api_key_required=True,
                    rate_limit_per_hour=500,
                    sync_frequency_minutes=60,
                    is_active=True
                ),
                DataSource(
                    name="FTC Consumer Sentinel",
                    description="Federal Trade Commission fraud reports",
                    api_endpoint="https://api.consumersentinel.gov/",
                    api_key_required=False,
                    rate_limit_per_hour=100,
                    sync_frequency_minutes=120,
                    is_active=True
                ),
                DataSource(
                    name="Scammer.info",
                    description="Community scam database",
                    api_endpoint="https://scammer.info/api/",
                    api_key_required=False,
                    rate_limit_per_hour=200,
                    sync_frequency_minutes=60,
                    is_active=True
                )
            ]
            
            for source in sources:
                db.add(source)
            
            # Create initial scam categories
            categories = [
                ScamCategory(
                    name="phishing",
                    description="Fraudulent emails and websites designed to steal credentials",
                    color_hex="#FF6B6B",
                    icon_name="mail"
                ),
                ScamCategory(
                    name="robocall",
                    description="Automated phone calls with fraudulent intent",
                    color_hex="#4ECDC4",
                    icon_name="phone"
                ),
                ScamCategory(
                    name="fake_website",
                    description="Fraudulent websites impersonating legitimate services",
                    color_hex="#45B7D1",
                    icon_name="globe"
                ),
                ScamCategory(
                    name="investment_fraud",
                    description="Fraudulent investment opportunities and schemes",
                    color_hex="#F7DC6F",
                    icon_name="trending-up"
                ),
                ScamCategory(
                    name="identity_theft",
                    description="Attempts to steal personal information",
                    color_hex="#BB8FCE",
                    icon_name="user-x"
                ),
                ScamCategory(
                    name="romance_scam",
                    description="Fraudulent romantic relationships for financial gain",
                    color_hex="#F1948A",
                    icon_name="heart"
                ),
                ScamCategory(
                    name="tech_support",
                    description="Fake technical support scams",
                    color_hex="#85C1E9",
                    icon_name="monitor"
                ),
                ScamCategory(
                    name="lottery_prize",
                    description="Fake lottery or prize notifications",
                    color_hex="#82E0AA",
                    icon_name="gift"
                )
            ]
            
            for category in categories:
                db.add(category)
            
            db.commit()
            print("Database initialized with seed data")
        else:
            print("Database already initialized")
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
