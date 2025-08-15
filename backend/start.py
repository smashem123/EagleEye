"""
Startup script for ScamSwatter backend
"""
import uvicorn
from app.core.config import settings
from app.core.init_db import init_db

def start_server():
    """Initialize database and start the server"""
    print("Initializing database...")
    init_db()
    
    print(f"Starting {settings.PROJECT_NAME} server...")
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )

if __name__ == "__main__":
    start_server()
