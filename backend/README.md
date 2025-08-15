# ScamSwatter Backend API

FastAPI-based backend service for the ScamSwatter real-time scam intelligence platform.

## Features

- **RESTful API** for scam intelligence data
- **Real-time scam feed** with advanced filtering
- **Location-aware alerts** with geographic filtering
- **Community reporting** system for user-submitted scams
- **Database integration** with PostgreSQL and Redis caching
- **Modular architecture** for easy API source integration

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (recommended)

### Using Docker (Recommended)

1. **Clone and navigate to the project:**
   ```bash
   cd EagleEye
   ```

2. **Start all services:**
   ```bash
   docker-compose up -d
   ```

3. **Access the API:**
   - API Documentation: http://localhost:8000/docs
   - API Base URL: http://localhost:8000/api/v1

### Manual Setup

1. **Install dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Set up environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials
   ```

3. **Initialize database:**
   ```bash
   python -m app.core.init_db
   ```

4. **Start the server:**
   ```bash
   python start.py
   ```

## API Endpoints

### Scam Intelligence

- `GET /api/v1/scams/feed` - Live scam feed with filtering
- `GET /api/v1/scams/{id}` - Get specific scam by ID
- `GET /api/v1/scams/type/{type}` - Get scams by type
- `POST /api/v1/scams/` - Create scam report (for data ingestion)

### Community Reports

- `POST /api/v1/scams/reports/` - Submit user scam report
- `GET /api/v1/scams/reports/pending` - Get pending reports
- `POST /api/v1/scams/reports/{id}/upvote` - Upvote report
- `POST /api/v1/scams/reports/{id}/downvote` - Downvote report

### System

- `GET /api/v1/health` - Health check endpoint
- `GET /` - API information

## Database Schema

### Core Tables

- **scam_reports** - Main scam intelligence data
- **locations** - Geographic location data
- **data_sources** - External API source configuration
- **scam_categories** - Scam type classifications
- **user_reports** - Community-submitted reports

## Configuration

Key environment variables in `.env`:

```bash
# Database
DATABASE_URL=postgresql://username:password@localhost:5432/scamswatter_db
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-super-secret-key-here

# External APIs
PHISHTANK_API_KEY=your_api_key
URLVOID_API_KEY=your_api_key
```

## Development

### Database Migrations

```bash
# Create migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head
```

### Testing

```bash
pytest
```

### Code Formatting

```bash
black app/
flake8 app/
```

## Architecture

```
app/
├── api/v1/          # API routes and endpoints
├── core/            # Core configuration and database
├── crud/            # Database operations
├── models/          # SQLAlchemy models
├── schemas/         # Pydantic schemas
└── main.py          # FastAPI application
```

## Next Steps

1. **Add API integrations** for external scam intelligence sources
2. **Implement data ingestion** services for real-time updates
3. **Add authentication** for protected endpoints
4. **Set up monitoring** and logging
5. **Deploy to production** with proper security measures
