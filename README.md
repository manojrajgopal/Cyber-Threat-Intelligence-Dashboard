# Cyber Threat Intelligence Dashboard

A comprehensive, production-ready Cyber Threat Intelligence (CTI) platform built with FastAPI (Python) backend and React frontend. This dashboard ingests threat data from OSINT sources, normalizes and enriches indicators of compromise (IOCs), correlates threats, scores risk, and provides real-time alerting and visualization.

## Features

### Backend Features
- **Threat Ingestion**: Automated fetching from OSINT feeds (AlienVault OTX, AbuseIPDB)
- **Data Normalization**: Standardized IOC schema (IP, Domain, URL, Hash)
- **IOC Enrichment**: WHOIS, GeoIP, ASN, reputation scoring via VirusTotal
- **Correlation & Risk Scoring**: Automated threat correlation and risk assessment
- **Real-time Alerting**: Severity-based alerts with acknowledgment workflow
- **User Management**: JWT-based authentication with RBAC
- **Audit Logging**: Comprehensive security audit trails
- **Reporting**: Exportable threat reports (JSON/CSV)

### Frontend Features
- **Interactive Dashboard**: Real-time KPIs and metrics
- **IOC Management**: List, search, and detailed IOC views
- **Alert Management**: Alert table with acknowledgment controls
- **Reports**: Export functionality for IOCs, alerts, and audit logs
- **Geolocation Map**: Threat visualization (placeholder for mapping integration)
- **Responsive Design**: Professional UI with Tailwind CSS

## Architecture

### Backend (FastAPI + MySQL)
```
backend/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Environment configuration
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Business logic (ingestion, enrichment, correlation)
│   ├── security/            # Authentication & authorization
│   ├── api/
│   │   ├── routes/          # API endpoints
│   │   └── api.py           # Route aggregation
│   └── db/                  # Database configuration
```

### Frontend (React)
```
frontend/
├── src/
│   ├── components/          # React components
│   │   ├── common/          # Shared components (Header, Sidebar, Footer)
│   │   ├── auth/            # Authentication components
│   │   ├── dashboard/       # Dashboard components
│   │   ├── iocs/            # IOC management
│   │   ├── alerts/          # Alert management
│   │   ├── reports/         # Report components
│   │   └── maps/            # Geolocation components
│   ├── services/            # API client
│   ├── App.js               # Main application
│   └── .env                 # Environment variables
```

## Prerequisites

- Python 3.8+
- Node.js 14+
- MySQL 8.0+
- pip and npm

## Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd cyber-threat-intelligence-dashboard
```

### 2. Backend Setup

#### Install Python Dependencies
```bash
cd backend
pip install fastapi uvicorn sqlalchemy pymysql python-jose[cryptography] passlib[bcrypt] python-multipart requests
```

#### MySQL Database Setup
```bash
# Create database
mysql -u root -p
CREATE DATABASE cti_dashboard;
CREATE USER 'cti_user'@'localhost' IDENTIFIED BY 'cti_password';
GRANT ALL PRIVILEGES ON cti_dashboard.* TO 'cti_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

#### Run Database Migrations
```bash
# The application will create tables automatically on startup
# Or manually run the schema:
mysql -u cti_user -p cti_dashboard < app/db/schema.sql
```

#### Configure Environment Variables
Create `.env` file in backend directory:
```bash
BACKEND_ENV=development
API_BASE_PATH=/api
SECRET_KEY=your_secret_key_here
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=cti_user
MYSQL_PASSWORD=cti_password
MYSQL_DATABASE=cti_dashboard
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_alienvault_otx_key
```

#### Start Backend Server
```bash
python run.py
```
Server will start on http://localhost:8000

### 3. Frontend Setup

#### Install Dependencies
```bash
cd frontend
npm install
```

#### Configure Environment
The `.env` file is already configured:
```
REACT_APP_BACKEND_URL=http://localhost:8000
```

#### Start Frontend Development Server
```bash
npm start
```
Frontend will be available on http://localhost:3000

## Usage

### First Time Setup
1. Start the backend server
2. Start the frontend server
3. Navigate to http://localhost:3000
4. Register a new account or use default credentials
5. The system will automatically create default roles and permissions

### API Endpoints

#### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration

#### IOCs
- `GET /api/iocs` - List IOCs
- `POST /api/iocs` - Create IOC
- `GET /api/iocs/{id}` - Get IOC details
- `POST /api/iocs/{id}/enrich` - Enrich IOC

#### Alerts
- `GET /api/alerts` - List alerts
- `PUT /api/alerts/{id}/acknowledge` - Acknowledge alert

#### Dashboard
- `GET /api/dashboard/metrics` - Get dashboard metrics

#### Reports
- `POST /api/reports/export` - Export reports

## Security Features

- **JWT Authentication**: Secure token-based authentication
- **Role-Based Access Control**: Granular permissions system
- **Password Hashing**: Bcrypt password encryption
- **Audit Logging**: Comprehensive security event logging
- **Input Validation**: Pydantic schema validation
- **CORS Protection**: Configured CORS policies

## Development

### Running Tests
```bash
# Backend tests
cd backend
python -m pytest

# Frontend tests
cd frontend
npm test
```

### Code Quality
- Black for Python code formatting
- ESLint for JavaScript/React code quality
- Pre-commit hooks recommended

## Production Deployment

### Backend
```bash
# Using Gunicorn
pip install gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Frontend
```bash
npm run build
# Serve build directory with nginx/apache
```

### Docker (Optional)
```dockerfile
# Add Docker support for containerized deployment
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the API documentation at `/api/docs`

## Future Enhancements

- ML-based anomaly detection
- SOAR integration
- STIX/TAXII compatibility
- Multi-tenant architecture
- Advanced correlation rules
- Real-time threat feeds
- SIEM integration