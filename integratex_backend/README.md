# IntegrateX Backend

Fresh FastAPI backend foundation for IntegrateX. It is designed to run against PostgreSQL and includes:
- 35 cybersecurity connector catalogue entries (catalogue templates, not falsely marked as live)
- Generic HTTP integration execution with bearer, API-key, basic and no-auth modes
- Configuration validation and configuration generation
- Real test-connection requests
- Incremental sync checkpoint storage (timestamp/cursor/manual; vendor support must be configured)
- Normalised event storage and deterministic evidence-based correlation
- Sarvam AI explanation endpoint (optional; API key remains server-side)
- JWT authentication primitives and password hashing
- SQLAlchemy models and Alembic migration setup

## Important truth about connectors
The catalogue includes all 35 requested products. A connector is not considered live merely because it appears in the catalogue. Real use requires vendor API documentation, endpoint details, credentials and permissions. Vendor-specific adapters may be required for unusual APIs. The generic engine deliberately reports actual HTTP outcomes.

## Requirements
- Python 3.12+ (use a current stable Python compatible with installed dependencies)
- PostgreSQL 18.x
- A database named `integratex_db`

## Windows setup (PowerShell)
From this folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set `DATABASE_URL` using your PostgreSQL password. Do not commit `.env`.

Create tables for local development:
```powershell
.\.venv\Scripts\python.exe -m app.db_init
```

Start API:
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## First-run database note
The database itself is created separately in pgAdmin. `db_init` creates the application tables inside `integratex_db`. For team/production workflows, use Alembic migrations (`alembic upgrade head`).

## Authentication
Register via `POST /api/auth/register`, then login via `POST /api/auth/login`. The login response contains a bearer token. Use `Authorization: Bearer <token>` for protected endpoints. `/api/health`, `/api/connectors` and docs are public for initial setup.

## Configuration shape
```json
{
  "name": "My security tool",
  "vendor": "Elastic",
  "base_url": "https://example.invalid",
  "auth": {"type": "bearer", "token": "REPLACE_ME"},
  "endpoints": [{
    "name": "alerts",
    "path": "/api/alerts",
    "method": "GET",
    "pagination": {"type": "none"}
  }],
  "schedule": {"type": "manual"},
  "mapping": {
    "id": "id",
    "timestamp": "created_at",
    "severity": "severity",
    "title": "title",
    "source": "source"
  },
  "incremental": {"enabled": false, "strategy": "timestamp", "field": "updated_at"}
}
```

Do not put real credentials in exported configuration files or screenshots. Prefer secret references in a production deployment; this starter keeps encrypted credentials in the database when saved through the API.

## API overview
- `GET /api/health`
- `GET /api/connectors`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/integrations`
- `POST /api/integrations`
- `POST /api/integrations/validate`
- `POST /api/integrations/generate-config`
- `POST /api/integrations/test-config`
- `POST /api/integrations/{id}/test`
- `POST /api/integrations/{id}/run`
- `GET /api/executions`
- `GET /api/records`
- `GET /api/incidents`
- `POST /api/ai/explain`

## Safety
This backend is a hackathon foundation, not a certified SIEM/SOAR product. Review vendor API scopes, network allowlists, retention, RBAC and secret-management before production. SSRF protections restrict localhost/private destinations by default; configure trusted vendor hosts explicitly if needed.
