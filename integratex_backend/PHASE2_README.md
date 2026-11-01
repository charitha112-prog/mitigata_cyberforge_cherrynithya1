# IntegrateX Phase 2 Backend

This package extends the supplied backend with a 35-entry connector catalogue, connector-template endpoint, a reusable HTTP engine, bounded pagination, event mapping/upsert-by-integration-and-external-id, optional checkpoint persistence, and a normalized Sarvam explanation response.

## Important connector status
All 35 catalogue entries are templates, not 35 live vendor integrations. Vendor API URLs, paths, request formats, authentication scopes, pagination conventions and event fields vary by product, edition and tenant. The package deliberately leaves endpoint paths and base URLs empty rather than inventing vendor endpoints. Configure them from the vendor's current official API documentation and test with an authorised account.

`Binary Search` is retained from the requested list, but its exact vendor/product identity is unverified; confirm the intended product before configuring it.

## Install/update on Windows
1. Keep your existing project folder and database as backup. Extract this ZIP to a NEW folder.
2. Copy your existing local `.env` into the new `integratex_backend` folder. Do not upload or share it. Rotate any keys/passwords that were exposed in shared archives/screenshots; generate a fresh credential encryption key only before storing new credentials (old encrypted credentials may become unreadable if you change the key).
3. Open the new `integratex_backend` folder in VS Code.
4. Create a Python 3.12 virtual environment if needed: `py -3.12 -m venv .venv`
5. Install: `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`
6. Start: `.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload`
7. Open `http://127.0.0.1:8000/docs`.

Do not run database initialization against an existing production database unless you understand the migration impact. This update reuses the existing SQLAlchemy tables and adds no required database columns.

## Connector workflow
- `GET /api/connectors` — list all 35 connector templates (public catalogue).
- `GET /api/connectors/{connector_id}/template` — get a starter config (requires Bearer token).
- `POST /api/integrations/generate-config` — generate a config from form values.
- `POST /api/integrations/validate` — validate `{ "config": {...}, "enabled": true }`.
- `POST /api/integrations/test-config` — make a real first-endpoint request; reports actual HTTP result.
- `POST /api/integrations` — save config and encrypt auth credentials.
- `POST /api/integrations/{id}/run` — fetch configured endpoints, paginate according to explicit endpoint settings, map events and persist records/checkpoints.

## Pagination configuration examples
Page pagination:
`"pagination":{"type":"page","page_param":"page","page_size_param":"page_size","page_size":100,"max_pages":10}`

Offset pagination:
`"pagination":{"type":"offset","offset_param":"offset","limit_param":"limit","page_size":100,"max_pages":10}`

Cursor pagination:
`"pagination":{"type":"cursor","cursor_param":"cursor","next_cursor_path":"meta.next_cursor","page_size":100,"max_pages":10}`

Next-link pagination:
`"pagination":{"type":"next_link","next_link_path":"links.next","max_pages":10}`

The actual parameter names and response paths must match the vendor API. Pagination is bounded to avoid unbounded requests.

## Incremental sync
Set config `incremental` to `{ "enabled": true, "strategy": "timestamp" }` and configure the endpoint's vendor-specific incremental parameter in `endpoint.incremental`, for example `{ "param": "since" }`. A connector whose API does not support filtering by timestamp/cursor cannot provide native incremental retrieval; use full fetch plus deduplication and label that limitation clearly. The checkpoint table records the last observed mapped event timestamp/cursor after a successful run.

## Security notes
- Keep `.env` private; never commit it or include it in uploads.
- Use HTTPS and least-privilege vendor API scopes.
- Do not expose credentials in frontend code or logs.
- SSRF checks block private/loopback/reserved destinations by default. Do not disable this outside an isolated local development environment.
- OAuth2 client-credentials token acquisition and AWS SigV4 are not generic credential types implemented by this engine yet; use vendor-specific adapters/token acquisition before marking those connectors operational.
