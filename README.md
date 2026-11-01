# IntegrateX Frontend

React + Vite frontend for the IntegrateX FastAPI backend.

## Run
1. Open this folder in VS Code.
2. In the terminal run:
   ```powershell
   npm install
   ```
3. Copy `.env.example` to `.env` (the default backend URL is for local development).
4. Start the frontend:
   ```powershell
   npm run dev
   ```
5. Open the URL shown by Vite (normally http://localhost:5173).

Keep the FastAPI backend running at `http://127.0.0.1:8000`.

## Important integration notes
- The frontend uses the API paths currently documented in the IntegrateX backend: `/api/auth/register`, `/api/auth/login`, `/api/connectors`, `/api/integrations`, `/api/integrations/validate`, `/api/integrations/generate-config`, `/api/integrations/test-config`, `/api/integrations/{id}/test`, `/api/integrations/{id}/run`, `/api/executions`, `/api/records`, and `/api/dashboard`.
- Protected calls send `Authorization: Bearer <JWT>`.
- Sarvam credentials are never stored in this frontend. Configure the Sarvam key in the backend `.env`.
- The Copilot page calls `VITE_COPILOT_ENDPOINT` (default `/api/ai/copilot`). This route must exist in the backend; if your backend exposes a different path, change the environment variable. It does not pretend AI is working if the route is unavailable.
- Storyboard correlation is an evidence-first frontend view over records returned by `/api/records`. It labels associations as candidate correlations and does not claim an attack occurred.
- Connector catalogue entries marked `template` are not live connections. A connector becomes live only after valid vendor credentials and a successful real API test.
