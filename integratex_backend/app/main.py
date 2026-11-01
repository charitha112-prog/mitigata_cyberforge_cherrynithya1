from datetime import datetime, timezone
from uuid import UUID
import json
import httpx
import asyncio
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from app.config import settings
from app.db import get_db
from app.models import User, Integration, Execution, SecurityRecord, SyncState, Incident
from app.schemas import RegisterIn, LoginIn, IntegrationIn, GenerateConfigIn, TestConfigIn
from app.security import hash_password, verify_password, create_access_token, get_current_user, encrypt_secret, decrypt_secret
from app.catalog import connector_list, get_connector, connector_template
from app.engine import validate_config, request_endpoint, fetch_all, IntegrationError
from app.correlation import correlate_records

app=FastAPI(title="IntegrateX API",version="2.0.0",description="Configuration-driven security integration platform")
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_origin_list,allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

@app.get("/api/health")
def health(): return {"status":"ok","service":"IntegrateX API","database":"configured"}

@app.get("/api/connectors")
def connectors(): return {"count":35,"connectors":connector_list()}

@app.get("/api/connectors/{connector_id}/template")
def get_template(connector_id:str,user=Depends(get_current_user)):
    config=connector_template(connector_id)
    if not config: raise HTTPException(404,"Connector template not found")
    return {"connector":get_connector(connector_id),"config":config}

@app.post("/api/auth/register")
def register(payload:RegisterIn,db:Session=Depends(get_db)):
    if db.scalar(select(User).where(User.email==payload.email)): raise HTTPException(409,"Email already registered")
    user=User(email=payload.email,password_hash=hash_password(payload.password)); db.add(user); db.commit(); db.refresh(user)
    return {"id":str(user.id),"email":user.email}

@app.post("/api/auth/login")
def login(payload:LoginIn,db:Session=Depends(get_db)):
    user=db.scalar(select(User).where(User.email==payload.email))
    if not user or not verify_password(payload.password,user.password_hash): raise HTTPException(401,"Incorrect email or password")
    return {"access_token":create_access_token(str(user.id)),"token_type":"bearer"}

@app.get("/api/integrations")
def list_integrations(db:Session=Depends(get_db),user=Depends(get_current_user)):
    rows=db.scalars(select(Integration).order_by(desc(Integration.created_at))).all()
    return [{"id":str(x.id),"name":x.name,"vendor":x.vendor,"enabled":x.enabled,"status":x.status,"config":x.config_json,"base_url":x.config_json.get("base_url")} for x in rows]

@app.post("/api/integrations/validate")
def validate(payload:IntegrationIn,user=Depends(get_current_user)):
    errors=validate_config(payload.config)
    return {"valid":not errors,"errors":errors}

@app.post("/api/integrations/generate-config")
def generate(payload:GenerateConfigIn,user=Depends(get_current_user)):
    config={"name":payload.name,"vendor":payload.vendor,"base_url":payload.base_url,"auth":{"type":payload.auth_type},"endpoints":payload.endpoints,"schedule":{"type":"manual"},"mapping":payload.mapping,"incremental":payload.incremental}
    return {"config":config,"validation_errors":validate_config(config)}

@app.post("/api/integrations/test-config")
async def test_config(payload:TestConfigIn,user=Depends(get_current_user)):
    errors=validate_config(payload.config)
    if errors: raise HTTPException(422,detail={"message":"Configuration invalid","errors":errors})
    result=await request_endpoint(payload.config["base_url"],payload.config["endpoints"][0],payload.config["auth"])
    return {k:v for k,v in result.items() if k not in {"body","headers"}}

@app.post("/api/integrations")
def create_integration(payload:IntegrationIn,db:Session=Depends(get_db),user=Depends(get_current_user)):
    errors=validate_config(payload.config)
    if errors: raise HTTPException(422,detail={"errors":errors})
    cfg=dict(payload.config); auth=cfg.pop("auth",{"type":"none"})
    secret=encrypt_secret(json.dumps(auth)) if auth.get("type")!="none" else None
    cfg["auth"]={"type":auth.get("type","none"),"configured":bool(secret)}
    row=Integration(name=cfg["name"],vendor=cfg.get("vendor","Custom"),config_json=cfg,credential_ciphertext=secret,enabled=payload.enabled,status="configured")
    db.add(row); db.commit(); db.refresh(row)
    return {"id":str(row.id),"name":row.name,"status":row.status,"credential_saved":bool(secret)}

def _load_auth(row):
    return json.loads(decrypt_secret(row.credential_ciphertext)) if row.credential_ciphertext else {"type":"none"}

def _event_value(item,mapping,key,default=None):
    path=mapping.get(key,key); value=item
    for part in str(path).split("."):
        value=value.get(part) if isinstance(value,dict) else None
    return default if value is None else value

def _parse_time(value):
    if not value:return None
    try:
        if isinstance(value,(int,float)): return datetime.fromtimestamp(value/1000 if value>10**12 else value,tz=timezone.utc)
        parsed=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:return None

@app.post("/api/integrations/{integration_id}/test")
async def test_saved(integration_id:UUID,db:Session=Depends(get_db),user=Depends(get_current_user)):
    row=db.get(Integration,integration_id)
    if not row:raise HTTPException(404,"Integration not found")
    cfg=row.config_json; result=await request_endpoint(cfg["base_url"],cfg["endpoints"][0],_load_auth(row))
    if result["ok"]:row.status="tested";db.commit()
    return {k:v for k,v in result.items() if k not in {"body","headers"}}

@app.post("/api/integrations/{integration_id}/run")
async def run_integration(integration_id:UUID,db:Session=Depends(get_db),user=Depends(get_current_user)):
    row=db.get(Integration,integration_id)
    if not row:raise HTTPException(404,"Integration not found")
    cfg,auth=row.config_json,_load_auth(row)
    execution=Execution(integration_id=row.id,endpoint_name="all",status="running");db.add(execution);db.commit();db.refresh(execution)
    total=pages=0; errors=[]
    try:
        for ep in cfg["endpoints"]:
            state=db.scalar(select(SyncState).where(SyncState.integration_id==row.id,SyncState.endpoint_name==ep.get("name",ep["path"])))
            inc=cfg.get("incremental",{}) or {}; checkpoint=state.checkpoint if state and inc.get("enabled") else None
            ep_run=dict(ep)
            if inc.get("enabled") and inc.get("param"):
                ep_run["incremental"]={"param":inc["param"]}
            fetched=await fetch_all(cfg["base_url"],ep_run,auth,checkpoint=checkpoint,max_pages=int(ep.get("pagination",{}).get("max_pages",20)))
            pages+=fetched["pages"]
            mapping=cfg.get("mapping",{})
            newest=None
            for item in fetched["items"]:
                if not isinstance(item,dict):continue
                external=_event_value(item,mapping,"id")
                if external is not None:
                    existing=db.scalar(select(SecurityRecord).where(SecurityRecord.integration_id==row.id,SecurityRecord.external_id==str(external)))
                    if existing:
                        existing.severity=str(_event_value(item,mapping,"severity","unknown"));existing.title=str(_event_value(item,mapping,"title","Untitled event"));existing.raw_json=item
                        existing.correlation_keys={k:_event_value(item,mapping,k) for k in ("user","ip","host","device_id","resource") if _event_value(item,mapping,k)}
                        existing.event_time=_parse_time(_event_value(item,mapping,"event_time"));continue
                record=SecurityRecord(integration_id=row.id,external_id=str(external) if external is not None else None,
                    event_time=_parse_time(_event_value(item,mapping,"event_time")),severity=str(_event_value(item,mapping,"severity","unknown")),
                    title=str(_event_value(item,mapping,"title","Untitled event")),source=row.vendor,raw_json=item,
                    correlation_keys={k:_event_value(item,mapping,k) for k in ("user","ip","host","device_id","resource") if _event_value(item,mapping,k)})
                db.add(record);total+=1
                candidate=_event_value(item,mapping,"event_time")
                if candidate and (newest is None or str(candidate)>str(newest)):newest=candidate
            if inc.get("enabled") and state is None:
                state=SyncState(integration_id=row.id,endpoint_name=ep.get("name",ep["path"]),strategy=inc.get("strategy","timestamp"),checkpoint=None);db.add(state)
            if inc.get("enabled") and state:
                state.checkpoint=str(newest or fetched.get("checkpoint") or state.checkpoint or "") or None
                state.last_success_at=datetime.now(timezone.utc)
            elif state:state.last_success_at=datetime.now(timezone.utc)
        execution.status="success";execution.fetched_count=total;execution.finished_at=datetime.now(timezone.utc);row.status="connected";db.commit()
        return {"execution_id":str(execution.id),"status":"success","new_records":total,"pages_fetched":pages,"sync_enabled":bool(cfg.get("incremental",{}).get("enabled"))}
    except Exception as exc:
        db.rollback();execution=db.get(Execution,execution.id);execution.status="failed";execution.error_message=str(exc)[:2000];execution.finished_at=datetime.now(timezone.utc);row=db.get(Integration,integration_id);row.status="error";db.commit()
        return {"execution_id":str(execution.id),"status":"failed","error":str(exc)}

@app.get("/api/executions")
def executions(db:Session=Depends(get_db),user=Depends(get_current_user)):
    rows=db.scalars(select(Execution).order_by(desc(Execution.started_at)).limit(200)).all()
    return [{"id":str(x.id),"integration_id":str(x.integration_id) if x.integration_id else None,"status":x.status,"http_status":x.http_status,"fetched_count":x.fetched_count,"error":x.error_message,"started_at":x.started_at,"finished_at":x.finished_at} for x in rows]

@app.get("/api/records")
def records(db:Session=Depends(get_db),user=Depends(get_current_user)):
    rows=db.scalars(select(SecurityRecord).order_by(desc(SecurityRecord.created_at)).limit(500)).all()
    return [{"id":str(x.id),"integration_id":str(x.integration_id) if x.integration_id else None,"external_id":x.external_id,"event_time":x.event_time,"severity":x.severity,"title":x.title,"source":x.source,"correlation_keys":x.correlation_keys,"raw":x.raw_json} for x in rows]

@app.post("/api/correlation/run")
def run_correlation(db:Session=Depends(get_db),user=Depends(get_current_user)):
    rows=db.scalars(select(SecurityRecord).order_by(desc(SecurityRecord.created_at)).limit(1000)).all()
    data=[{"id":str(x.id),"source":x.source,"title":x.title,"event_time":x.event_time,"correlation_keys":x.correlation_keys} for x in rows]
    findings=correlate_records(data);created=[]
    for f in findings:
        inc=Incident(title=f["title"],confidence=f["confidence"],rationale=f["rationale"],evidence_record_ids=[e["record_id"] for e in f["evidence"]]);db.add(inc);created.append(f)
    db.commit();return {"count":len(created),"incidents":findings}

@app.get("/api/incidents")
def incidents(db:Session=Depends(get_db),user=Depends(get_current_user)):
    rows=db.scalars(select(Incident).order_by(desc(Incident.created_at)).limit(200)).all()
    return [{"id":str(x.id),"title":x.title,"confidence":x.confidence,"rationale":x.rationale,"evidence_record_ids":x.evidence_record_ids,"created_at":x.created_at} for x in rows]

@app.post("/api/ai/copilot")
@app.post("/api/ai/explain")
async def ai_explain(
    payload: dict,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Answer Copilot questions with Sarvam; include stored evidence for investigations."""
    if not settings.sarvam_api_key:
        raise HTTPException(
            status_code=503,
            detail="Sarvam API key is not configured in backend .env",
        )

    prompt = str(
        payload.get("message")
        or payload.get("question")
        or payload.get("context")
        or ""
    ).strip()[:10000]

    if not prompt:
        raise HTTPException(status_code=422, detail="Please enter a message.")

    # Add recent database evidence only for questions that ask about security data.
    evidence_context = ""
    investigation_terms = (
        "record", "event", "alert", "incident", "attack",
        "evidence", "investigat", "threat", "log",
    )
    if any(term in prompt.lower() for term in investigation_terms):
        try:
            recent_records = db.scalars(
                select(SecurityRecord)
                .order_by(desc(SecurityRecord.created_at))
                .limit(15)
            ).all()

            evidence = []
            for record in recent_records:
                event_time = (
                    record.event_time.isoformat()
                    if record.event_time
                    else None
                )
                evidence.append({
                    "record_id": str(record.id),
                    "source": record.source,
                    "title": record.title,
                    "severity": record.severity,
                    "event_time": event_time,
                    "correlation_keys": record.correlation_keys or {},
                })

            evidence_context = (
                "\\n\\nIntegrateX database evidence (up to 15 most recently "
                "stored records; this is the available evidence, not proof of "
                "an attack):\\n"
                + json.dumps(evidence, ensure_ascii=False, default=str)
            )
            if not evidence:
                evidence_context += "\\nNo security records are currently stored."
        except Exception as exc:
            print("COPILOT DATABASE CONTEXT ERROR:", repr(exc))
            evidence_context = (
                "\\n\\nIntegrateX database evidence could not be loaded. "
                "Do not claim to have analysed stored records."
            )

    model = settings.sarvam_model or "sarvam-105b"
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are IntegrateX Security Copilot. Explain cybersecurity "
                    "integrations and analyse only evidence supplied in the "
                    "conversation or database context. Clearly distinguish "
                    "observed facts from hypotheses. Never invent incidents, "
                    "indicators, timestamps, or relationships. Do not claim an "
                    "attack is confirmed without sufficient evidence. If evidence "
                    "is missing, say so and suggest verification steps. Keep "
                    "answers concise and practical."
                ),
            },
            {
                "role": "user",
                "content": prompt + evidence_context,
            },
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
        "reasoning_effort": None,
        "stream": False,
    }

    url = settings.sarvam_base_url.rstrip("/") + "/v1/chat/completions"
    headers = {
        "api-subscription-key": settings.sarvam_api_key,
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(90.0)) as client:
            response = None

            # Retry temporary overload/gateway/rate-limit responses.
            for attempt in range(3):
                response = await client.post(url, headers=headers, json=body)
                print("SARVAM STATUS:", response.status_code)

                if response.status_code not in (429, 502, 503, 504):
                    break

                if attempt < 2:
                    await asyncio.sleep(1.5 * (attempt + 1))

            if response is None:
                raise HTTPException(
                    status_code=502,
                    detail="No response received from Sarvam.",
                )

            if not response.is_success:
                # Log a short upstream diagnostic without logging credentials.
                print("SARVAM ERROR BODY:", response.text[:1000])
                upstream_status = response.status_code
                safe_status = (
                    upstream_status
                    if upstream_status in (400, 401, 403, 404, 429)
                    else 502
                )
                raise HTTPException(
                    status_code=safe_status,
                    detail={
                        "message": "Sarvam API request failed.",
                        "sarvam_status": upstream_status,
                        "sarvam_response": response.text[:1000],
                    },
                )

            try:
                data = response.json()
            except ValueError:
                raise HTTPException(
                    status_code=502,
                    detail="Sarvam returned an invalid JSON response.",
                )

            choices = data.get("choices") or []
            if not choices:
                raise HTTPException(
                    status_code=502,
                    detail="Sarvam returned no completion choices.",
                )

            choice = choices[0] or {}
            message = choice.get("message") or {}
            answer = message.get("content")

            # Some compatible responses represent content as text-part arrays.
            if isinstance(answer, list):
                answer = " ".join(
                    part.get("text", "")
                    for part in answer
                    if isinstance(part, dict)
                )

            if not isinstance(answer, str) or not answer.strip():
                finish_reason = choice.get("finish_reason")
                usage = data.get("usage", {})
                print(
                    "SARVAM EMPTY ANSWER:",
                    {
                        "finish_reason": finish_reason,
                        "usage": usage,
                    },
                )
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Sarvam returned no visible answer. "
                        "Please retry; check the backend terminal if it persists."
                    ),
                )

            return {
                "answer": answer.strip(),
                "response": answer.strip(),
                "provider": "Sarvam AI",
                "model": model,
                "evidence_records_included": bool(evidence_context),
            }

    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Sarvam request timed out. Please try again.",
        )
    except httpx.HTTPError as exc:
        print("SARVAM CONNECTION ERROR:", repr(exc))
        raise HTTPException(
            status_code=502,
            detail="Could not connect to Sarvam AI.",
        )
    except Exception as exc:
        print("COPILOT UNEXPECTED ERROR:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail=f"Copilot processing error: {type(exc).__name__}",
        )
