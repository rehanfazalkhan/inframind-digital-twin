from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .auth import authenticate
from .config import Settings
from .models import ArchitectureAssessment, BlastRadius, DigitalTwin, Principal, ScanRequest, TerraformProposal, VoiceQuery
from .policy import PolicyViolation
from .service import InfraMindService

settings = Settings.from_environment()
service = InfraMindService(settings)
static_dir = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="InfraMind Digital Twin", version="0.1.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "public, max-age=300"
    return response


def principal(authorization: str | None, role: str) -> Principal:
    return authenticate(authorization, settings, role)


def http_error(error: Exception) -> HTTPException:
    if isinstance(error, KeyError):
        return HTTPException(status_code=404, detail="Requested digital twin, resource, or proposal was not found.")
    if isinstance(error, (PolicyViolation, ValueError)):
        return HTTPException(status_code=403, detail=str(error))
    if isinstance(error, RuntimeError):
        return HTTPException(status_code=503, detail=str(error))
    return HTTPException(status_code=500, detail="InfraMind request failed.")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readiness() -> dict[str, object]:
    gaps = settings.production_gaps() if settings.is_production else []
    return {"status": "ready" if not gaps else "not_ready", "environment": settings.environment, "gaps": gaps}


@app.get("/api/twins", response_model=list[DigitalTwin])
def list_twins() -> list[DigitalTwin]:
    return service.repository.recent()


@app.get("/api/twins/{twin_id}", response_model=DigitalTwin)
def get_twin(twin_id: str) -> DigitalTwin:
    twin = service.repository.get(twin_id)
    if not twin:
        raise HTTPException(status_code=404, detail="Digital twin not found.")
    return twin


@app.post("/api/twins", response_model=DigitalTwin, status_code=201)
async def create_twin(
    request: ScanRequest,
    authorization: str | None = Header(default=None),
    actor_role: str = Header(default="inframind_operator", alias="X-InfraMind-Development-Role"),
) -> DigitalTwin:
    try:
        return await service.create_twin(request, principal(authorization, actor_role))
    except Exception as error:
        raise http_error(error) from error


@app.post("/api/twins/{twin_id}/analyze", response_model=DigitalTwin)
async def analyze_twin(
    twin_id: str,
    authorization: str | None = Header(default=None),
    actor_role: str = Header(default="inframind_operator", alias="X-InfraMind-Development-Role"),
) -> DigitalTwin:
    try:
        return await service.analyze(twin_id, principal(authorization, actor_role))
    except Exception as error:
        raise http_error(error) from error


@app.get("/api/twins/{twin_id}/impact", response_model=BlastRadius)
def blast_radius(twin_id: str, resource_id: str) -> BlastRadius:
    try:
        return service.blast_radius(twin_id, resource_id)
    except Exception as error:
        raise http_error(error) from error


@app.post("/api/twins/{twin_id}/proposals", response_model=TerraformProposal, status_code=201)
def create_proposal(
    twin_id: str,
    authorization: str | None = Header(default=None),
    actor_role: str = Header(default="inframind_operator", alias="X-InfraMind-Development-Role"),
) -> TerraformProposal:
    try:
        return service.create_proposal(twin_id, principal(authorization, actor_role))
    except Exception as error:
        raise http_error(error) from error


@app.post("/api/twins/{twin_id}/proposals/{proposal_id}/approve", response_model=TerraformProposal)
def approve_proposal(
    twin_id: str,
    proposal_id: str,
    authorization: str | None = Header(default=None),
    actor_role: str = Header(default="inframind_approver", alias="X-InfraMind-Development-Role"),
) -> TerraformProposal:
    try:
        return service.approve_proposal(twin_id, proposal_id, principal(authorization, actor_role))
    except Exception as error:
        raise http_error(error) from error


@app.post("/api/twins/{twin_id}/proposals/{proposal_id}/pull-request", response_model=TerraformProposal)
async def create_pull_request(
    twin_id: str,
    proposal_id: str,
    authorization: str | None = Header(default=None),
    actor_role: str = Header(default="inframind_approver", alias="X-InfraMind-Development-Role"),
) -> TerraformProposal:
    try:
        return await service.create_pull_request(twin_id, proposal_id, principal(authorization, actor_role))
    except Exception as error:
        raise http_error(error) from error


@app.post("/api/twins/{twin_id}/query")
def query_twin(
    twin_id: str,
    query: VoiceQuery,
    authorization: str | None = Header(default=None),
    actor_role: str = Header(default="inframind_operator", alias="X-InfraMind-Development-Role"),
) -> dict[str, object]:
    try:
        principal(authorization, actor_role)
        return service.answer_topology_question(twin_id, query.question)
    except Exception as error:
        raise http_error(error) from error
