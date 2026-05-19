from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from app.core.security import require_analyst, require_viewer
from app.models.schemas import CreateJobRequest, CreateProjectRequest, ScopeUpdateRequest
from app.services.auth import AuthStore
from app.services.dashboard import build_project_dashboard
from app.services.jobs import JobStore
from app.services.projects import create_project, get_project, list_projects, update_scope
from app.services.tool_registry import available_tasks, validate_task_type


router = APIRouter(prefix="/api")


@router.get("/tools")
def tools(user: dict = Depends(require_viewer)):
    return {"tasks": available_tasks()}


@router.get("/projects")
def projects(user: dict = Depends(require_viewer)):
    return {"projects": list_projects()}


@router.post("/projects", status_code=status.HTTP_201_CREATED)
def create_project_endpoint(
    payload: CreateProjectRequest,
    request: Request,
    user: dict = Depends(require_analyst),
):
    try:
        project = create_project(payload.name, payload.client, payload.description)
        _audit(
            user,
            request,
            "project.create",
            "project",
            project.get("project", {}).get("name"),
            {"client": payload.client},
        )
        return project
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/projects/{project_name}")
def project_detail(project_name: str, user: dict = Depends(require_viewer)):
    try:
        return get_project(project_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/projects/{project_name}/dashboard")
def project_dashboard(project_name: str, user: dict = Depends(require_viewer)):
    try:
        return build_project_dashboard(project_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/projects/{project_name}/scope")
def update_project_scope(
    project_name: str,
    payload: ScopeUpdateRequest,
    request: Request,
    user: dict = Depends(require_analyst),
):
    try:
        project = update_scope(
            project_name,
            payload.domains,
            payload.ips,
            payload.exclusions,
            payload.replace,
        )
        _audit(
            user,
            request,
            "project.update_scope",
            "project",
            project_name,
            {
                "domains": len(payload.domains or []),
                "ips": len(payload.ips or []),
                "exclusions": len(payload.exclusions or []),
                "replace": payload.replace,
            },
        )
        return project
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/projects/{project_name}/jobs", status_code=status.HTTP_202_ACCEPTED)
def create_job(
    project_name: str,
    payload: CreateJobRequest,
    request: Request,
    user: dict = Depends(require_analyst),
):
    try:
        validate_task_type(payload.task_type)
        get_project(project_name)
        job = JobStore().create_job(project_name, payload.task_type, payload.params)
        _audit(
            user,
            request,
            "job.create",
            "job",
            job["id"],
            {"project_name": project_name, "task_type": payload.task_type},
        )
        return job
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/jobs")
def jobs(
    project_name: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    user: dict = Depends(require_viewer),
):
    try:
        return {"jobs": JobStore().list_jobs(project_name=project_name, limit=limit)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/jobs/{job_id}")
def job_detail(job_id: str, user: dict = Depends(require_viewer)):
    try:
        return JobStore().get_job(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/jobs/{job_id}/log")
def job_log(job_id: str, user: dict = Depends(require_viewer)):
    try:
        content = JobStore().read_log_tail(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(content=content, media_type="text/plain; charset=utf-8")


def _audit(
    user: dict,
    request: Request,
    action: str,
    resource_type: str,
    resource_id: str | None,
    details: dict,
) -> None:
    AuthStore().audit(
        actor=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status="success",
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        details=details,
    )
