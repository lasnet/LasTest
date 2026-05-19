from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.core.security import require_api_key
from app.models.schemas import CreateJobRequest, CreateProjectRequest, ScopeUpdateRequest
from app.services.jobs import JobStore
from app.services.projects import create_project, get_project, list_projects, update_scope
from app.services.tool_registry import available_tasks, validate_task_type


router = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])


@router.get("/tools")
def tools():
    return {"tasks": available_tasks()}


@router.get("/projects")
def projects():
    return {"projects": list_projects()}


@router.post("/projects", status_code=status.HTTP_201_CREATED)
def create_project_endpoint(payload: CreateProjectRequest):
    try:
        return create_project(payload.name, payload.client, payload.description)
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/projects/{project_name}")
def project_detail(project_name: str):
    try:
        return get_project(project_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/projects/{project_name}/scope")
def update_project_scope(project_name: str, payload: ScopeUpdateRequest):
    try:
        return update_scope(project_name, payload.domains, payload.ips, payload.replace)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/projects/{project_name}/jobs", status_code=status.HTTP_202_ACCEPTED)
def create_job(project_name: str, payload: CreateJobRequest):
    try:
        validate_task_type(payload.task_type)
        get_project(project_name)
        return JobStore().create_job(project_name, payload.task_type, payload.params)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/jobs")
def jobs(
    project_name: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    try:
        return {"jobs": JobStore().list_jobs(project_name=project_name, limit=limit)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/jobs/{job_id}")
def job_detail(job_id: str):
    try:
        return JobStore().get_job(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/jobs/{job_id}/log")
def job_log(job_id: str):
    try:
        content = JobStore().read_log_tail(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(content=content, media_type="text/plain; charset=utf-8")

