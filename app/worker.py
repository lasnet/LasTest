from __future__ import annotations

import signal
import sys
import time
import traceback
from pathlib import Path
from typing import TextIO

from app.core.settings import get_settings
from app.services.jobs import JobStore
from app.services.paths import ensure_runtime_dirs
from app.services.tool_registry import run_task


STOP = False


def _handle_stop(signum, frame):  # noqa: ARG001
    global STOP
    STOP = True


def _log_writer(handle: TextIO):
    def write(message: str) -> None:
        handle.write(message.rstrip("\n") + "\n")
        handle.flush()

    return write


def run_once(store: JobStore | None = None) -> bool:
    settings = get_settings()
    ensure_runtime_dirs(settings)
    store = store or JobStore(settings)
    job = store.acquire_next_job()
    if job is None:
        return False

    log_path = Path(job["log_path"])
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as log_file:
        log = _log_writer(log_file)
        log(f"Job {job['id']} started: {job['task_type']} / {job['project_name']}")
        try:
            result = run_task(
                job["task_type"],
                job["project_name"],
                job.get("params") or {},
                log,
                settings,
            )
        except Exception as exc:
            log("Job failed")
            log(traceback.format_exc())
            store.finish_job(job["id"], "failed", error=str(exc))
            return True

        log(f"Job finished: {result}")
        store.finish_job(job["id"], "succeeded", result=result)
    return True


def main() -> int:
    settings = get_settings()
    ensure_runtime_dirs(settings)
    store = JobStore(settings)
    store.ensure_schema()

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    print("LasTest worker started", flush=True)
    while not STOP:
        processed = run_once(store)
        if not processed:
            time.sleep(settings.job_poll_interval_sec)
    print("LasTest worker stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

