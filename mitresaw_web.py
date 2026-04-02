#!/usr/bin/env python3
"""MITRESaw Web — Single-page web interface for MITRESaw."""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

app = FastAPI(title="MITRESaw Web")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_run_state = {
    "running": False,
    "pid": None,
    "started": None,
    "log": [],
    "progress": {"procedures": 0, "procedures_total": 0, "citations": 0, "citations_total": 0},
    "complete": False,
    "error": None,
}
_log_lock = threading.Lock()


def _reset_state():
    _run_state.update({
        "running": False,
        "pid": None,
        "started": None,
        "log": [],
        "progress": {"procedures": 0, "procedures_total": 0, "citations": 0, "citations_total": 0},
        "complete": False,
        "error": None,
    })


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse("static/index.html")


@app.post("/api/run")
async def start_run(request: Request):
    if _run_state["running"]:
        return JSONResponse({"error": "A run is already in progress"}, status_code=409)

    body = await request.json()
    flags = body.get("flags", "-D -E")

    _reset_state()
    _run_state["running"] = True
    _run_state["started"] = datetime.now().isoformat()

    def _run():
        try:
            cmd = [sys.executable, "MITRESaw.py"] + flags.split()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            _run_state["pid"] = proc.pid
            for line in proc.stdout:
                line = line.rstrip("\n")
                with _log_lock:
                    _run_state["log"].append(line)
                    # Keep last 500 lines
                    if len(_run_state["log"]) > 500:
                        _run_state["log"] = _run_state["log"][-500:]
            proc.wait()
            _run_state["complete"] = True
            if proc.returncode != 0:
                _run_state["error"] = f"Exit code {proc.returncode}"
        except Exception as e:
            _run_state["error"] = str(e)
        finally:
            _run_state["running"] = False

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started", "flags": flags}


@app.get("/api/status")
async def get_status():
    with _log_lock:
        last_lines = _run_state["log"][-20:]
    return {
        "running": _run_state["running"],
        "complete": _run_state["complete"],
        "error": _run_state["error"],
        "started": _run_state["started"],
        "log_lines": len(_run_state["log"]),
        "last_lines": last_lines,
    }


@app.get("/api/log")
async def get_log():
    with _log_lock:
        return {"log": _run_state["log"]}


@app.get("/api/log/stream")
async def log_stream(request: Request):
    """SSE stream of log lines."""
    async def generate():
        last_idx = 0
        while True:
            if await request.is_disconnected():
                break
            with _log_lock:
                new_lines = _run_state["log"][last_idx:]
                last_idx = len(_run_state["log"])
            for line in new_lines:
                yield {"event": "log", "data": line}
            if not _run_state["running"] and last_idx >= len(_run_state["log"]):
                yield {"event": "done", "data": json.dumps({
                    "complete": _run_state["complete"],
                    "error": _run_state["error"],
                })}
                break
            await asyncio.sleep(0.5)

    return EventSourceResponse(generate())


@app.post("/api/stop")
async def stop_run():
    if not _run_state["running"] or not _run_state["pid"]:
        return {"status": "not running"}
    try:
        import signal
        os.kill(_run_state["pid"], signal.SIGTERM)
        return {"status": "stopped"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/results")
async def list_results():
    """List output files in data/."""
    files = []
    data_dir = Path("data")
    if data_dir.exists():
        for f in sorted(data_dir.rglob("*")):
            if f.is_file() and not f.name.startswith(".") and not str(f).startswith("data/stix"):
                stat = f.stat()
                files.append({
                    "path": str(f),
                    "name": f.name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
    return {"files": files}


@app.get("/api/results/download")
async def download_file(path: str):
    p = Path(path)
    if not p.exists() or not str(p).startswith("data"):
        return JSONResponse({"error": "File not found"}, status_code=404)
    return FileResponse(p, filename=p.name)


@app.get("/api/cache/stats")
async def cache_stats():
    cache_dir = Path("data/.citation_cache")
    if not cache_dir.exists():
        return {"total": 0, "size_mb": 0, "success": 0, "failed": 0}
    total = 0
    success = 0
    failed = 0
    size = 0
    for f in cache_dir.glob("*.json"):
        total += 1
        size += f.stat().st_size
        try:
            data = json.loads(f.read_text())
            if data.get("text"):
                success += 1
            else:
                failed += 1
        except Exception:
            failed += 1
    return {
        "total": total,
        "size_mb": round(size / 1024 / 1024, 1),
        "success": success,
        "failed": failed,
    }


@app.get("/api/exclusions")
async def get_exclusions():
    import csv
    path = Path("data/exclusions.csv")
    if not path.exists():
        return {"exclusions": []}
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return {"exclusions": rows}


@app.post("/api/exclusions")
async def update_exclusions(request: Request):
    import csv
    body = await request.json()
    rows = body.get("exclusions", [])
    path = Path("data/exclusions.csv")
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["indicator", "reason"])
        writer.writeheader()
        for row in rows:
            writer.writerow({"indicator": row.get("indicator", ""), "reason": row.get("reason", "")})
    return {"status": "saved", "count": len(rows)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    print("\n  MITRESaw Web — http://localhost:6729\n")
    uvicorn.run(app, host="0.0.0.0", port=6729)
