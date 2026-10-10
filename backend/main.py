import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .orchestrator import run_investigation
from .reasoning_agent import run_reasoning
from .models import ReasoningRequest

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="AegisAI APK Threat Investigation",
    description="Static APK investigation pipeline with threat intelligence and explainable risk analysis. APKs are never installed or executed.",
    version="2.0.0",
)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "aegisai", "execution_policy": "APK is never installed or executed"}


@app.post("/api/analyze")
async def analyze_apk_endpoint(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Please upload a .apk file")
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            content = await file.read()
            if len(content) == 0:
                raise HTTPException(status_code=400, detail="Uploaded APK is empty")
            tmp.write(content)
            tmp_path = tmp.name
        return await run_investigation(tmp_path, file.filename)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze APK: {e}")
    finally:
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)


@app.post("/api/reason")
async def reason_endpoint(payload: ReasoningRequest):
    """
    GenAI Reasoning Agent endpoint. Takes findings already produced by the
    Static Analysis and Threat Intelligence Agents and reasons over them —
    it does not re-scan the APK itself.
    """
    result = await run_reasoning(payload.app_info, payload.findings, payload.iocs)
    return result


@app.get("/")
async def frontend():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/reasoning")
async def reasoning_page():
    return FileResponse(FRONTEND_DIR / "reasoning.html")


@app.get("/threat-intel")
async def threat_intel_page():
    return FileResponse(FRONTEND_DIR / "threat.html")


@app.get("/network")
async def network_page():
    return FileResponse(FRONTEND_DIR / "network.html")


@app.get("/sandbox")
async def sandbox_page():
    return FileResponse(FRONTEND_DIR / "sandbox.html")


@app.get("/codegraph")
async def codegraph_page():
    return FileResponse(FRONTEND_DIR / "codegraph.html")


@app.get("/verifier")
async def verifier_page():
    return FileResponse(FRONTEND_DIR / "verifier.html")


@app.get("/report")
async def report_page():
    return FileResponse(FRONTEND_DIR / "report.html")
