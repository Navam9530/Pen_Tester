import logging, pdfkit, base64
from main import setup_logging, get_report
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

setup_logging()
logger = logging.getLogger(__name__)
app = FastAPI(title="Pen Tester")
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_root():
    return FileResponse("static/index.html")

@app.post("/getReport")
async def api_getReport(request: Request):
    logger.info("API /getReport hit")
    body = await request.json()
    url = body["url"]

    report = await get_report(url)
    if report is None:
        return {"error": "Failed to generate report"}

    pdf_bytes = pdfkit.from_string(report["report"], output_path=False)
    pdf_base64 = base64.b64encode(pdf_bytes).decode("utf-8")

    return {"status": "success", "data": report, "pdf_base64": pdf_base64}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=9530, reload=True)
