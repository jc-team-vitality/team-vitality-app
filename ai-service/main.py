from fastapi import FastAPI

app = FastAPI(
    title="TeamVitality AI Service",
    description="AI Service for TeamVitality application",
    version="0.1.0"
)

@app.get("/")
async def root():
    return {"message": "Hello World from TeamVitality AI Service (FastAPI)"}

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    reload = os.environ.get("RELOAD", "false").lower() == "true"
    uvicorn.run("main:app", host=host, port=port, reload=reload)
