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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
