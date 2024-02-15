from fastapi import FastAPI, Request
from .DPRProcessor import DPRProcessor
from fastapi.responses import JSONResponse
from fastapi import status
import yaml

app = FastAPI()


@app.post("/run")
async def run_simulator(request: Request):
    data = await request.json()
    yaml_data = yaml.dump(data)
    dpr_sim = DPRProcessor(yaml_data)
    attrs = await dpr_sim.run()
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=attrs)
