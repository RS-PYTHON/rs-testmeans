from fastapi import FastAPI, Request
from DPR_processor_mock import DPRProcessor
from fastapi.responses import JSONResponse
from fastapi import status
import yaml
import uvicorn


app = FastAPI()


@app.post("/run")
async def run_simulator(request: Request):
    data = await request.json()
    yaml_data = yaml.dump(data)
    dpr_sim = DPRProcessor(yaml_data)
    attrs = await dpr_sim.run()
    return JSONResponse(status_code=status.HTTP_200_OK, content=attrs)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)