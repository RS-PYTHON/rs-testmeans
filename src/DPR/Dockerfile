FROM python:3.11-slim-bookworm
LABEL description="This docker allow to run a DPR Processor mockup."

WORKDIR /src/DPR
COPY ./. /src/DPR/

RUN python3.11 -m pip install --upgrade pip
# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root

# Clean everything
RUN rm -rf /tmp/whl /root/.cache/pip /var/cache/apt/archives /var/lib/apt/lists/*

ENTRYPOINT [ "poetry", "run", "python3.11", "dpr_simulator_ws.py"]