FROM ghcr.io/rs-python/python:3.11.7-slim-bookworm
LABEL description="This docker allow to run a DPR Processor mockup."

COPY ./layer-cleanup.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/layer-cleanup.sh

WORKDIR /src/DPR
COPY ./. /src/DPR/
COPY ./common /src/common

RUN python3.11 -m pip install --upgrade pip && layer-cleanup.sh
# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry && layer-cleanup.sh

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root && layer-cleanup.sh

# Set labels based on the Open Containers Initiative (OCI):
# https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
#
LABEL org.opencontainers.image.source="https://github.com/RS-PYTHON/rs-testmeans"
LABEL org.opencontainers.image.ref.name="ghcr.io/rs-python/rs-testmeans_dpr-station-mock"
LABEL dockerfile.url="https://github.com/RS-PYTHON/rs-testmeans/blob/develop/src/DPR/Dockerfile"

ENTRYPOINT [ "poetry", "run", "python3.11", "dpr_simulator_ws.py"]