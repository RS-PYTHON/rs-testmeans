
FROM ghcr.io/rs-python/python:3.11.7-slim-bookworm
LABEL description="This docker allow to run a CADIP mockup server."

WORKDIR /opt/cadip
COPY ./CADIP/cadip_station_mock.py /opt/cadip
COPY ./CADIP/pyproject.toml /opt/cadip
COPY ./CADIP/config /opt/cadip/config
# Copy common folder and associated symbolic link
COPY ./common /opt/common
COPY ./CADIP/common /opt/cadip/common

# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root

# Clean everything
RUN rm -rf /tmp/whl /root/.cache/pip /var/cache/apt/archives /var/lib/apt/lists/*

# Set labels based on the Open Containers Initiative (OCI):
# https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
#
LABEL org.opencontainers.image.source="https://github.com/RS-PYTHON/rs-testmeans"
LABEL org.opencontainers.image.ref.name="ghcr.io/rs-python/rs-testmeans_cadip-station-mock"
LABEL dockerfile.url="https://github.com/RS-PYTHON/rs-testmeans/blob/develop/src/CADIP/Dockerfile"

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/cadip/cadip_station_mock.py", "-H", "0.0.0.0" ]
