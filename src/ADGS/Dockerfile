
FROM ghcr.io/rs-python/python:3.11.7-slim-bookworm
LABEL description="This docker allow to run a ADGS mockup server."

WORKDIR /opt/adgs
COPY ./adgs_station_mock.py /opt/adgs
COPY ./common /opt/adgs/common
COPY ./pyproject.toml /opt/adgs
COPY ./config /opt/adgs/config

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
LABEL org.opencontainers.image.ref.name="ghcr.io/rs-python/rs-testmeans_adgs-station-mock"
LABEL dockerfile.url="https://github.com/RS-PYTHON/rs-testmeans/blob/develop/src/ADGS/Dockerfile"

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/adgs/adgs_station_mock.py", "-H", "0.0.0.0" ]
