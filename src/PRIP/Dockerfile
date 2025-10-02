
FROM ghcr.io/rs-python/python:3.11.7-slim-bookworm
LABEL description="This docker allow to run a PRIP mockup server."

COPY ./layer-cleanup.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/layer-cleanup.sh

WORKDIR /opt/prip
COPY ./PRIP/prip_station_mock.py /opt/prip
COPY ./PRIP/pyproject.toml /opt/prip
COPY ./PRIP/config /opt/prip/config
# Copy common folder and associated symbolic link
COPY ./common /opt/common
COPY ./PRIP/common /opt/prip/common

# Change poetry virtual env dir or it will be removed by layer-cleanup
# See: https://python-poetry.org/docs/configuration/#cache-directory
ENV POETRY_CACHE_DIR=/root/pypoetry

# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry && layer-cleanup.sh

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root && layer-cleanup.sh

# Set labels based on the Open Containers Initiative (OCI):
# https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
#
LABEL org.opencontainers.image.source="https://github.com/RS-PYTHON/rs-testmeans"
LABEL org.opencontainers.image.ref.name="ghcr.io/rs-python/rs-testmeans_prip-station-mock"
LABEL dockerfile.url="https://github.com/RS-PYTHON/rs-testmeans/blob/develop/src/PRIP/Dockerfile"

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/prip/prip_station_mock.py", "-H", "0.0.0.0" ]
