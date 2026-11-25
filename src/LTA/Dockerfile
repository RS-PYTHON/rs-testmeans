
#
# Target Docker image name:
# ghcr.io/rs-python/rs-testmeans_lta-station-mock
#

ARG PYTHON_VERSION=3.13.18

FROM ghcr.io/rs-python/python:${PYTHON_VERSION}-slim-bookworm
LABEL description="This docker allows to run a LTA mockup server."

COPY ./layer-cleanup.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/layer-cleanup.sh

WORKDIR /opt/LTA
COPY ./lta_station_mock.py /opt/LTA
COPY ./pyproject.toml /opt/LTA
COPY ./uv.lock /opt/LTA
COPY ./config /opt/LTA/config

# Install uv, see: https://docs.astral.sh/uv/guides/integration/docker/
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/

# Install the locked dependencies (without the dev dependencies) in /opt/LTA/.venv, with the system python
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy UV_NO_CACHE=1
RUN uv sync --frozen --no-dev --no-build && rm /usr/local/bin/uv && layer-cleanup.sh
ENV PATH="/opt/LTA/.venv/bin:$PATH"

# Remove custom scripts
RUN rm -f /usr/local/bin/layer-cleanup.sh /usr/local/bin/restore-apt.sh

# Set labels based on the Open Containers Initiative (OCI):
# https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
#
LABEL org.opencontainers.image.source="https://github.com/RS-PYTHON/rs-testmeans"
LABEL dockerfile.url="https://github.com/RS-PYTHON/rs-testmeans/blob/develop/src/LTA/Dockerfile"

ENTRYPOINT [ "python3", "/opt/LTA/lta_station_mock.py", "-H", "0.0.0.0" ]
