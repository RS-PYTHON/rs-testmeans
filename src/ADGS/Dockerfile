
FROM ghcr.io/rs-python/python:3.11.7-slim-bookworm
LABEL description="This docker allow to run a ADGS mockup server."

COPY ./layer-cleanup.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/layer-cleanup.sh

WORKDIR /opt/adgs
COPY ./ADGS/adgs_station_mock.py /opt/adgs
COPY ./ADGS/pyproject.toml /opt/adgs
COPY ./ADGS/config /opt/adgs/config
# Copy common folder and associated symbolic link
COPY ./common /opt/common
COPY ./ADGS/common /opt/adgs/common

# Change poetry virtual env dir or it will be removed by layer-cleanup
# See: https://python-poetry.org/docs/configuration/#cache-directory
ENV POETRY_CACHE_DIR=/root/pypoetry

# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry && layer-cleanup.sh

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root && layer-cleanup.sh

# Remove apt repository list and custom scripts
RUN rm -f /etc/apt/sources.list /usr/local/bin/layer-cleanup.sh /usr/local/bin/restore-apt.sh

# Set labels based on the Open Containers Initiative (OCI):
# https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
#
LABEL org.opencontainers.image.source="https://github.com/RS-PYTHON/rs-testmeans"
LABEL org.opencontainers.image.ref.name="ghcr.io/rs-python/rs-testmeans_adgs-station-mock"
LABEL dockerfile.url="https://github.com/RS-PYTHON/rs-testmeans/blob/develop/src/ADGS/Dockerfile"

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/adgs/adgs_station_mock.py", "-H", "0.0.0.0" ]
