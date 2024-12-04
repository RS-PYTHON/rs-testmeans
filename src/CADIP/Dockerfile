
FROM ghcr.io/rs-python/python:3.11.7-slim-bookworm
LABEL description="This docker allow to run a CADIP mockup server."

WORKDIR /opt/cadip
COPY ./cadip_station_mock.py /opt/cadip
COPY ./pyproject.toml /opt/cadip
COPY ./config /opt/cadip/config

# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root

# Clean everything
RUN rm -rf /tmp/whl /root/.cache/pip /var/cache/apt/archives /var/lib/apt/lists/*

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/cadip/cadip_station_mock.py", "-H", "0.0.0.0" ]
