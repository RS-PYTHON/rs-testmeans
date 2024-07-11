
FROM python:3.11-slim-bookworm
LABEL description="This docker allows to run a LTA mockup server."

WORKDIR /opt/LTA
COPY ./lta_station_mock.py /opt/LTA
COPY ./pyproject.toml /opt/LTA
COPY ./config /opt/LTA/config

# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root

# Clean everything
RUN rm -rf /tmp/whl /root/.cache/pip /var/cache/apt/archives /var/lib/apt/lists/*

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/LTA/lta_station_mock.py", "-H", "0.0.0.0" ]
