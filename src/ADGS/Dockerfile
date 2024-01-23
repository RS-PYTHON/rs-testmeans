
FROM python:3.11-slim-bookworm
LABEL description="This docker allow to run a ADGS mockup server."

WORKDIR /opt/adgs
COPY ./adgs_station_mock.py /opt/adgs
COPY ./pyproject.toml /opt/adgs
COPY ./config /opt/adgs/config

# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root

# Clean everything
RUN rm -rf /tmp/whl /root/.cache/pip /var/cache/apt/archives /var/lib/apt/lists/*

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/adgs/adgs_station_mock.py", "-H", "0.0.0.0" ]
