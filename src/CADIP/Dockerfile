
FROM ubuntu:20.04
LABEL description="This docker allow to run a CADIP mockup server."

WORKDIR /opt/cadip
COPY ./cadip_station_mock.py /opt/cadip
COPY ./pyproject.toml /opt/cadip
COPY ./config /opt/cadip/config


ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Install system dependencies
RUN apt-get update -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends \
    software-properties-common \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends \
    curl \
    && add-apt-repository ppa:deadsnakes/ppa -y \
    && apt-get update -y

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends \
    python3.11 python3.11-distutils

RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.11

RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN python3.11 -m pip install --no-cache-dir poetry

SHELL ["/bin/bash", "-c"]
RUN poetry install --no-root

ENTRYPOINT [ "poetry", "run", "python3.11", "/opt/cadip/cadip_station_mock.py", "-H", "0.0.0.0" ]
