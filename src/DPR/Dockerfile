# FROM python:3.11.7-bullseye
FROM python:3.11-slim-bookworm as builder
RUN apt update && apt install -y libpq-dev gcc

# Update pip version
RUN pip install --no-cache-dir --upgrade pip

RUN mkdir -p /tmp/whl
ADD ./*.whl /tmp/whl

# Install the wheel packages in the right order (dependencies first).
# This also installs all the sub-dependencies e.g. fastapi ect ...
RUN cd /tmp/whl && pip install --no-cache-dir rs_server_common-*.whl rs_server_adgs-*.whl

FROM python:3.11-slim-bookworm

# Install dependencies necessary for execution (e.g. libpq) not compilation (gcc)
RUN \
    apt update && \
    apt install -y libpq-dev && \
    rm -rf /var/cache/apt/archives /var/lib/apt/lists/*

# Copy the python installation from the build stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Clean everything
RUN rm -rf /tmp/whl /root/.cache/pip /var/cache/apt/archives /var/lib/apt/lists/*

# Add a default user
RUN useradd -m user
USER user
WORKDIR /home/user
