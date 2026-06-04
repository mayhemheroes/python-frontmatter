# Build Stage
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir atheris

ADD . /src
WORKDIR /src
RUN python3 -m pip install --no-cache-dir .

CMD ["/src/mayhem/fuzz_load.py"]
