FROM python:3.14-slim

WORKDIR /worker
COPY . Censys-platform

RUN pip install --no-cache-dir -r Censys-platform/requirements.txt

ENTRYPOINT Censys-platform/censys_search.py
