FROM python:3.12-slim

WORKDIR /worker
COPY . Urlscan.io

RUN pip install --no-cache-dir -r Urlscan.io/requirements.txt

ENTRYPOINT Urlscan.io/urlscan_analyzer.py
