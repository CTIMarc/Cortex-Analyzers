FROM python:3.12-slim

WORKDIR /worker
COPY . Shodan

RUN pip install --no-cache-dir -r Shodan/requirements.txt

ENTRYPOINT Shodan/shodan_analyzer.py
