FROM python:3.14-slim

WORKDIR /worker
COPY . Shodan

RUN pip install --no-cache-dir -r Shodan/requirements.txt

ENTRYPOINT Shodan/shodan_analyzer.py
