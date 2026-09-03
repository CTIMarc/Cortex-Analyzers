FROM python:3.12-slim

WORKDIR /worker
COPY . PublicWWW

RUN pip install --no-cache-dir -r PublicWWW/requirements.txt

ENTRYPOINT PublicWWW/publicwww_analyzer.py
