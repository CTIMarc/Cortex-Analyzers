FROM python:3.12-slim

WORKDIR /worker
COPY . VirusTotal

RUN pip install --no-cache-dir -r VirusTotal/requirements.txt

ENTRYPOINT VirusTotal/virustotal.py
