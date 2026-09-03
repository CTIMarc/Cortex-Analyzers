FROM python:3.12-slim

WORKDIR /worker
COPY . CustomProxy

RUN pip install --no-cache-dir -r CustomProxy/requirements.txt

ENTRYPOINT CustomProxy/custom_proxy.py
