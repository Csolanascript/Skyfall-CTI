"""Skyfall-CTI · KEVin API — Stub"""
from fastapi import FastAPI

app = FastAPI(title="KEVin API — CVE to STIX 2.1")

@app.get("/health")
def health():
    return {"status": "ok", "service": "kevin-api"}

@app.post("/normalize")
def normalize():
    return {"message": "stub — replace with real CVE normalization logic"}
