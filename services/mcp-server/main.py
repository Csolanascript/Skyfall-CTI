"""Skyfall-CTI · MCP Server — Stub"""
from fastapi import FastAPI

app = FastAPI(title="Skyfall MCP Server")

@app.get("/health")
def health():
    return {"status": "ok", "service": "mcp-server"}

@app.get("/query")
def query():
    return {"message": "stub — replace with real MCP/RAG logic"}
