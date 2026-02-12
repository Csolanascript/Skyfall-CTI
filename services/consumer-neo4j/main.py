"""Skyfall-CTI · Consumer Neo4j — Stub"""
import os, time, signal, sys

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

print(f"[consumer-neo4j] Waiting for Kafka at {os.getenv('KAFKA_BROKER')}...")
print(f"[consumer-neo4j] Topics: {os.getenv('KAFKA_TOPICS')}")
print(f"[consumer-neo4j] Neo4j: {os.getenv('NEO4J_URI')}")
print("[consumer-neo4j] Stub running — replace with real consumer logic")

while True:
    time.sleep(60)
