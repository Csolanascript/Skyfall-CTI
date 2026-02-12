"""Skyfall-CTI · Consumer Elasticsearch — Stub"""
import os, time, signal, sys

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

print(f"[consumer-elastic] Waiting for Kafka at {os.getenv('KAFKA_BROKER')}...")
print(f"[consumer-elastic] Topics: {os.getenv('KAFKA_TOPICS')}")
print(f"[consumer-elastic] ES: {os.getenv('ELASTICSEARCH_URL')}")
print("[consumer-elastic] Stub running — replace with real consumer logic")

while True:
    time.sleep(60)
