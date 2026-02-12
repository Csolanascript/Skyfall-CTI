"""Skyfall-CTI · Dumps Crawler — Stub"""
import os, time, signal, sys

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

print(f"[dumps-crawler] Kafka: {os.getenv('KAFKA_BROKER')}")
print(f"[dumps-crawler] Topic: {os.getenv('KAFKA_TOPIC')}")
print(f"[dumps-crawler] Intel-Owl: {os.getenv('INTELOWL_URL')}")
print(f"[dumps-crawler] Interval: {os.getenv('SCRAPE_INTERVAL_SECONDS')}s")
print("[dumps-crawler] Stub running — replace with real scraping logic")

while True:
    time.sleep(int(os.getenv("SCRAPE_INTERVAL_SECONDS", "3600")))
