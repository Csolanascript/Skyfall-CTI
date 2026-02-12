"""Skyfall-CTI · Telegram Crawler — Stub"""
import os, time, signal, sys

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

print(f"[telegram-crawler] Webhook: {os.getenv('N8N_WEBHOOK_URL')}")
print("[telegram-crawler] Stub running — replace with real Telethon logic")

while True:
    time.sleep(60)
