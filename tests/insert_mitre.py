import json
import requests
from kafka import KafkaProducer
from stix2 import MemoryStore

# Configuración de Skyfall-Backbone
KAFKA_BROKER = "localhost:9092"  # Cambiar a kafka:29092 si corre dentro de Docker
TOPIC_DESTINO = "stix.osint"     # O el topic que use tu consumer-neo4j

def ingest_mitre_to_kafka():
    # 1. Descargar el Bundle oficial de MITRE Enterprise ATT&CK
    print("📥 Descargando datos de MITRE ATT&CK...")
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url)
    mitre_data = response.json()

    # 2. Cargar en MemoryStore (siguiendo la guía de MITRE)
    # Esto valida que el STIX sea correcto
    mem_store = MemoryStore(stix_data=mitre_data)
    
    # 3. Configurar Productor de Kafka
    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        compression_type='gzip' # Recomendado para STIX (mucho texto repetitivo)
    )

    # 4. Extraer objetos y enviarlos individualmente
    # Obtenemos todos los objetos del bundle
    all_objects = mitre_data.get("objects", [])
    total = len(all_objects)
    
    print(f"🚀 Iniciando envío de {total} objetos a Kafka...")

    for i, obj in enumerate(all_objects):
        # Enviamos cada objeto por separado para no saturar el tamaño de mensaje de Kafka
        producer.send(TOPIC_DESTINO, obj)
        
        if i % 500 == 0:
            print(f"✅ Enviados {i}/{total} objetos...")

    producer.flush()
    print("✨ Ingesta completada con éxito.")

if __name__ == "__main__":
    ingest_mitre_to_kafka()