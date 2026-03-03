import os, sys, json, time, signal, requests
from collections import Counter
from stix2 import MemoryStore
from neo4j import GraphDatabase

# ── Configuración ─────────────────────────────────────────────────────────
MITRE_DOMAINS = os.getenv("MITRE_DOMAINS", "enterprise-attack,mobile-attack,ics-attack").split(",")
MITRE_BASE_URL = os.getenv("MITRE_BASE_URL", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master")
NEO4J_URL = os.getenv("NEO4J_URL", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "skyfall2026")
MITRE_OUTPUT_PATH = os.getenv("MITRE_OUTPUT_PATH", "/data/mitre_bundle.json")

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

class Neo4jLoader:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def load_stix_objects(self, objects):
        nodes = [obj for obj in objects if obj['type'] != 'relationship']
        rels = [obj for obj in objects if obj['type'] == 'relationship']
        with self.driver.session() as session:
            print(f"[neo4j] Cargando {len(nodes)} nodos...")
            session.execute_write(self._create_nodes_batch, nodes)
            print(f"[neo4j] Cargando {len(rels)} relaciones...")
            session.execute_write(self._create_rels_batch, rels)

    @staticmethod
    def _create_nodes_batch(tx, nodes):
        query = """
        UNWIND $batch AS obj
        MERGE (n:StixObject {id: obj.id})
        SET n.name = obj.name,
            n.type = obj.type,
            n.description = obj.description,
            n.created = obj.created,
            n.modified = obj.modified,
            n.external_id = [ref IN obj.external_references WHERE ref.source_name IN ['mitre-attack', 'mobile-attack', 'ics-attack'] | ref.external_id][0]
        WITH n, obj
        CALL apoc.create.addLabels(n, [replace(toUpper(substring(obj.type,0,1)) + substring(obj.type,1), '-', '_')]) YIELD node
        RETURN count(node)
        """
        tx.run(query, batch=nodes)

    @staticmethod
    def _create_rels_batch(tx, rels):
        query = """
        UNWIND $batch AS rel
        MATCH (src:StixObject {id: rel.source_ref})
        MATCH (tgt:StixObject {id: rel.target_ref})
        CALL apoc.create.relationship(src, toUpper(replace(rel.relationship_type, '-', '_')), {id: rel.id}, tgt) YIELD rel as r
        RETURN count(r)
        """
        tx.run(query, batch=rels)

def download_mitre_domain(domain: str) -> dict:
    url = f"{MITRE_BASE_URL}/{domain}/{domain}.json"
    print(f"[mitre-ingestor] Descargando {domain}...")
    resp = requests.get(url, timeout=120); resp.raise_for_status()
    return resp.json()

def save_for_elastic_ndjson(objects: list):
    """
    Guarda los objetos en formato NDJSON (Newline Delimited JSON).
    Cada objeto STIX será una línea independiente para una ingesta eficiente en Elastic.
    """

    print(f"[mitre-ingestor] Generando datos en formato NDJSON para Elastic...")
    
    # Aseguramos que el directorio de staging existe
    os.makedirs(os.path.dirname(MITRE_OUTPUT_PATH), exist_ok=True)
    
    # Escribimos objeto por objeto, uno por línea
    try:
        with open(MITRE_OUTPUT_PATH, "w", encoding="utf-8") as f:
            for obj in objects:
                # Convertimos el objeto a string y añadimos salto de línea
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        
        print(f"[mitre-ingestor] Archivo NDJSON guardado: {len(objects)} objetos listos para ingesta.")
    except Exception as e:
        print(f"[!] Error al guardar el archivo: {e}")

def main():
    if os.getenv("RUN_MITRE_INGESTOR", "0") != "1":
        print("[mitre-ingestor] RUN_MITRE_INGESTOR=0. Saliendo.")
        return

    all_objects = []
    for domain in MITRE_DOMAINS:
        bundle = download_mitre_domain(domain.strip())
        all_objects.extend(bundle.get("objects", []))
    
    save_for_elastic_ndjson(all_objects)

    print(f"\n[mitre-ingestor] Conectando a Neo4j en {NEO4J_URL}...")
    loader = Neo4jLoader(NEO4J_URL, NEO4J_USER, NEO4J_PASS)
    
    # Bucle de espera para Neo4j
    connected = False
    for i in range(15):
        try:
            with loader.driver.session() as s: s.run("RETURN 1")
            connected = True; break
        except Exception:
            print(f"  [{i+1}/15] Neo4j arrancando... esperando 5s")
            time.sleep(5)
    
    if not connected:
        print("[!] Error: Neo4j no respondió. Revisa los logs de neo4j."); return

    try:
        loader.load_stix_objects(all_objects)
        print("[mitre-ingestor] ¡Carga completada con éxito!")
    finally:
        loader.close()

if __name__ == "__main__":
    main()