from neo4j import GraphDatabase

class SkyfallNeo4jIngestor:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_bundle(self, bundle_dict: Dict[str, Any]):
        """Inserta un bundle STIX directamente en Neo4j."""
        objects = bundle_dict.get("objects", [])
        
        # 1. Separar Nodos de Relaciones
        nodes = [o for o in objects if o["type"] != "relationship"]
        rels = [o for o in objects if o["type"] == "relationship"]

        with self.driver.session() as session:
            # 2. Ingestar Nodos
            session.execute_write(self._ingest_nodes_tx, nodes)
            # 3. Ingestar Relaciones
            session.execute_write(self._ingest_rels_tx, rels)
        
        print(f"[✓] Ingestados {len(nodes)} nodos y {len(rels)} relaciones en Neo4j.")

    @staticmethod
    def _ingest_nodes_tx(tx, nodes):
        for node in nodes:
            # Limpiar propiedades para Neo4j (aplanar listas/dicts si es necesario)
            props = {k: (json.dumps(v) if isinstance(v, (list, dict)) else v) 
                    for k, v in node.items() if v is not None}
            
            # Etiqueta dinámica basada en el tipo: attack-pattern -> AttackPattern
            label = node["type"].replace("-", "").capitalize()
            
            query = f"""
            MERGE (n:StixObject {{id: $props.id}})
            SET n += $props
            SET n:{label}
            """
            tx.run(query, props=props)

    @staticmethod
    def _ingest_rels_tx(tx, rels):
        for rel in rels:
            # Tipo de relación en MAYÚSCULAS: based-on -> BASED_ON
            rel_type = rel["relationship_type"].upper().replace("-", "_")
            
            query = f"""
            MATCH (src:StixObject {{id: $source_ref}})
            MATCH (tgt:StixObject {{id: $target_ref}})
            MERGE (src)-[r:{rel_type}]->(tgt)
            SET r.id = $id
            """
            tx.run(query, **rel)