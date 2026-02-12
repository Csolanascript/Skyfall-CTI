# 🦅 SKYFALL CTI
### **Proactive Threat Intelligence & Narrative Analysis Ecosystem**

**Skyfall CTI** is an event-driven platform bridging technical vulnerabilities and geopolitical analysis. It fuses NVD data with Telegram/Grok OSINT via STIX 2.1. Using Kafka, Neo4j, and Elasticsearch, it enables proactive defense via AI-assisted graph intelligence.

---

## 🚀 Key Features

* **Multi-Vector Ingestion**: Automated pipelines for technical vulnerabilities (NVD/CISA) and social OSINT (Telegram/Grok).
* **Event-Driven Backbone**: High-performance data streaming powered by **Apache Kafka** to decouple ingestion from analysis.
* **Hybrid Persistence**: Dual-engine storage utilizing **Neo4j** for relational Knowledge Graphs and **Elasticsearch** for massive full-text search.
* **AI Context Layer**: A **Model Context Protocol (MCP)** server built with FastAPI that enables LLMs to perform RAG-based queries over the threat graph.
* **Standardized Intelligence**: Native implementation of **STIX 2.1** to ensure interoperability and structured relationship mapping.

---

## 🏗️ Architecture

The system follows a tiered microservices approach deployed via Docker:

1.  **Ingestion Layer**: Hybrid orchestration using **n8n** for API-based sources and **Python (Telethon)** for persistent social monitoring.
2.  **Message Broker**: **Apache Kafka** manages asynchronous data topics, ensuring resilience and scalability.
3.  **Intelligence Engine**: Python-based consumers transform raw data into STIX 2.1 objects before persisting them into the hybrid data store.
4.  **Access Layer**: A **React** frontend for graph visualization and an **MCP Server** for natural language interrogation.



---

## 🛠️ Tech Stack

| Layer | Component | Technology |
| :--- | :--- | :--- |
| **Infrastructure** | Orchestration | Docker Compose |
| **Ingestion** | Producers | n8n & Python (Telethon) |
| **Broker** | Bus de Datos | Apache Kafka |
| **Enrichment** | Analysis | Intel-Owl & KEVin-API |
| **Persistence** | Data Engines | Neo4j & Elasticsearch |
| **IA/Access** | AI Interface | FastAPI & MCP Protocol |

---

## 🚦 Getting Started

### Prerequisites
* Docker & Docker Compose
* Minimum 16GB RAM (Recommended)

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/your-user/skyfall-cti.git](https://github.com/your-user/skyfall-cti.git)
   cd skyfall-cti
