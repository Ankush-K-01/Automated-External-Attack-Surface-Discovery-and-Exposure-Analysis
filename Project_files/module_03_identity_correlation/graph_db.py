"""Neo4j connection is environment-configured; graph loads use MERGE only."""
import os
from neo4j import GraphDatabase
def driver(): return GraphDatabase.driver(os.environ["NEO4J_URI"],auth=(os.environ["NEO4J_USER"],os.environ["NEO4J_PASSWORD"]))
