from .mixins.technology_integrity_mixin import TechnologyIntegrityMixin
from .neo4j_client import Neo4jClient as _Neo4jClient


class Neo4jClient(TechnologyIntegrityMixin, _Neo4jClient):
    """Public graph client with cross-scanner Technology identity integrity."""


__all__ = ["Neo4jClient"]
