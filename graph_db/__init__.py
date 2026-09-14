from .mixins.technology_integrity_mixin import TechnologyIntegrityMixin
from . import neo4j_client as _neo4j_client_module


_Neo4jClient = _neo4j_client_module.Neo4jClient


class Neo4jClient(TechnologyIntegrityMixin, _Neo4jClient):
    """Public graph client with cross-scanner Technology identity integrity."""


# A number of existing callers import directly from ``graph_db.neo4j_client``
# instead of the package root. Rebind the submodule export after the base client
# has loaded so both import styles resolve to the same integrity-enabled class.
# Importing any submodule executes this package ``__init__`` first, so callers
# cannot bypass the wrapper simply by using the legacy direct-import path.
_neo4j_client_module.Neo4jClient = Neo4jClient


__all__ = ["Neo4jClient"]
