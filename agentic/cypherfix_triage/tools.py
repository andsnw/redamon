"""Tools available to the triage agent during ReAct analysis phase."""

import logging
import os

from neo4j import READ_ACCESS, AsyncGraphDatabase

from graph_db.tenant_filter import (
    TenantScopeError,
    find_disallowed_write_operation,
    scope_query,
)
from prompt_safety import wrap_untrusted

logger = logging.getLogger(__name__)

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "redamon_neo4j")


class TriageNeo4jToolManager:
    """Manages Neo4j connections and query execution for triage agent."""

    def __init__(self, user_id: str, project_id: str):
        self.user_id = user_id
        self.project_id = project_id
        self.driver = None

    async def connect(self):
        self.driver = AsyncGraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
        )

    async def close(self):
        if self.driver:
            await self.driver.close()

    async def _execute(self, cypher: str, params: dict) -> list[dict]:
        """Run already-vetted Cypher in a read session.

        Read access mode is belt-and-braces: the write clauses are refused
        before we get here, and a read session makes a missed one fail at the
        server instead of mutating the graph.
        """
        if not self.driver:
            await self.connect()

        async with self.driver.session(default_access_mode=READ_ACCESS) as session:
            result = await session.run(cypher, params)
            return await result.data()

    async def run_query(self, cypher: str, params: dict = None) -> list[dict]:
        """Run LLM-written Cypher, refusing anything that cannot be proven scoped.

        This is the only path the model can reach. It mirrors the main agent's
        `query_graph` chokepoint (`agentic/tools.py`): refuse writes, then
        `scope_query`, which injects the tenant filter, rejects the reserved
        `Muted` label and raises rather than running an unscopable pattern.
        """
        disallowed = find_disallowed_write_operation(cypher)
        if disallowed:
            raise TenantScopeError(
                f"Write operations are not allowed in triage queries "
                f"(found: {disallowed.strip()})"
            )

        scoped = scope_query(cypher, self.user_id, self.project_id)

        query_params = {
            "userId": self.user_id,
            "projectId": self.project_id,
            "tenant_user_id": self.user_id,
            "tenant_project_id": self.project_id,
            **(params or {}),
        }
        return await self._execute(scoped, query_params)

    async def run_static_query(self, cypher: str) -> list[dict]:
        """Run a repo-authored collection query (already carries $userId/$projectId).

        Deliberately separate from `run_query`: these queries are written in
        `prompts/cypher_queries.py`, hand-write their own `NOT x:Muted` terms and
        would not survive `scope_query`'s label requirement. Nothing the model
        emits may reach this method.
        """
        return await self._execute(
            cypher, {"userId": self.user_id, "projectId": self.project_id}
        )

class TriageWebSearchManager:
    """Web search tool for enriching triage analysis."""

    def __init__(self, tavily_api_key: str = "", key_rotator=None):
        self.tavily_api_key = tavily_api_key or ""
        self.key_rotator = key_rotator  # Optional[KeyRotator]

    async def search(self, query: str, max_results: int = 5) -> str:
        """Search the web using Tavily API."""
        api_key = self.key_rotator.current_key if self.key_rotator and self.key_rotator.has_keys else self.tavily_api_key
        if not api_key:
            return "Web search unavailable: Tavily API key not configured in Global Settings"

        try:
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "max_results": max_results,
                        "search_depth": "basic",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                if self.key_rotator:
                    self.key_rotator.tick()

                results = []
                for r in data.get("results", []):
                    results.append(
                        f"**{r['title']}**\n{r['url']}\n{r.get('content', '')[:500]}"
                    )
                if not results:
                    return "No results found."
                return wrap_untrusted("\n\n---\n\n".join(results), "WEB_SEARCH_RESULTS")
        except Exception as e:
            logger.error(f"Web search failed: {e}")
            return f"Web search error: {e}"


# Tool definitions for the LLM
TRIAGE_TOOLS = [
    {
        "name": "query_graph",
        "description": (
            "Run a read-only follow-up Cypher query against the Neo4j graph database. "
            "Use this when you need additional context about specific findings. "
            "Tenant filters are injected for you, but every node pattern must name "
            "an explicit label, e.g. MATCH (v:Vulnerability), never MATCH (n). "
            "Write clauses are refused."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cypher": {
                    "type": "string",
                    "description": "Read-only Cypher query. Every node pattern needs an explicit label.",
                },
            },
            "required": ["cypher"],
        },
    },
    {
        "name": "web_search",
        "description": (
            "Search the web for vulnerability details, CVE information, "
            "CISA KEV catalog status, or exploit availability."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query",
                },
            },
            "required": ["query"],
        },
    },
]
