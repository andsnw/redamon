"""Technology identity integrity.

Technology data comes from several scanners and the same product can arrive
with different casing (for example ``Cloudflare`` and ``cloudflare``) or with a
missing version property versus the versionless sentinel ``''``. Neo4j's
composite uniqueness constraint is case-sensitive and does not protect tuples
containing null, so those representations can become parallel Technology
nodes.

The public ``graph_db.Neo4jClient`` runs this lightweight duplicate sweep before
closing. Only nodes with the same tenant, project, case-folded name and version
are merged. APOC's ``mergeNodes`` preserves all relationships.
"""


class TechnologyIntegrityMixin:
    """Keep Technology identity canonical across scanner-specific writers."""

    def normalize_technology_identity(self) -> int:
        with self.driver.session() as session:
            row = session.run(
                """
                MATCH (t:Technology)
                WHERE t.user_id IS NOT NULL
                  AND t.project_id IS NOT NULL
                  AND coalesce(trim(t.name), '') <> ''
                WITH t.user_id AS uid,
                     t.project_id AS pid,
                     toLower(trim(t.name)) AS name_key,
                     coalesce(t.version, '') AS version,
                     t,
                     size([(t)--() | 1]) AS degree
                ORDER BY uid, pid, name_key, version, degree DESC, t.name ASC
                WITH uid, pid, name_key, version, collect(t) AS nodes
                WHERE size(nodes) > 1
                CALL apoc.refactor.mergeNodes(
                    nodes,
                    {properties: 'discard', mergeRels: true, produceSelfRel: false}
                ) YIELD node
                SET node.version = version,
                    node.updated_at = datetime()
                RETURN count(node) AS merged_groups
                """
            ).single()
        return int((row or {}).get("merged_groups", 0) or 0)

    def close(self):
        try:
            merged = self.normalize_technology_identity()
            if merged:
                print(
                    f"[+][graph-db] merged {merged} duplicate Technology "
                    "identity group(s)"
                )
        finally:
            return super().close()
