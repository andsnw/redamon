from graph_db.mixins.technology_integrity_mixin import TechnologyIntegrityMixin


class _Result:
    def single(self):
        return {"merged_groups": 2}


class _Session:
    def __init__(self):
        self.query = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, query, **params):
        self.query = query
        return _Result()


class _Driver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class _Client(TechnologyIntegrityMixin):
    def __init__(self, session):
        self.driver = _Driver(session)


def test_technology_identity_groups_case_insensitively_and_coalesces_version():
    session = _Session()
    merged = _Client(session).normalize_technology_identity()

    assert merged == 2
    assert "toLower(trim(t.name)) AS name_key" in session.query
    assert "coalesce(t.version, '') AS version" in session.query
    assert "t.user_id AS uid" in session.query
    assert "t.project_id AS pid" in session.query


def test_technology_merge_preserves_relationships():
    session = _Session()
    _Client(session).normalize_technology_identity()

    assert "apoc.refactor.mergeNodes" in session.query
    assert "mergeRels: true" in session.query
    assert "produceSelfRel: false" in session.query
    assert "SET node.version = version" in session.query


def test_package_and_direct_client_imports_share_integrity_wrapper():
    from graph_db import Neo4jClient as package_client
    from graph_db.neo4j_client import Neo4jClient as direct_client

    assert direct_client is package_client
    assert issubclass(direct_client, TechnologyIntegrityMixin)


def test_close_does_not_return_from_finally():
    import inspect

    source = inspect.getsource(TechnologyIntegrityMixin.close)
    assert "finally:" in source
    assert "super().close()" in source
    assert "return super().close()" not in source
