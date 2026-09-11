"""Finding triage: AI verdicts, and the mute / unmute suppression state.

Two separate things live here, and keeping them separate is the point:

- A **verdict** (`triage_status` and friends) is the classifier's opinion. It
  ranks a finding and never hides it, and the AI can write nothing else.
- A **mute** is a human decision to suppress a finding as noise. It adds the
  `:Muted` label, which makes the node invisible to every agent query and every
  analytics, report and graph read.

Only a person mutes. `apply_triage_verdicts` cannot set `:Muted` no matter what
the model returns, so a prompt injection in scanner output (`raw_response`,
`evidence`) can at worst mislabel a verdict a human can overrule.

See `docs/readmes/GRAPH.SCHEMA.md` for the label's schema contract, and
`graph_db/tenant_filter.py` for how invisibility is enforced.
"""

#: Labels a finding can be muted on. Asset and reference nodes (IP, Port,
#: Domain, Endpoint, CVE, ...) are deliberately absent: they are context, and
#: muting one would orphan the real findings hanging off it.
#:
#: Used as a Cypher label expression, so a node id that belongs to anything else
#: matches nothing and the write is a no-op. That is the fail-closed direction:
#: a caller cannot mute an asset by guessing its id.
#:
#: Keep in sync with MUTEABLE in `webapp/src/lib/muteEnforcement.test.ts`.
MUTEABLE_LABELS = (
    "Vulnerability",
    "JsReconFinding",
    "Secret",
    "MultiscannerFinding",
    "GithubSecret",
    "GithubSensitiveFile",
    "MalPackageFinding",
    "ExploitGvm",
)

_MUTEABLE = "|".join(MUTEABLE_LABELS)

#: Findings are keyed on `id`, except MalPackageFinding, whose uniqueness
#: constraint is on `finding_id` (`graph_db/schema.py`). Matching either keeps
#: one call site for all eight labels.
#:
#: This is the stored `id` PROPERTY and never Neo4j's elementId: import and
#: version-activate do DETACH DELETE and recreate, so elementId changes under a
#: node that is otherwise the same finding.
_BY_ID = "(n.id = $node_id OR n.finding_id = $node_id)"

#: The functional label of a muted node. A muted finding is dual-labelled and
#: Neo4j does not order labels, so `labels(n)[0]` may be 'Muted' and would
#: mis-type the row. Everything reporting "what kind of finding is this" uses
#: this instead.
_FUNCTIONAL_LABEL = "[l IN labels(n) WHERE l <> 'Muted'][0]"

#: Worst-first ordering, so a capped list keeps the findings that matter. An
#: unknown or missing severity sorts last rather than being treated as critical.
_SEVERITY_RANK = """CASE toLower(coalesce(n.severity, ''))
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"""

#: Verdict + priority properties the triage phase owns. Listed once so the write
#: and the unmute cleanup cannot drift apart.
TRIAGE_PROPS = (
    "triage_status",
    "triage_confidence",
    "triage_reason",
    "triage_source",
    "triage_cluster_id",
    "triaged_at",
    # Prioritisation (deterministic scorer). triage_priority_score is THE sort
    # key: higher = more urgent. Deliberately no inverted "priority number".
    "triage_priority_score",
    "triage_signals",
    # Score model v3. The score is one number, but an operator who cannot see
    # WHY it ranked there has no way to disagree with it, so the whole
    # derivation is stored beside it.
    "triage_state",           # open | fixed | gone | inactive | false_positive
    "triage_tier",            # T1 | T2 | T3 | T4
    "triage_tier_rule",       # the rule that placed it in that tier
    "triage_factors",         # JSON: C, L, I, R with the evidence for each
    "triage_math_score",      # the score before any AI correction
    "triage_host",            # the host the model resolved, deterministically
    "triage_group_key",       # one problem, one fix (replaces triage_cluster_id)
    "triage_run_id",          # drives "new since the last triage"
    "triage_model_version",
    "triage_intel_date",
    # The AI review (Step C).
    "triage_ai_verdict",      # real | doubtful | false_positive | unclear | not_reviewed
    "triage_ai_corrections",  # JSON
    "triage_ai_quote",        # verified: a substring of the evidence we sent
    "triage_ai_model",
    "triage_ai_at",
    "triage_fix_lever",
    "triage_evidence_hash",   # the review cache key
    # X9: the chain findings that proved this, so the proof survives an
    # activation that drops the bridge edges but keeps the chain nodes.
    "triage_proof",
)

VALID_TRIAGE_STATUS = ("confirmed", "likely_noise", "needs_verification", "unreviewed")

#: What `triage_state` may hold. Anything else is refused rather than stored,
#: because the board's sections are driven by this and an unknown value would
#: silently drop a finding out of every section.
VALID_TRIAGE_STATE = ("open", "fixed", "gone", "inactive", "false_positive")

#: What the AI review may conclude.
VALID_AI_VERDICT = ("real", "doubtful", "false_positive", "unclear", "not_reviewed")

#: The board's four sections, in the order they are always shown.
SECTION_RANKED = 0
SECTION_NOT_TRIAGED = 1
SECTION_FALSE_POSITIVE = 2
SECTION_RESOLVED = 3


class TriageMixin:
    """Mute/unmute and AI-verdict writes for finding nodes."""

    def mute_finding(self, user_id: str, project_id: str, node_id: str,
                     muted_by: str = "", reason: str = "") -> dict:
        """Suppress one finding as noise.

        Adds `:Muted` ALONGSIDE the finding's own label rather than replacing it.
        That is what makes unmute lossless and what lets a re-scan keep the mute:
        recon re-runs `MERGE (v:Vulnerability {id, user_id, project_id})`, which
        still matches a `:Vulnerability:Muted` node, refreshes its scan
        properties and leaves the suppression intact. Relabelling would make that
        MERGE miss and create a second, un-muted duplicate.

        Idempotent: muting an already-muted finding refreshes nothing but the
        reason, and returns muted=True.

        Returns {"muted": bool, "label": str|None}. `muted=False` means nothing
        matched: a wrong id, another tenant's id, or an asset node, all of which
        are indistinguishable to the caller on purpose.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n:Muted,
            n.muted = true,
            n.muted_at = datetime(),
            n.muted_by = $muted_by,
            n.muted_reason = $reason
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query,
                node_id=node_id, user_id=user_id, project_id=project_id,
                muted_by=muted_by or user_id, reason=reason or "",
            ).single()

        if record is None:
            return {"muted": False, "label": None}
        return {"muted": True, "label": record["label"]}

    def unmute_finding(self, user_id: str, project_id: str, node_id: str) -> dict:
        """Restore a suppressed finding.

        Removes the label and the muted properties and touches nothing else, so
        the finding comes back with every relationship and scan property it had.
        Idempotent.

        Note this deliberately does NOT clear the triage verdict: unmuting is
        "show me this again", not "forget what we concluded about it".
        """
        query = f"""
        MATCH (n:Muted)
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        REMOVE n:Muted, n.muted, n.muted_at, n.muted_by, n.muted_reason
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id
            ).single()

        if record is None:
            return {"unmuted": False, "label": None}
        return {"unmuted": True, "label": record["label"]}

    def list_muted(self, user_id: str, project_id: str) -> list:
        """Every suppressed finding in the project.

        The ONLY query in the codebase that deliberately matches `:Muted`. It is
        reachable exclusively from the webapp's Muted-table endpoint over the
        internal API; the agent cannot reach it, and `scope_query` refuses any
        agent query that so much as names the label.
        """
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
        RETURN coalesce(n.id, n.finding_id)        AS id,
               {_FUNCTIONAL_LABEL}                 AS label,
               coalesce(n.name, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               toString(n.muted_at)                AS muted_at,
               coalesce(n.muted_by, '')            AS muted_by,
               coalesce(n.muted_reason, '')        AS muted_reason,
               coalesce(n.triage_status, 'unreviewed') AS triage_status,
               n.triage_reason                     AS triage_reason
        ORDER BY n.muted_at DESC
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(
                query, user_id=user_id, project_id=project_id)]

    def list_triage_findings(self, user_id: str, project_id: str, limit: int = 2000) -> list:
        """Every finding in triage scope that is NOT muted, for the Priority Board.

        THE ORDERING CONTRACT. The board has four sections, always in this order,
        and the server decides which one each finding is in so the client cannot
        disagree with it:

          0 Ranked            open, carries a triage_run_id, sorted by score
          1 Not triaged yet   open, never scored, sorted by severity
          2 Likely false pos  the AI or a human called it noise
          3 Resolved          fixed, gone or inactive

        Within a section the key is (score DESC, severity, id), with the id as a
        stable final tiebreak so two runs over an unchanged graph produce exactly
        the same order.

        A capped list keeps the top N, because the score is a near-total order;
        `count_triage_findings` gives the caller the real total so the table can
        say "showing N of M" rather than presenting a truncated list as the whole
        picture.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY|FOUND_AT|HAS_SECRET|HAS_FINDING]-(n)
        WITH n, head(collect(parent)) AS parent
        WITH n, parent,
             coalesce(n.triage_state, 'open') AS state,
             coalesce(n.triage_status, 'unreviewed') AS status
        WITH n, parent, state, status,
             CASE
               WHEN state IN ['fixed', 'gone', 'inactive'] THEN {SECTION_RESOLVED}
               WHEN state = 'false_positive' OR status = 'likely_noise'
                 THEN {SECTION_FALSE_POSITIVE}
               WHEN coalesce(n.triage_run_id, '') = '' THEN {SECTION_NOT_TRIAGED}
               ELSE {SECTION_RANKED}
             END AS section
        RETURN coalesce(n.id, n.finding_id)        AS id,
               // NOT labels(n)[0]: a muted finding is dual-labelled and Neo4j
               // does not order labels, so that could return 'Muted' and
               // mis-type the row (X14).
               {_FUNCTIONAL_LABEL}                 AS label,
               coalesce(n.name, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               coalesce(n.matched_at, n.url, n.endpoint, '') AS location,
               // The host the model actually used, not a non-deterministic pick
               // from whichever parent Neo4j returned first (R5).
               coalesce(n.triage_host, parent.name, parent.address, parent.url, '') AS host,
               section                             AS section,
               state                               AS triage_state,
               status                              AS triage_status,
               n.triage_confidence                 AS triage_confidence,
               n.triage_reason                     AS triage_reason,
               coalesce(n.triage_source, '')       AS triage_source,
               coalesce(n.triage_tier, '')         AS triage_tier,
               coalesce(n.triage_tier_rule, '')    AS triage_tier_rule,
               n.triage_factors                    AS triage_factors,
               n.triage_math_score                 AS triage_math_score,
               n.triage_priority_score             AS triage_priority_score,
               coalesce(n.triage_signals, [])      AS triage_signals,
               coalesce(n.triage_group_key, n.triage_cluster_id, '') AS triage_group_key,
               coalesce(n.triage_run_id, '')       AS triage_run_id,
               coalesce(n.triage_ai_verdict, '')   AS triage_ai_verdict,
               n.triage_ai_corrections             AS triage_ai_corrections,
               n.triage_ai_quote                   AS triage_ai_quote,
               coalesce(n.triage_ai_model, '')     AS triage_ai_model,
               toString(n.triage_ai_at)            AS triage_ai_at,
               coalesce(n.triage_fix_lever, '')    AS triage_fix_lever,
               n.triage_proof                      AS triage_proof,
               toString(n.triaged_at)              AS triaged_at,
               toString(n.updated_at)              AS updated_at
        ORDER BY section,
                 coalesce(n.triage_priority_score, -1) DESC,
                 {_SEVERITY_RANK},
                 coalesce(n.id, n.finding_id)
        LIMIT $limit
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(
                query, user_id=user_id, project_id=project_id, limit=limit)]

    def count_triage_findings(self, user_id: str, project_id: str) -> int:
        """How many findings are in triage scope, ignoring the display cap.

        The Triage table is capped, so this is what lets the UI say "showing N
        of M" instead of presenting a truncated list as the whole picture.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        RETURN count(n) AS total
        """
        with self.driver.session() as session:
            record = session.run(
                query, user_id=user_id, project_id=project_id).single()
        return int(record["total"]) if record else 0

    def apply_triage_verdicts(self, user_id: str, project_id: str, verdicts: list) -> dict:
        """Write AI verdicts onto findings.

        `verdicts` is a list of {id, triage_status, triage_confidence,
        triage_reason, triage_cluster_id}.

        Two guarantees this method is responsible for, both enforced in Cypher
        rather than trusted to the caller:

        1. **A human verdict is never overwritten.** `triage_source = 'human'`
           means someone already decided; a re-run must leave it alone, or the
           operator's judgement silently evaporates on the next triage.
        2. **The classifier cannot mute.** There is no `SET n:Muted` here and
           there must never be one. Scanner output reaches the classify prompt,
           so a model that has been talked into saying "hide me" can at worst
           write a verdict a human can see and overrule.

        Unknown statuses are dropped rather than written, so a malformed model
        response cannot invent a state the UI has no meaning for.
        """
        clean = []
        for v in verdicts or []:
            node_id = (v or {}).get("id")
            status = (v or {}).get("triage_status")
            if not node_id or status not in VALID_TRIAGE_STATUS:
                continue
            confidence = v.get("triage_confidence")
            try:
                confidence = max(0.0, min(1.0, float(confidence)))
            except (TypeError, ValueError):
                confidence = None
            clean.append({
                "id": str(node_id),
                "status": status,
                "confidence": confidence,
                "reason": str(v.get("triage_reason") or "")[:500],
                "cluster_id": str(v.get("triage_cluster_id") or "") or None,
            })

        if not clean:
            return {"updated": 0, "skipped_human": 0, "rejected": len(verdicts or [])}

        query = f"""
        UNWIND $verdicts AS verdict
        MATCH (n:{_MUTEABLE})
        WHERE (n.id = verdict.id OR n.finding_id = verdict.id)
          AND n.user_id = $user_id AND n.project_id = $project_id
        WITH n, verdict, n.triage_source = 'human' AS isHuman
        FOREACH (_ IN CASE WHEN isHuman THEN [] ELSE [1] END |
          SET n.triage_status     = verdict.status,
              n.triage_confidence = verdict.confidence,
              n.triage_reason     = verdict.reason,
              n.triage_cluster_id = verdict.cluster_id,
              n.triage_source     = 'ai',
              n.triaged_at        = datetime()
        )
        RETURN count(CASE WHEN isHuman THEN 1 END) AS skipped_human,
               count(CASE WHEN isHuman THEN NULL ELSE 1 END) AS updated
        """
        with self.driver.session() as session:
            record = session.run(
                query, verdicts=clean, user_id=user_id, project_id=project_id
            ).single()

        return {
            "updated": (record["updated"] if record else 0) or 0,
            "skipped_human": (record["skipped_human"] if record else 0) or 0,
            "rejected": len(verdicts or []) - len(clean),
        }

    def apply_triage_scores(self, user_id: str, project_id: str, rows: list,
                            guard_updated_at: bool = True) -> dict:
        """Publish a triage run's results onto the findings. Step E, and the
        only step that writes.

        `rows` carry the whole derivation, not just a number: state, the four
        factors with the evidence behind each, the tier and the rule that chose
        it, the resolved host, the group key, the run id, and the AI's verdict
        where one was produced. An operator who cannot see why a finding ranked
        where it did has no way to disagree with it.

        Three rules are enforced HERE, in Cypher, rather than trusted to the
        caller:

        1. **A human's verdict is theirs.** Facts, factors and the score always
           update, because those are measurements and staleness helps nobody.
           `triage_status`, `triage_reason` and `triage_confidence` on a
           human-owned finding are never touched, and `triage_source` stays
           'human' (C14).
        2. **Nothing is muted here.** There is no `SET n:Muted` in this method
           and there never must be: a run produces verdicts, and only a person
           suppresses a finding.
        3. **A node a scan changed mid-run is skipped.** Steps A to D read the
           graph minutes before this writes. If a scanner re-ingested a finding
           in between, its facts are no longer the ones that were scored, so the
           row is left alone and counted as `skipped_changed`; the next run
           picks it up. Triage never sets `updated_at` itself (only
           `triaged_at`), so this compares against scanner writes only.

        Returns counts, never finding text.
        """
        clean = []
        for r in rows or []:
            node_id = (r or {}).get("id")
            if not node_id:
                continue
            clean.append(self._clean_publish_row(r))

        if not clean:
            return {"updated": 0, "skipped_human": 0, "skipped_changed": 0,
                    "rejected": len(rows or [])}

        # `seen_updated_at` is the node's updated_at as Step A read it. A row
        # that never carried one (a caller that does not track it) opts out of
        # the guard rather than being skipped for ever.
        query = f"""
        UNWIND $rows AS row
        MATCH (n:{_MUTEABLE})
        WHERE (n.id = row.id OR n.finding_id = row.id)
          AND n.user_id = $user_id AND n.project_id = $project_id
        WITH n, row,
             n.triage_source = 'human' AS isHuman,
             (NOT $guard
              OR row.seen_updated_at IS NULL
              OR toString(n.updated_at) = row.seen_updated_at) AS unchanged
        FOREACH (_ IN CASE WHEN unchanged THEN [1] ELSE [] END |
          // Measurements: always written, human-owned or not (C14).
          SET n.triage_priority_score = row.score,
              n.triage_math_score     = row.math_score,
              n.triage_signals        = row.signals,
              n.triage_state          = row.state,
              n.triage_tier           = row.tier,
              n.triage_tier_rule      = row.tier_rule,
              n.triage_factors        = row.factors,
              n.triage_host           = row.host,
              n.triage_group_key      = row.group_key,
              n.triage_run_id         = row.run_id,
              n.triage_model_version  = row.model_version,
              n.triaged_at            = datetime()
        )
        FOREACH (_ IN CASE WHEN unchanged AND row.proof IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_proof = row.proof)
        FOREACH (_ IN CASE WHEN unchanged AND row.intel_date IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_intel_date = row.intel_date)
        FOREACH (_ IN CASE WHEN unchanged AND row.evidence_hash IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_evidence_hash = row.evidence_hash)
        FOREACH (_ IN CASE WHEN unchanged AND row.fix_lever IS NOT NULL THEN [1] ELSE [] END |
          SET n.triage_fix_lever = row.fix_lever)
        // The AI review and the verdict it implies: never over a human.
        FOREACH (_ IN CASE WHEN unchanged AND NOT isHuman AND row.ai_verdict IS NOT NULL
                           THEN [1] ELSE [] END |
          SET n.triage_ai_verdict     = row.ai_verdict,
              n.triage_ai_corrections = row.ai_corrections,
              n.triage_ai_quote       = row.ai_quote,
              n.triage_ai_model       = row.ai_model,
              n.triage_ai_at          = datetime()
        )
        FOREACH (_ IN CASE WHEN unchanged AND NOT isHuman AND row.status IS NOT NULL
                           THEN [1] ELSE [] END |
          SET n.triage_status     = row.status,
              n.triage_confidence = row.confidence,
              n.triage_source     = 'ai'
        )
        FOREACH (_ IN CASE WHEN unchanged AND NOT isHuman AND row.reason IS NOT NULL
                           THEN [1] ELSE [] END |
          SET n.triage_reason = row.reason)
        RETURN count(CASE WHEN NOT unchanged THEN 1 END) AS skipped_changed,
               count(CASE WHEN unchanged AND isHuman THEN 1 END) AS skipped_human,
               count(CASE WHEN unchanged THEN 1 END) AS updated
        """
        with self.driver.session() as session:
            record = session.run(
                query, rows=clean, user_id=user_id, project_id=project_id,
                guard=bool(guard_updated_at),
            ).single()

        return {
            "updated": (record["updated"] if record else 0) or 0,
            "skipped_human": (record["skipped_human"] if record else 0) or 0,
            "skipped_changed": (record["skipped_changed"] if record else 0) or 0,
            "rejected": len(rows or []) - len(clean),
        }

    @staticmethod
    def _clean_publish_row(r: dict) -> dict:
        """Coerce one publish row, refusing anything outside its enum.

        Everything here either came from the pure score model or passed the
        review's quote check, but this is the last gate before the graph, so an
        out-of-range number or an invented state is dropped rather than stored.
        """
        import json as _json

        def _float(value, default=0.0):
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        def _text(value, cap):
            text = str(value or "").strip()
            return text[:cap] or None

        def _json_text(value, cap=8000):
            if value is None:
                return None
            if isinstance(value, str):
                return value[:cap]
            try:
                return _json.dumps(value, default=str)[:cap]
            except (TypeError, ValueError):
                return None

        status = r.get("status")
        if status not in VALID_TRIAGE_STATUS:
            status = None
        confidence = r.get("confidence")
        try:
            confidence = None if confidence is None else max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = None

        state = r.get("state")
        if state not in VALID_TRIAGE_STATE:
            state = "open"
        tier = r.get("tier") if r.get("tier") in ("T1", "T2", "T3", "T4") else "T4"
        ai_verdict = r.get("ai_verdict")
        if ai_verdict not in VALID_AI_VERDICT:
            ai_verdict = None

        signals = r.get("signals") or []
        if not isinstance(signals, list):
            signals = [str(signals)]

        return {
            "id": str(r.get("id")),
            "score": max(0.0, min(100.0, _float(r.get("score")))),
            "math_score": max(0.0, min(100.0, _float(r.get("math_score", r.get("score"))))),
            "signals": [str(x)[:120] for x in signals][:30],
            "state": state,
            "tier": tier,
            "tier_rule": _text(r.get("tier_rule"), 200) or "",
            "factors": _json_text(r.get("factors")) or "{}",
            "host": _text(r.get("host"), 300) or "",
            "group_key": _text(r.get("group_key"), 200) or "",
            "run_id": _text(r.get("run_id"), 60) or "",
            "model_version": _text(r.get("model_version"), 40) or "",
            "intel_date": _text(r.get("intel_date"), 40),
            "proof": _json_text(r.get("proof"), 4000),
            "evidence_hash": _text(r.get("evidence_hash"), 80),
            "fix_lever": _text(r.get("fix_lever"), 120),
            "status": status,
            "confidence": confidence,
            "reason": _text(r.get("reason"), 500),
            "ai_verdict": ai_verdict,
            "ai_corrections": _json_text(r.get("ai_corrections"), 4000),
            "ai_quote": _text(r.get("ai_quote"), 1000),
            "ai_model": _text(r.get("ai_model"), 120) or "",
            "seen_updated_at": _text(r.get("seen_updated_at"), 60),
        }

    def set_human_verdict(self, user_id: str, project_id: str, node_id: str,
                          status: str, reason: str = "") -> dict:
        """Record an operator's own verdict, which the AI may not later overwrite.

        Stamping `triage_source = 'human'` is what makes the skip in
        `apply_triage_verdicts` fire on the next run.
        """
        if status not in VALID_TRIAGE_STATUS:
            return {"updated": False, "reason": f"invalid status {status!r}"}

        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n.triage_status = $status,
            n.triage_reason = $reason,
            n.triage_source = 'human',
            n.triage_confidence = 1.0,
            n.triaged_at = datetime()
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id,
                status=status, reason=str(reason or "")[:500],
            ).single()

        return {"updated": record is not None,
                "label": record["label"] if record else None}
