"""
conflict_rules.py — Data-driven cross-agent conflict resolution for the
Orchestrator Agent (Nura, multi-account edition).

Design boundary this file enforces:
    Conflict detection and resolution are DETERMINISTIC. No model call is made
    anywhere in this module. Rules key on the structured `recommended_action`
    field carried by each finding, never on agent co-occurrence.

    Pairs that cannot be resolved by rule are emitted with
    kind == KIND_ADJUDICATE and are handed to the model for contextual
    judgment. Those are the only cases the model sees.

Prerequisite on the producing agents:
    Every finding written to the findings table MUST carry:
        recommended_action   one value from ACTIONS (below)
        resource_id          the ARN or stable resource identifier
        account_id           the owning account
        severity             CRITICAL | HIGH | MEDIUM | LOW
        remediation_status   open | in_progress | resolved | suppressed
    Findings missing `recommended_action` are skipped by the resolver and
    counted in `skipped_unclassified` so the gap is visible, not silent.
"""

from itertools import combinations


# ─────────────────────────────────────────────────────────────────────────────
# 1. Action vocabulary
# ─────────────────────────────────────────────────────────────────────────────

# Destructive — removes the resource or its data
TERMINATE        = "TERMINATE"
DELETE           = "DELETE"
DELETE_SNAPSHOT  = "DELETE_SNAPSHOT"
STOP             = "STOP"

# Forensic hold — the resource must not be altered
PRESERVE         = "PRESERVE"
QUARANTINE       = "QUARANTINE"
ISOLATE          = "ISOLATE"
ACTIVE_INVESTIGATION = "ACTIVE_INVESTIGATION"

# Resilience
REMOVE_REDUNDANCY  = "REMOVE_REDUNDANCY"     # drop Multi-AZ, drop replica
ENFORCE_REDUNDANCY = "ENFORCE_REDUNDANCY"
REDUCE_RETENTION   = "REDUCE_RETENTION"
RETENTION_FLOOR    = "RETENTION_FLOOR"
BACKUP_IN_FLIGHT   = "BACKUP_IN_FLIGHT"
RESTORE_IN_FLIGHT  = "RESTORE_IN_FLIGHT"
DR_TEST_WINDOW     = "DR_TEST_WINDOW"
CROSS_REGION_REPLICA = "CROSS_REGION_REPLICA"

# Capacity
DOWNSIZE       = "DOWNSIZE"
SCHEDULE_OFF   = "SCHEDULE_OFF"
SCALE_UP       = "SCALE_UP"
SCALE_OUT      = "SCALE_OUT"

# Network
OPEN_PATH      = "OPEN_PATH"
CLOSE_PATH     = "CLOSE_PATH"

# Identity
GRANT          = "GRANT"
REVOKE         = "REVOKE"
BREAK_GLASS_USED = "BREAK_GLASS_USED"

# Disruptive remediation — requires a restart or rekey
ROTATE_KEY     = "ROTATE_KEY"
PATCH_REBOOT   = "PATCH_REBOOT"
REPLACE        = "REPLACE"

# Compliance constraints
DATA_RESIDENCY = "DATA_RESIDENCY"
ENCRYPT_CMK    = "ENCRYPT_CMK"

# Signals (not actions, but they participate in pairs)
SPEND_SPIKE    = "SPEND_SPIKE"
APPROVED_CHANGE = "APPROVED_CHANGE"
MONITOR        = "MONITOR"
NO_ACTION      = "NO_ACTION"

ACTIONS = {
    TERMINATE, DELETE, DELETE_SNAPSHOT, STOP,
    PRESERVE, QUARANTINE, ISOLATE, ACTIVE_INVESTIGATION,
    REMOVE_REDUNDANCY, ENFORCE_REDUNDANCY, REDUCE_RETENTION, RETENTION_FLOOR,
    BACKUP_IN_FLIGHT, RESTORE_IN_FLIGHT, DR_TEST_WINDOW, CROSS_REGION_REPLICA,
    DOWNSIZE, SCHEDULE_OFF, SCALE_UP, SCALE_OUT,
    OPEN_PATH, CLOSE_PATH,
    GRANT, REVOKE, BREAK_GLASS_USED,
    ROTATE_KEY, PATCH_REBOOT, REPLACE,
    DATA_RESIDENCY, ENCRYPT_CMK,
    SPEND_SPIKE, APPROVED_CHANGE, MONITOR, NO_ACTION,
}

# Action classes — rules match on these, not on individual actions
DESTRUCTIVE        = frozenset({TERMINATE, DELETE, DELETE_SNAPSHOT, STOP})
FORENSIC_HOLD      = frozenset({PRESERVE, QUARANTINE, ISOLATE, ACTIVE_INVESTIGATION})
RESILIENCE_DOWN    = frozenset({REMOVE_REDUNDANCY, REDUCE_RETENTION})
RESILIENCE_UP      = frozenset({ENFORCE_REDUNDANCY, RETENTION_FLOOR})
JOB_IN_FLIGHT      = frozenset({BACKUP_IN_FLIGHT, RESTORE_IN_FLIGHT, DR_TEST_WINDOW})
CAPACITY_DOWN      = frozenset({DOWNSIZE, SCHEDULE_OFF})
CAPACITY_UP        = frozenset({SCALE_UP, SCALE_OUT})
DISRUPTIVE         = frozenset({ROTATE_KEY, PATCH_REBOOT, REPLACE})
WRITE_ACTIONS      = (DESTRUCTIVE | RESILIENCE_DOWN | RESILIENCE_UP | CAPACITY_DOWN
                      | CAPACITY_UP | DISRUPTIVE
                      | frozenset({OPEN_PATH, CLOSE_PATH, GRANT, REVOKE, ENCRYPT_CMK}))


# ─────────────────────────────────────────────────────────────────────────────
# 2. Precedence lattice
# ─────────────────────────────────────────────────────────────────────────────
# Lower index wins. Used as the fallback resolver for action pairs that are
# incompatible but not covered by an explicit rule.

FORENSIC     = "forensic"
REGULATORY   = "regulatory"
SECURITY     = "security"
RESILIENCE   = "resilience"
AVAILABILITY = "availability"
COST         = "cost"

PRECEDENCE = [FORENSIC, REGULATORY, SECURITY, RESILIENCE, AVAILABILITY, COST]

DOMAIN_BY_AGENT = {
    "incident-agent":          AVAILABILITY,   # promoted to FORENSIC when holding
    "compliance-agent":        REGULATORY,
    "security-agent":          SECURITY,
    "network-security-agent":  SECURITY,
    "access-analyzer-agent":   SECURITY,
    "backup-dr-agent":         RESILIENCE,
    "infra-agent":             AVAILABILITY,
    "cost-agent":              COST,
    "cost-anomaly-agent":      COST,
}


def domain_of(finding):
    """Domain tier for a finding. A finding asserting a forensic hold is
    promoted to the top tier regardless of which agent raised it."""
    if finding.get("recommended_action") in FORENSIC_HOLD:
        return FORENSIC
    return DOMAIN_BY_AGENT.get(finding.get("agent", ""), AVAILABILITY)


def precedence_rank(finding):
    try:
        return PRECEDENCE.index(domain_of(finding))
    except ValueError:
        return len(PRECEDENCE)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Outcome kinds
# ─────────────────────────────────────────────────────────────────────────────

KIND_CONFLICT   = "conflict"     # real disagreement; one side defers
KIND_SUPPRESS   = "suppression"  # finding A is explained by finding B; not a problem
KIND_SERIALIZE  = "serialize"    # both valid, must not run concurrently
KIND_ADJUDICATE = "adjudicate"   # rule cannot decide — hand to the model


# ─────────────────────────────────────────────────────────────────────────────
# 4. Rule table
# ─────────────────────────────────────────────────────────────────────────────
# Each rule is matched against an unordered pair of findings on the same
# (account_id, resource_id). `a` and `b` describe the two sides; the engine
# tries both orientations. `agents` of None means "any agent".
#
#   winner       which side prevails ("a" | "b" | None)
#   defer_until  machine-readable re-evaluation trigger for the losing side

RULES = [
    {
        "id": "CFL-001",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"cost-agent", "cost-anomaly-agent", "infra-agent"}, "actions": DESTRUCTIVE},
        "b": {"agents": {"incident-agent"}, "actions": FORENSIC_HOLD},
        "winner": "b",
        "severity": "HIGH",
        "defer_until": "incident_closed",
        "title": "Destructive action on a resource under active incident investigation",
        "resolution": "Block the destructive action. Re-evaluate when the incident is closed.",
    },
    {
        "id": "CFL-002",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"cost-agent", "cost-anomaly-agent", "infra-agent"}, "actions": DESTRUCTIVE},
        "b": {"agents": {"security-agent"}, "actions": FORENSIC_HOLD},
        "winner": "b",
        "severity": "CRITICAL",
        "defer_until": "security_finding_resolved",
        "title": "Destructive action on a quarantined or compromised resource",
        "resolution": "Block the destructive action. Evidence must be preserved until the security finding is resolved.",
    },
    {
        "id": "CFL-003",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"cost-agent"}, "actions": DESTRUCTIVE | RESILIENCE_DOWN},
        "b": {"agents": {"compliance-agent"}, "actions": frozenset({RETENTION_FLOOR})},
        "winner": "b",
        "severity": "HIGH",
        "defer_until": "retention_floor_relaxed",
        "title": "Cost action would breach a compliance retention floor",
        "resolution": "Pin retention to the compliance floor. Recalculate the cost saving above that floor.",
    },
    {
        "id": "CFL-004",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"cost-agent"}, "actions": RESILIENCE_DOWN},
        "b": {"agents": {"backup-dr-agent"}, "actions": RESILIENCE_UP},
        "winner": "b",
        "severity": "HIGH",
        "defer_until": "rpo_rto_formally_relaxed",
        "title": "Cost action would breach a stated RPO/RTO obligation",
        "resolution": "Void the cost recommendation unless the RPO/RTO target is formally relaxed by the service owner.",
    },
    {
        "id": "CFL-005",
        "kind": KIND_ADJUDICATE,
        "a": {"agents": {"cost-agent"}, "actions": CAPACITY_DOWN},
        "b": {"agents": {"infra-agent"}, "actions": CAPACITY_UP},
        "winner": None,
        "severity": "MEDIUM",
        "defer_until": None,
        "title": "Cost recommends reducing capacity while Infrastructure recommends increasing it",
        "resolution": "Model adjudication required: compare utilisation history, workload pattern and the time windows of both signals. Escalate with both recommendations and the reasoning; do not auto-resolve.",
    },
    {
        "id": "CFL-006",
        "kind": KIND_SUPPRESS,
        "a": {"agents": {"cost-anomaly-agent"}, "actions": frozenset({SPEND_SPIKE})},
        "b": {"agents": {"incident-agent"}, "actions": FORENSIC_HOLD},
        "winner": "b",
        "severity": "LOW",
        "defer_until": "incident_closed",
        "title": "Spend spike explained by active incident response",
        "resolution": "Suppress the anomaly for the incident window. Link the explaining finding and retain both records.",
    },
    {
        "id": "CFL-007",
        "kind": KIND_SUPPRESS,
        "a": {"agents": {"cost-anomaly-agent"}, "actions": frozenset({SPEND_SPIKE})},
        "b": {"agents": {"backup-dr-agent"}, "actions": JOB_IN_FLIGHT},
        "winner": "b",
        "severity": "LOW",
        "defer_until": "dr_job_complete",
        "title": "Spend spike explained by a DR test or restore in progress",
        "resolution": "Suppress the anomaly for the job window.",
    },
    {
        "id": "CFL-008",
        "kind": KIND_SUPPRESS,
        "a": {"agents": {"cost-anomaly-agent"}, "actions": frozenset({SPEND_SPIKE})},
        "b": {"agents": {"infra-agent"}, "actions": frozenset({APPROVED_CHANGE, SCALE_UP, SCALE_OUT})},
        "winner": "b",
        "severity": "LOW",
        "defer_until": None,
        "title": "Spend spike correlates with an approved capacity change",
        "resolution": "Suppress if the change is approved and time-correlated. Escalate if no approval record exists.",
    },
    {
        "id": "CFL-009",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"infra-agent"}, "actions": frozenset({OPEN_PATH})},
        "b": {"agents": {"network-security-agent"}, "actions": frozenset({CLOSE_PATH})},
        "winner": "b",
        "severity": "HIGH",
        "defer_until": "scoped_exception_approved",
        "title": "Connectivity change conflicts with a network security rule",
        "resolution": "Network security prevails. Synthesise the narrowest scoped rule that satisfies the connectivity need and record a time-bounded exception.",
    },
    {
        "id": "CFL-010",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"infra-agent"}, "actions": frozenset({GRANT})},
        "b": {"agents": {"access-analyzer-agent"}, "actions": frozenset({REVOKE})},
        "winner": "b",
        "severity": "HIGH",
        "defer_until": "scoped_policy_approved",
        "title": "Permission grant conflicts with a least-privilege finding",
        "resolution": "Access Analyzer prevails. Synthesise a scoped policy alternative rather than granting as requested.",
    },
    {
        "id": "CFL-011",
        "kind": KIND_SUPPRESS,
        "a": {"agents": {"access-analyzer-agent"}, "actions": frozenset({REVOKE})},
        "b": {"agents": {"backup-dr-agent"}, "actions": RESILIENCE_UP | JOB_IN_FLIGHT},
        "winner": "b",
        "severity": "MEDIUM",
        "defer_until": None,
        "title": "Unused-role finding targets a registered DR restore path",
        "resolution": "Check the DR role registry. If registered, suppress the revoke and exempt the role from unused-principal scanning with a recorded justification.",
    },
    {
        "id": "CFL-012",
        "kind": KIND_SUPPRESS,
        "a": {"agents": {"access-analyzer-agent", "security-agent"}, "actions": frozenset({REVOKE, BREAK_GLASS_USED})},
        "b": {"agents": {"incident-agent"}, "actions": FORENSIC_HOLD},
        "winner": "b",
        "severity": "MEDIUM",
        "defer_until": "post_incident_review",
        "title": "Break-glass or elevated access used during active incident response",
        "resolution": "Suppress within the incident window. Flag for mandatory post-incident access review.",
    },
    {
        "id": "CFL-013",
        "kind": KIND_SERIALIZE,
        "a": {"agents": {"security-agent"}, "actions": DISRUPTIVE},
        "b": {"agents": {"infra-agent"}, "actions": frozenset({SCALE_UP, SCALE_OUT, NO_ACTION, MONITOR})},
        "winner": None,
        "severity": "MEDIUM",
        "defer_until": "next_maintenance_window",
        "title": "Disruptive security remediation conflicts with an availability constraint",
        "resolution": "Not either/or. Schedule the remediation into the next maintenance window. Escalate only if that window falls past the remediation SLA.",
    },
    {
        "id": "CFL-014",
        "kind": KIND_SERIALIZE,
        "a": {"agents": {"security-agent"}, "actions": DISRUPTIVE | DESTRUCTIVE},
        "b": {"agents": {"incident-agent"}, "actions": FORENSIC_HOLD},
        "winner": "b",
        "severity": "HIGH",
        "defer_until": "forensic_snapshot_complete",
        "title": "Security remediation would destroy evidence under forensic hold",
        "resolution": "Snapshot first, then remediate the copy. The original stays on hold until the incident closes.",
    },
    {
        "id": "CFL-015",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"backup-dr-agent"}, "actions": frozenset({CROSS_REGION_REPLICA})},
        "b": {"agents": {"compliance-agent"}, "actions": frozenset({DATA_RESIDENCY})},
        "winner": "b",
        "severity": "CRITICAL",
        "defer_until": "compliant_region_selected",
        "title": "DR replication target violates a data-residency constraint",
        "resolution": "Compliance prevails. Re-target replication to a region permitted by the residency constraint.",
    },
    {
        "id": "CFL-016",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"cost-agent"}, "actions": RESILIENCE_DOWN | CAPACITY_DOWN | DESTRUCTIVE},
        "b": {"agents": {"compliance-agent"}, "actions": RESILIENCE_UP | frozenset({ENCRYPT_CMK})},
        "winner": "b",
        "severity": "HIGH",
        "defer_until": "control_exception_approved",
        "title": "Cost action would remove a mandated compliance control",
        "resolution": "Compliance prevails. The control stays; the cost saving is void without a formally approved control exception.",
    },
    {
        "id": "CFL-017",
        "kind": KIND_CONFLICT,
        "a": {"agents": {"network-security-agent"}, "actions": frozenset({CLOSE_PATH})},
        "b": {"agents": {"backup-dr-agent"}, "actions": frozenset({CROSS_REGION_REPLICA, RESTORE_IN_FLIGHT})},
        "winner": None,
        "severity": "HIGH",
        "defer_until": "replication_path_whitelisted",
        "title": "Network closure would sever a replication or restore path",
        "resolution": "Whitelist the replication path narrowly (specific prefixes and ports) rather than reopening the broader rule.",
    },
    {
        "id": "CFL-018",
        "kind": KIND_SERIALIZE,
        "a": {"agents": {"infra-agent"}, "actions": DISRUPTIVE | DESTRUCTIVE},
        "b": {"agents": {"backup-dr-agent"}, "actions": JOB_IN_FLIGHT},
        "winner": "b",
        "severity": "MEDIUM",
        "defer_until": "dr_job_complete",
        "title": "Rebuild or replace requested while a backup or restore is in flight",
        "resolution": "Serialise. Defer the infrastructure action until the job completes.",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 5. Matching engine
# ─────────────────────────────────────────────────────────────────────────────

ACTIVE_STATUSES = {"open", "in_progress", ""}


def _side_matches(side, finding):
    agents = side.get("agents")
    if agents is not None and finding.get("agent") not in agents:
        return False
    return finding.get("recommended_action") in side["actions"]


def _match_rule(rule, f1, f2):
    """Return (finding_a, finding_b) in rule orientation, or None."""
    if _side_matches(rule["a"], f1) and _side_matches(rule["b"], f2):
        return f1, f2
    if _side_matches(rule["a"], f2) and _side_matches(rule["b"], f1):
        return f2, f1
    return None


def _fallback_precedence(f1, f2):
    """Generic resolver for incompatible action pairs with no explicit rule.

    Incompatibility test: one side writes destructively or reduces posture
    while the other asserts a hold, an in-flight job, or the opposite posture.
    """
    a1 = f1.get("recommended_action")
    a2 = f2.get("recommended_action")

    opposed = (
        (a1 in DESTRUCTIVE and a2 in (FORENSIC_HOLD | JOB_IN_FLIGHT | RESILIENCE_UP)) or
        (a2 in DESTRUCTIVE and a1 in (FORENSIC_HOLD | JOB_IN_FLIGHT | RESILIENCE_UP)) or
        (a1 in RESILIENCE_DOWN and a2 in RESILIENCE_UP) or
        (a2 in RESILIENCE_DOWN and a1 in RESILIENCE_UP) or
        (a1 == OPEN_PATH and a2 == CLOSE_PATH) or
        (a2 == OPEN_PATH and a1 == CLOSE_PATH) or
        (a1 == GRANT and a2 == REVOKE) or
        (a2 == GRANT and a1 == REVOKE) or
        (a1 in CAPACITY_DOWN and a2 in CAPACITY_UP) or
        (a2 in CAPACITY_DOWN and a1 in CAPACITY_UP)
    )
    if not opposed:
        return None

    r1, r2 = precedence_rank(f1), precedence_rank(f2)
    if r1 == r2:
        return {"rule_id": "CFL-PREC-TIE", "kind": KIND_ADJUDICATE,
                "winner_finding": None, "loser_finding": None,
                "severity": "MEDIUM",
                "title": "Opposed recommendations within the same precedence tier",
                "resolution": "No deterministic ordering. Model adjudication required.",
                "defer_until": None, "a": f1, "b": f2}

    winner, loser = (f1, f2) if r1 < r2 else (f2, f1)
    return {"rule_id": "CFL-PREC", "kind": KIND_CONFLICT,
            "winner_finding": winner, "loser_finding": loser,
            "severity": "HIGH" if precedence_rank(winner) <= 2 else "MEDIUM",
            "title": (f"{domain_of(winner)} recommendation supersedes "
                      f"{domain_of(loser)} recommendation"),
            "resolution": (f"Defer the {loser.get('agent')} action. "
                           f"{winner.get('agent')} prevails by precedence."),
            "defer_until": "winning_finding_resolved", "a": f1, "b": f2}


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}


def resolve_resource(findings, account_id, resource_id):
    """Resolve all pairwise outcomes for one resource. Pure function."""
    outcomes = []

    # CFL-020 — severity reconciliation: take the max, never average.
    severities = [f.get("severity", "LOW") for f in findings]
    effective_severity = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0)) if severities else "LOW"

    seen_pairs = set()

    for f1, f2 in combinations(findings, 2):
        if f1.get("agent") == f2.get("agent"):
            continue

        pair_key = tuple(sorted([f1.get("scan_id", ""), f2.get("scan_id", "")]))
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        matched = None
        for rule in RULES:
            orientation = _match_rule(rule, f1, f2)
            if orientation:
                fa, fb = orientation
                winner = {"a": fa, "b": fb, None: None}[rule["winner"]]
                loser = None
                if rule["winner"] == "a":
                    loser = fb
                elif rule["winner"] == "b":
                    loser = fa
                matched = {
                    "rule_id": rule["id"], "kind": rule["kind"],
                    "winner_finding": winner, "loser_finding": loser,
                    "severity": rule["severity"], "title": rule["title"],
                    "resolution": rule["resolution"],
                    "defer_until": rule["defer_until"], "a": fa, "b": fb,
                }
                break

        if matched is None:
            matched = _fallback_precedence(f1, f2)

        # CFL-019 — concurrent writes on one resource that are not semantically
        # opposed still must not run together.
        if matched is None:
            if (f1.get("recommended_action") in WRITE_ACTIONS
                    and f2.get("recommended_action") in WRITE_ACTIONS):
                first = f1 if precedence_rank(f1) <= precedence_rank(f2) else f2
                second = f2 if first is f1 else f1
                matched = {
                    "rule_id": "CFL-019", "kind": KIND_SERIALIZE,
                    "winner_finding": first, "loser_finding": second,
                    "severity": "LOW",
                    "title": "Concurrent write actions on the same resource",
                    "resolution": (f"Serialise: apply {first.get('agent')} first, "
                                   f"then re-evaluate {second.get('agent')}."),
                    "defer_until": "prior_action_complete", "a": f1, "b": f2,
                }

        if matched is None:
            continue

        outcomes.append({
            "rule_id":        matched["rule_id"],
            "kind":           matched["kind"],
            "account_id":     account_id,
            "resource_id":    resource_id,
            "severity":       matched["severity"],
            "title":          matched["title"],
            "resolution":     matched["resolution"],
            "defer_until":    matched["defer_until"],
            "agents":         sorted({matched["a"].get("agent", ""), matched["b"].get("agent", "")}),
            "actions":        [matched["a"].get("recommended_action"),
                               matched["b"].get("recommended_action")],
            "prevails":       (matched["winner_finding"] or {}).get("agent"),
            "defers":         (matched["loser_finding"] or {}).get("agent"),
            "evidence": [
                {"scan_id": matched["a"].get("scan_id"), "agent": matched["a"].get("agent"),
                 "action": matched["a"].get("recommended_action"),
                 "severity": matched["a"].get("severity"),
                 "timestamp": matched["a"].get("timestamp")},
                {"scan_id": matched["b"].get("scan_id"), "agent": matched["b"].get("agent"),
                 "action": matched["b"].get("recommended_action"),
                 "severity": matched["b"].get("severity"),
                 "timestamp": matched["b"].get("timestamp")},
            ],
            "effective_resource_severity": effective_severity,
        })

    return outcomes


def resolve(items):
    """Entry point. `items` is the raw findings list from DynamoDB.

    Returns a dict with conflicts, suppressions, serialisations, the
    adjudication queue for the model, and counters that make data-quality
    gaps visible rather than silent.
    """
    active, stale, unclassified = [], 0, 0

    for item in items:
        if item.get("agent") == "orchestrator":
            continue
        if not item.get("resource_id"):
            continue
        if item.get("remediation_status", "open") not in ACTIVE_STATUSES:
            stale += 1
            continue
        if item.get("recommended_action") not in ACTIONS:
            unclassified += 1
            continue
        active.append(item)

    by_resource = {}
    for item in active:
        key = (item.get("account_id", ""), item["resource_id"])
        by_resource.setdefault(key, []).append(item)

    all_outcomes = []
    for (acct, res), findings in by_resource.items():
        if len(findings) < 2:
            continue
        all_outcomes.extend(resolve_resource(findings, acct, res))

    return {
        "conflicts":         [o for o in all_outcomes if o["kind"] == KIND_CONFLICT],
        "suppressions":      [o for o in all_outcomes if o["kind"] == KIND_SUPPRESS],
        "serialisations":    [o for o in all_outcomes if o["kind"] == KIND_SERIALIZE],
        "adjudication_queue":[o for o in all_outcomes if o["kind"] == KIND_ADJUDICATE],
        "resources_checked": len(by_resource),
        "findings_active":   len(active),
        "skipped_stale":     stale,
        "skipped_unclassified": unclassified,
    }
