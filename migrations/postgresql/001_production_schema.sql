CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TABLE IF NOT EXISTS intents (
    intent_id TEXT PRIMARY KEY,
    intent_hash TEXT NOT NULL UNIQUE,
    fabric_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    document_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS design_reservations (
    reservation_id TEXT PRIMARY KEY,
    idempotency_key_hash TEXT NOT NULL UNIQUE,
    requirements_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    reservation_hash TEXT NOT NULL UNIQUE,
    allocation_domain TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','quarantined')),
    intent_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS design_reservations_fabric_idx
    ON design_reservations(allocation_domain, fabric_id, state);

CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY,
    plan_hash TEXT NOT NULL UNIQUE,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    reservation_id TEXT REFERENCES design_reservations(reservation_id),
    intent_id TEXT NOT NULL REFERENCES intents(intent_id),
    fabric_id TEXT NOT NULL,
    document_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES plans(plan_id),
    plan_hash TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
    approver TEXT NOT NULL,
    change_reference TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS approvals_plan_idx
    ON approvals(plan_id, created_at DESC);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES plans(plan_id),
    plan_hash TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL CHECK (mode IN ('dry_run','apply')),
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    maintenance_start TIMESTAMPTZ,
    maintenance_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS fabric_locks (
    fabric_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id),
    acquired_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    phase_id TEXT NOT NULL,
    device_id TEXT,
    evidence_type TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    payload_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_run_idx
    ON evidence(run_id, phase_id, created_at);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_aggregate_idx
    ON audit_events(aggregate_type, aggregate_id, sequence);

CREATE TABLE IF NOT EXISTS network_allocations (
    allocation_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL REFERENCES design_reservations(reservation_id),
    allocation_domain TEXT NOT NULL,
    resource_pool_id TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    prefix CIDR NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','quarantined')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    EXCLUDE USING gist (
        allocation_domain WITH =,
        resource_pool_id WITH =,
        prefix inet_ops WITH &&
    ) WHERE (state IN ('reserved','committed','quarantined'))
);

CREATE INDEX IF NOT EXISTS network_allocations_active_idx
    ON network_allocations(allocation_domain, resource_pool_id, state, prefix);

CREATE TABLE IF NOT EXISTS scalar_allocations (
    allocation_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL REFERENCES design_reservations(reservation_id),
    allocation_domain TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    value TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','quarantined')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS scalar_allocations_active_unique
    ON scalar_allocations(allocation_domain, resource_type, value)
    WHERE state IN ('reserved','committed','quarantined');

CREATE INDEX IF NOT EXISTS scalar_allocations_active_idx
    ON scalar_allocations(allocation_domain, resource_type, state, value);
