BEGIN;

CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TABLE IF NOT EXISTS design_reservation (
    reservation_id UUID PRIMARY KEY,
    idempotency_key_hash TEXT NOT NULL UNIQUE,
    requirements_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    reservation_hash TEXT NOT NULL UNIQUE,
    allocation_domain TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','quarantined')),
    intent JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_allocation (
    allocation_id UUID PRIMARY KEY,
    reservation_id UUID NOT NULL REFERENCES design_reservation(reservation_id),
    allocation_domain TEXT NOT NULL,
    resource_pool_id TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    prefix CIDR NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','quarantined')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    EXCLUDE USING gist (
        allocation_domain WITH =,
        resource_pool_id WITH =,
        prefix WITH &&
    ) WHERE (state IN ('reserved','committed','quarantined'))
);

CREATE TABLE IF NOT EXISTS scalar_allocation (
    allocation_id UUID PRIMARY KEY,
    reservation_id UUID NOT NULL REFERENCES design_reservation(reservation_id),
    allocation_domain TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    value TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','quarantined')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS scalar_allocation_active_unique
    ON scalar_allocation(allocation_domain, resource_type, value)
    WHERE state IN ('reserved','committed','quarantined');

CREATE TABLE IF NOT EXISTS fabric_intent (
    intent_id TEXT PRIMARY KEY,
    intent_hash TEXT NOT NULL UNIQUE,
    fabric_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deployment_plan (
    plan_id TEXT PRIMARY KEY,
    plan_hash TEXT NOT NULL UNIQUE,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    reservation_id UUID REFERENCES design_reservation(reservation_id),
    intent_id TEXT NOT NULL REFERENCES fabric_intent(intent_id),
    fabric_id TEXT NOT NULL,
    document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_approval (
    approval_id UUID PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES deployment_plan(plan_id),
    plan_hash TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
    approver_identity TEXT NOT NULL,
    change_reference TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS plan_approval_latest_idx
    ON plan_approval(plan_id, created_at DESC);

CREATE TABLE IF NOT EXISTS deployment_run (
    run_id UUID PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES deployment_plan(plan_id),
    plan_hash TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL CHECK (mode IN ('dry_run','apply')),
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    maintenance_start TIMESTAMPTZ,
    maintenance_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS run_evidence (
    evidence_id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES deployment_run(run_id),
    phase_id TEXT NOT NULL,
    device_id TEXT,
    evidence_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    payload_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS run_evidence_lookup_idx
    ON run_evidence(run_id, phase_id, created_at);

CREATE TABLE IF NOT EXISTS audit_event (
    sequence BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload JSONB NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_event_aggregate_idx
    ON audit_event(aggregate_type, aggregate_id, sequence);

COMMIT;
