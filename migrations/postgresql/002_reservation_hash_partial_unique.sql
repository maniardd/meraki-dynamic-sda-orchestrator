-- 002_reservation_hash_partial_unique.sql
--
-- Fix: re-planning an identical design after a verified release failed with a
-- 409 conflict. design_reservations.reservation_hash carried an UNCONDITIONAL
-- UNIQUE constraint, but reservation_hash is a deterministic hash of the derived
-- design body. Once a reservation is released its allocations are freed and an
-- identical demand re-derives the same reservation_hash -- which then collided
-- with the retained released row (UniqueViolation -> ConflictError -> HTTP 409).
--
-- The network_allocations (GiST) and scalar_allocations (partial unique) ledgers
-- already exclude released rows. This migration brings the reservation table in
-- line: uniqueness is enforced only among ACTIVE reservations, so a released
-- design can be re-planned while genuine active duplicates are still rejected.
--
-- Idempotent and safe to run against both the deployed schema and a fresh one.

BEGIN;

-- Drop the unconditional unique constraint created inline by 001. The
-- auto-generated name is design_reservations_reservation_hash_key; guard with
-- IF EXISTS so the migration is safe if it was already removed.
ALTER TABLE design_reservations
    DROP CONSTRAINT IF EXISTS design_reservations_reservation_hash_key;

-- Enforce uniqueness only among active reservations (released rows excluded),
-- mirroring network_allocations and scalar_allocations.
CREATE UNIQUE INDEX IF NOT EXISTS design_reservations_reservation_hash_active
    ON design_reservations(reservation_hash)
    WHERE state IN ('reserved','committed','quarantined');

COMMIT;
