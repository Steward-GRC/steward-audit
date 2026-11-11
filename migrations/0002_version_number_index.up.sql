-- Copyright 2026 The Steward Authors
-- SPDX-License-Identifier: Apache-2.0

-- A policy version's events carry its number in the hashed attributes, so the
-- chain covers it. The query filters on it, so index the expression it reads.
CREATE INDEX audit_records_version_number_idx
    ON audit_records ((attributes->>'version_number'))
    WHERE (attributes->>'version_number') IS NOT NULL;
