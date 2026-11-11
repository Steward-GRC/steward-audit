-- Copyright 2026 The Steward Authors
-- SPDX-License-Identifier: Apache-2.0

-- The query filters on a list of actions, and the action list reads the
-- distinct ones.
CREATE INDEX audit_records_action_idx ON audit_records (action);
