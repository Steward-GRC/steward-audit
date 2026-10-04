# API

The service writes records only from events, and serves reads and verification over gRPC.

## Events in

Publishers send a `steward.audit.v1.AuditEvent` (`proto/steward/audit/v1/audit.proto`) to the
`audit` topic exchange (durable), serialized as protobuf binary with the AMQP content type:

```text
application/protobuf; proto=steward.audit.v1.AuditEvent
```

A publisher generates its own stubs from this repo's `proto/` at a pinned commit; it never imports
this module. The service declares the durable queue `audit.service.queue` and binds it to two
routing keys:

| Routing key | Tier |
| --- | --- |
| `audit.audit` | `TIER_AUDIT`: kept indefinitely by default, never purged when legal-basis exempt |
| `audit.activity` | `TIER_ACTIVITY`: kept for the activity retention (730 days by default) |

| Field | Required | Meaning |
| --- | --- | --- |
| `tier` | yes | `TIER_AUDIT` or `TIER_ACTIVITY`; the tier in the body is the one stored |
| `action` | yes | what happened, such as `policy.published` |
| `actor_user_id` | no | who did it; empty for system events; during act-as, the admin at the keyboard |
| `subject` | no | what it happened to, as `<kind>:<id>` |
| `group_id` | no | the group that scopes who may read the record |
| `occurred_at` | yes | when it happened, stamped by the publisher |
| `attributes` | no | extra detail, string to string |
| `legal_basis_exempt` | no | the record is never purged |

Attributes are hashed into the chain but never returned by the API, so don't put anything in them a
reader of the raw export shouldn't see.

JSON bodies are not accepted. A message that can't be stored (another content type, a body that
isn't an `AuditEvent`, an unset or unknown tier, no action, no or an invalid time) is
dead-lettered. Any other failure is not requeued either: the message goes to the queue's
dead-letter exchange, which the broker policy sets, instead of looping.

## gRPC

`steward.audit.v1.AuditService`, in `proto/steward/audit/v1/audit.proto`. The server also serves
`grpc.health.v1` and reflection.

Every request carries a `RequesterIdentity` (user id, roles, groups) that the gateway fills from the
session it authenticated; an empty user id is refused with `AUDIT_UNAUTHENTICATED`.

| RPC | Who may call | What it does |
| --- | --- | --- |
| `QueryAuditLog` | `auditor`, `compliance_officer`: any group. `group_admin`: only its own group, named in `group_id` | A page of records, filtered by tier, group, actor and subject. `next_page_token` is set when the page is full. Not audited. |
| `ExportAuditSegment` | `auditor`, `compliance_officer` | A record id range and the checkpoints wholly inside it, for offline verification. Each export is recorded as `audit_log.exported`. |
| `VerifyAuditChain` | any signed-in caller | Re-walks a record id range and its checkpoints on the server and returns pass or fail with the problems found. |
| `ListRecentEvents` | `auditor`, `compliance_officer`; `group_admin` sees its group and records with no group | Records that occurred at or after `since_timestamp` (an hour ago when unset), for a polling tail. Not audited. |

Page sizes and limits are 1 to 200; anything else means 50. Group admins can't export: record ids
are global and sequential, so an id range would reach other groups.

Errors carry a coded `ErrorInfo`; see [error codes](error-codes.md).

## Calling other services

None. The audit service calls no other Steward service and imports no other service's module. Other
services reach it by publishing events, and the gateway calls the gRPC API above.
