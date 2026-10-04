# Error codes

Every gRPC error from the audit service carries an `ErrorInfo` with the symbol as its
reason, the domain `audit` and the code in `codeNum`. Only user-safe messages reach the
caller; every other code is sent as `Code N: Internal Error`.

| Code | Symbol | Area | Cause | User-safe |
| --- | --- | --- | --- | --- |
| 2000 | `AUDIT_INTERNAL` | audit | an uncoded failure inside the audit service | no |
| 2001 | `AUDIT_STORE_UNAVAILABLE` | audit store | an audit store read failed; the op metadata names it, the cause is only logged | no |
| 2002 | `AUDIT_EXPORT_FORBIDDEN` | audit export | a caller without the auditor or compliance_officer role asked for a raw segment | yes |
| 2003 | `AUDIT_GROUP_SCOPE_DENIED` | audit query | a group_admin asked for another group or for every group | yes |
| 2004 | `AUDIT_UNAUTHENTICATED` | audit | the request carried no requester, or one with an empty user id | yes |
| 2005 | `AUDIT_INVALID_PAGE_TOKEN` | audit query | the page token is not one this service issued | yes |
| 2006 | `AUDIT_TAIL_FORBIDDEN` | audit tail | the caller has no role that may follow recent audit events | yes |
