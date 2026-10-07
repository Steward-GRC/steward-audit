# Error codes

Every gRPC error from the audit service carries an `ErrorInfo` with the symbol as its
reason, the domain `audit` and the code in `codeNum`. Only user-safe messages reach the
caller; every other code is sent as `Code N: Internal Error`.

| Code | Symbol | Area | Cause | User-safe |
| --- | --- | --- | --- | --- |
| 2000 | `AUDIT_INTERNAL` | audit | an uncoded failure inside the audit service | no |
| 2001 | `AUDIT_STORE_UNAVAILABLE` | audit store | an audit store read failed; the op metadata names it, the cause is only logged | no |
| 2002 | `AUDIT_EXPORT_FORBIDDEN` | audit export | a caller without audit.read asked for a raw segment | yes |
| 2003 | `AUDIT_GROUP_SCOPE_DENIED` | audit query | a caller without audit.read asked for a group it doesn't manage, or for every group | yes |
| 2004 | `AUDIT_UNAUTHENTICATED` | audit | the request carried no requester, or one with an empty user id | yes |
| 2005 | `AUDIT_INVALID_PAGE_TOKEN` | audit query | the page token is not one this service issued | yes |
| 2006 | `AUDIT_TAIL_FORBIDDEN` | audit tail | the caller has neither audit.read nor a group it manages | yes |
| 2007 | `AUDIT_VERIFY_FORBIDDEN` | audit verify | the caller has neither audit.read nor a group it manages | yes |
| 2008 | `AUDIT_MANAGE_FORBIDDEN` | audit retention | a caller without compliance.manage asked to shred a subject or manage legal holds | yes |
| 2009 | `AUDIT_INVALID_ARGUMENT` | audit retention | a required field (the subject key, the reason or the hold id) was empty | yes |
| 2010 | `AUDIT_HOLD_NOT_FOUND` | legal hold | no legal hold in force has that id; it may already be released | yes |
| 2011 | `AUDIT_SHRED_INCOMPLETE` | crypto-shred | the subject's key is destroyed but clearing its records or writing the shred record failed; the cause is only logged | yes |
