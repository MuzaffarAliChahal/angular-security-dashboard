# Backend API contract

The dashboard's `HttpSecurityApi` expects these endpoints under `/api/security`. All bodies are JSON and timestamps are ISO-8601 strings in UTC.

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| GET | `/events?hours=24` | – | `AuditEvent[]`, newest first |
| GET | `/users` | – | `User[]` |
| GET | `/policy` | – | `SecurityPolicy` |
| PUT | `/policy` | `SecurityPolicy` | `{ policy, event }`, where `event` is the `POLICY_CHANGED` audit entry |
| PATCH | `/users/{email}` | `{ "role": "ADMIN" }` or `{ "locked": true }` | `{ user, event }` with the matching audit entry |
| GET | `/alerts/acknowledged` | – | `string[]` of acknowledged alert ids |
| POST | `/alerts/{id}/ack` | – | `204 No Content` |

Types are in [`src/app/core/models.ts`](../src/app/core/models.ts).

```json
// AuditEvent
{ "id": 812, "at": "2026-10-12T21:28:00Z", "type": "LOGIN_FAILED", "user": "omar.farooq@example.com",
  "ip": "185.220.101.37", "country": "Netherlands", "detail": "bad password" }
```

Notes for the server side:

- The audit log is append-only. Role, lock and policy changes return the event they created, so the UI can show it without reloading.
- Alerts are computed from events by the rules in `detection.ts`. They can run in the browser (as now) or on the server with the same thresholds.
- The server must reject a user changing their own role or locking themselves; the UI already hides those controls.
