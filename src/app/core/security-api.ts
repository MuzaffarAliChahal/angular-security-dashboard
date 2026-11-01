import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, delay, of } from 'rxjs';
import { environment } from '../../environments/environment';
import { demoEvents, demoUsers } from './demo-data';
import { AuditEvent, SecurityPolicy, User } from './models';

/**
 * Backend contract (see docs/api.md). The HTTP version is written against that contract;
 * the demo version keeps everything in memory.
 */
export abstract class SecurityApi {
  abstract readonly mode: 'live' | 'demo';
  abstract events(): Observable<AuditEvent[]>;
  abstract users(): Observable<User[]>;
  abstract policy(): Observable<SecurityPolicy>;
  abstract acknowledged(): Observable<string[]>;
  abstract updateUser(email: string, patch: Partial<Pick<User, 'role' | 'locked'>>, actor: string): Observable<{ user: User; event: AuditEvent }>;
  abstract updatePolicy(policy: SecurityPolicy, actor: string): Observable<{ policy: SecurityPolicy; event: AuditEvent }>;
  abstract acknowledge(alertId: string): Observable<void>;
}

@Injectable()
export class HttpSecurityApi extends SecurityApi {
  readonly mode = 'live' as const;
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiUrl}/api/security`;

  events() { return this.http.get<AuditEvent[]>(`${this.base}/events`, { params: { hours: 24 } }); }
  users() { return this.http.get<User[]>(`${this.base}/users`); }
  policy() { return this.http.get<SecurityPolicy>(`${this.base}/policy`); }
  acknowledged() { return this.http.get<string[]>(`${this.base}/alerts/acknowledged`); }
  updateUser(email: string, patch: Partial<Pick<User, 'role' | 'locked'>>) {
    return this.http.patch<{ user: User; event: AuditEvent }>(`${this.base}/users/${encodeURIComponent(email)}`, patch);
  }
  updatePolicy(policy: SecurityPolicy) {
    return this.http.put<{ policy: SecurityPolicy; event: AuditEvent }>(`${this.base}/policy`, policy);
  }
  acknowledge(alertId: string) {
    return this.http.post<void>(`${this.base}/alerts/${encodeURIComponent(alertId)}/ack`, {});
  }
}

export const DEFAULT_POLICY: SecurityPolicy = {
  minPasswordLength: 12,
  lockoutThreshold: 5,
  lockoutMinutes: 15,
  sessionTimeoutMinutes: 30,
  requireMfaForAdmins: true,
};

@Injectable()
export class DemoSecurityApi extends SecurityApi {
  readonly mode = 'demo' as const;
  private readonly userList = demoUsers();
  private readonly eventList = demoEvents(this.userList);
  private current = { ...DEFAULT_POLICY };
  private readonly acks = new Set<string>();

  constructor() {
    super();
    // Apply what the generated events imply: lockouts and last sign-in times.
    for (const e of [...this.eventList].reverse()) {
      const u = this.userList.find((x) => x.email === e.user);
      if (!u) continue;
      if (e.type === 'ACCOUNT_LOCKED') u.locked = true;
      if (e.type === 'LOGIN_SUCCESS') u.lastLoginAt = e.at;
    }
  }

  events() { return this.reply([...this.eventList]); }
  users() { return this.reply(this.userList.map((u) => ({ ...u }))); }
  policy() { return this.reply({ ...this.current }); }
  acknowledged() { return this.reply([...this.acks]); }

  updateUser(email: string, patch: Partial<Pick<User, 'role' | 'locked'>>, actor: string) {
    const u = this.userList.find((x) => x.email === email)!;
    let event: AuditEvent;
    if (patch.role && patch.role !== u.role) {
      event = this.record('ROLE_CHANGED', email, `${u.role} → ${patch.role}`, actor);
      u.role = patch.role;
    } else {
      u.locked = !!patch.locked;
      event = this.record(u.locked ? 'ACCOUNT_LOCKED' : 'ACCOUNT_UNLOCKED', email, u.locked ? 'locked by an administrator' : 'unlocked by an administrator', actor);
    }
    return this.reply({ user: { ...u }, event });
  }

  updatePolicy(policy: SecurityPolicy, actor: string) {
    const changes = (Object.keys(policy) as (keyof SecurityPolicy)[])
      .filter((k) => policy[k] !== this.current[k])
      .map((k) => `${k}: ${this.current[k]} → ${policy[k]}`);
    this.current = { ...policy };
    const event = this.record('POLICY_CHANGED', actor, changes.join(', ') || 'no changes', actor);
    return this.reply({ policy: { ...this.current }, event });
  }

  acknowledge(alertId: string) {
    this.acks.add(alertId);
    return this.reply(undefined);
  }

  private record(type: AuditEvent['type'], user: string, detail: string, actor: string): AuditEvent {
    const event: AuditEvent = {
      id: (this.eventList[0]?.id ?? 0) + 1, at: new Date().toISOString(), type, user, ip: '39.45.0.1', country: 'Pakistan', detail, actor,
    };
    this.eventList.unshift(event);
    return event;
  }

  private reply<T>(value: T): Observable<T> {
    return of(value).pipe(delay(environment.demoLatencyMs));
  }
}
