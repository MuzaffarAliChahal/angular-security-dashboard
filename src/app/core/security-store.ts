import { Injectable, computed, inject, signal } from '@angular/core';
import { forkJoin } from 'rxjs';
import { detect } from './detection';
import { AuditEvent, Role, SecurityPolicy, User } from './models';
import { DEFAULT_POLICY, SecurityApi } from './security-api';

/** The signed-in administrator in this demo. */
export const CURRENT_ADMIN = 'ayesha.khan@example.com';

/**
 * Signal-based state for the console. Loads everything once, applies changes through the API
 * and derives alerts and statistics with computed signals.
 */
@Injectable({ providedIn: 'root' })
export class SecurityStore {
  private readonly api = inject(SecurityApi);

  readonly loaded = signal(false);
  readonly error = signal<string | null>(null);
  readonly events = signal<AuditEvent[]>([]);
  readonly users = signal<User[]>([]);
  readonly policy = signal<SecurityPolicy>(DEFAULT_POLICY);
  private readonly acked = signal<Set<string>>(new Set());

  readonly alerts = computed(() =>
    detect(this.events(), this.users(), this.policy().requireMfaForAdmins).map((a) => ({ ...a, acknowledged: this.acked().has(a.id) })),
  );
  readonly openAlerts = computed(() => this.alerts().filter((a) => !a.acknowledged));

  readonly signIns = computed(() => this.events().filter((e) => e.type === 'LOGIN_SUCCESS' || e.type === 'LOGIN_FAILED'));
  readonly failedRate = computed(() => {
    const all = this.signIns();
    return all.length ? (100 * all.filter((e) => e.type === 'LOGIN_FAILED').length) / all.length : 0;
  });
  readonly mfaCoverage = computed(() => {
    const u = this.users();
    return u.length ? (100 * u.filter((x) => x.mfaEnabled).length) / u.length : 0;
  });

  /** Sign-ins per hour for the last 24 hours, oldest first. */
  readonly hourly = computed(() => {
    const now = Date.now();
    const buckets = Array.from({ length: 24 }, (_, i) => ({ hoursAgo: 23 - i, ok: 0, failed: 0, label: '' }));
    for (const e of this.signIns()) {
      const h = Math.floor((now - new Date(e.at).getTime()) / 3_600_000);
      if (h < 0 || h > 23) continue;
      const b = buckets[23 - h];
      if (e.type === 'LOGIN_SUCCESS') b.ok++;
      else b.failed++;
    }
    for (const b of buckets) {
      b.label = new Date(now - b.hoursAgo * 3_600_000).getHours().toString().padStart(2, '0');
    }
    return buckets;
  });

  readonly topFailingIps = computed(() => {
    const map = new Map<string, { ip: string; country: string; count: number; users: Set<string> }>();
    for (const e of this.events().filter((x) => x.type === 'LOGIN_FAILED')) {
      const row = map.get(e.ip) ?? { ip: e.ip, country: e.country, count: 0, users: new Set<string>() };
      row.count++;
      row.users.add(e.user);
      map.set(e.ip, row);
    }
    return [...map.values()].sort((a, b) => b.count - a.count).slice(0, 5).map((r) => ({ ...r, accounts: r.users.size }));
  });

  load() {
    if (this.loaded()) return;
    forkJoin({ events: this.api.events(), users: this.api.users(), policy: this.api.policy(), acked: this.api.acknowledged() }).subscribe({
      next: (r) => {
        this.events.set(r.events);
        this.users.set(r.users);
        this.policy.set(r.policy);
        this.acked.set(new Set(r.acked));
        this.loaded.set(true);
      },
      error: (e: Error) => this.error.set(e.message),
    });
  }

  changeRole(email: string, role: Role) {
    this.api.updateUser(email, { role }, CURRENT_ADMIN).subscribe((r) => this.applyUser(r.user, r.event));
  }

  setLocked(email: string, locked: boolean) {
    this.api.updateUser(email, { locked }, CURRENT_ADMIN).subscribe((r) => this.applyUser(r.user, r.event));
  }

  savePolicy(policy: SecurityPolicy) {
    return new Promise<void>((resolve) =>
      this.api.updatePolicy(policy, CURRENT_ADMIN).subscribe((r) => {
        this.policy.set(r.policy);
        this.events.update((list) => [r.event, ...list]);
        resolve();
      }),
    );
  }

  acknowledge(alertId: string) {
    this.api.acknowledge(alertId).subscribe(() => this.acked.update((s) => new Set(s).add(alertId)));
  }

  private applyUser(user: User, event: AuditEvent) {
    this.users.update((list) => list.map((u) => (u.email === user.email ? user : u)));
    this.events.update((list) => [event, ...list]);
  }
}
