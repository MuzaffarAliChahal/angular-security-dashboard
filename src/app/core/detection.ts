/**
 * Detection rules that turn audit events into alerts. Pure functions, so they are easy to test
 * and could run the same way on the server.
 */
import { Alert, AuditEvent, User } from './models';

const MIN = 60_000;
const t = (e: AuditEvent) => new Date(e.at).getTime();

/** Groups items by key. */
function groupBy<T>(items: T[], key: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    map.set(k, [...(map.get(k) ?? []), item]);
  }
  return map;
}

/** Largest number of events that fall inside any sliding window of `windowMs`, and where that window ends. */
export function peakInWindow(events: AuditEvent[], windowMs: number): { count: number; endsAt: AuditEvent | null } {
  const sorted = [...events].sort((a, b) => t(a) - t(b));
  let best = { count: 0, endsAt: null as AuditEvent | null };
  let start = 0;
  for (let end = 0; end < sorted.length; end++) {
    while (t(sorted[end]) - t(sorted[start]) > windowMs) start++;
    const count = end - start + 1;
    if (count > best.count) best = { count, endsAt: sorted[end] };
  }
  return best;
}

/** 5+ failed logins for one account within 10 minutes. */
export function bruteForce(events: AuditEvent[], threshold = 5, windowMinutes = 10): Alert[] {
  const failed = events.filter((e) => e.type === 'LOGIN_FAILED');
  return [...groupBy(failed, (e) => e.user)].flatMap(([user, list]) => {
    const peak = peakInWindow(list, windowMinutes * MIN);
    if (peak.count < threshold || !peak.endsAt) return [];
    return [{
      id: `BRUTE_FORCE:${user}`, rule: 'BRUTE_FORCE', severity: 'HIGH', subject: user, at: peak.endsAt.at, acknowledged: false,
      title: `Brute-force attempt on ${user}`,
      detail: `${peak.count} failed logins within ${windowMinutes} minutes, last from ${peak.endsAt.ip} (${peak.endsAt.country})`,
    } satisfies Alert];
  });
}

/** One IP failing against 3+ different accounts within 10 minutes. */
export function credentialStuffing(events: AuditEvent[], minAccounts = 3, windowMinutes = 10): Alert[] {
  const failed = events.filter((e) => e.type === 'LOGIN_FAILED');
  return [...groupBy(failed, (e) => e.ip)].flatMap(([ip, list]) => {
    const sorted = [...list].sort((a, b) => t(a) - t(b));
    for (let i = 0; i < sorted.length; i++) {
      const window = sorted.filter((e) => t(e) >= t(sorted[i]) && t(e) - t(sorted[i]) <= windowMinutes * MIN);
      const accounts = new Set(window.map((e) => e.user));
      if (accounts.size >= minAccounts) {
        const last = window[window.length - 1];
        return [{
          id: `CREDENTIAL_STUFFING:${ip}`, rule: 'CREDENTIAL_STUFFING', severity: 'HIGH', subject: ip, at: last.at, acknowledged: false,
          title: `Credential stuffing from ${ip}`,
          detail: `${window.length} failed logins against ${accounts.size} accounts within ${windowMinutes} minutes (${last.country})`,
        } satisfies Alert];
      }
    }
    return [];
  });
}

/** Successful logins for one account from two countries less than an hour apart. */
export function impossibleTravel(events: AuditEvent[], withinMinutes = 60): Alert[] {
  const ok = events.filter((e) => e.type === 'LOGIN_SUCCESS');
  return [...groupBy(ok, (e) => e.user)].flatMap(([user, list]) => {
    const sorted = [...list].sort((a, b) => t(a) - t(b));
    for (let i = 1; i < sorted.length; i++) {
      const [a, b] = [sorted[i - 1], sorted[i]];
      const gap = (t(b) - t(a)) / MIN;
      if (a.country !== b.country && gap < withinMinutes) {
        return [{
          id: `IMPOSSIBLE_TRAVEL:${user}`, rule: 'IMPOSSIBLE_TRAVEL', severity: 'MEDIUM', subject: user, at: b.at, acknowledged: false,
          title: `Impossible travel for ${user}`,
          detail: `Signed in from ${a.country} and ${b.country} ${Math.round(gap)} minutes apart`,
        } satisfies Alert];
      }
    }
    return [];
  });
}

/** Admins without MFA, when the policy requires it. */
export function adminsWithoutMfa(users: User[], required: boolean, now: Date): Alert[] {
  if (!required) return [];
  return users
    .filter((u) => u.role === 'ADMIN' && !u.mfaEnabled && !u.locked)
    .map((u) => ({
      id: `ADMIN_WITHOUT_MFA:${u.email}`, rule: 'ADMIN_WITHOUT_MFA', severity: 'MEDIUM', subject: u.email, at: now.toISOString(), acknowledged: false,
      title: `Admin without MFA: ${u.email}`,
      detail: 'The policy requires MFA for administrators',
    } satisfies Alert));
}

/** Any role change that grants ADMIN. */
export function privilegeEscalation(events: AuditEvent[]): Alert[] {
  return events
    .filter((e) => e.type === 'ROLE_CHANGED' && e.detail.endsWith('→ ADMIN'))
    .map((e) => ({
      id: `PRIVILEGE_ESCALATION:${e.id}`, rule: 'PRIVILEGE_ESCALATION', severity: 'LOW', subject: e.user, at: e.at, acknowledged: false,
      title: `${e.user} was made an admin`,
      detail: `${e.detail}${e.actor ? ` by ${e.actor}` : ''}`,
    } satisfies Alert));
}

const RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 } as const;

export function detect(events: AuditEvent[], users: User[], requireMfaForAdmins: boolean, now = new Date()): Alert[] {
  return [
    ...bruteForce(events),
    ...credentialStuffing(events),
    ...impossibleTravel(events),
    ...adminsWithoutMfa(users, requireMfaForAdmins, now),
    ...privilegeEscalation(events),
  ].sort((a, b) => RANK[a.severity] - RANK[b.severity] || b.at.localeCompare(a.at));
}
