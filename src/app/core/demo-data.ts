/**
 * Generates a realistic, repeatable 24 hours of audit events for the demo, including
 * three attack patterns for the detection rules to find.
 */
import { AuditEvent, Role, User } from './models';

/** Small seeded PRNG (mulberry32), so the demo looks the same on every load. */
export function rng(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let r = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

const PEOPLE: [string, string, Role, boolean][] = [
  ['Ayesha Khan', 'ayesha.khan', 'ADMIN', true],
  ['Omar Farooq', 'omar.farooq', 'ADMIN', false],
  ['Sara Malik', 'sara.malik', 'MANAGER', true],
  ['Bilal Ahmed', 'bilal.ahmed', 'MANAGER', true],
  ['Hina Shah', 'hina.shah', 'ANALYST', true],
  ['Usman Tariq', 'usman.tariq', 'ADMIN', false],
  ['Zara Iqbal', 'zara.iqbal', 'ANALYST', true],
  ['Daniyal Raza', 'daniyal.raza', 'VIEWER', false],
  ['Mariam Aslam', 'mariam.aslam', 'VIEWER', true],
  ['Fahad Javed', 'fahad.javed', 'ANALYST', true],
  ['Nida Hussain', 'nida.hussain', 'VIEWER', false],
  ['Kamran Ali', 'kamran.ali', 'MANAGER', true],
  ['Emily Carter', 'emily.carter', 'ANALYST', true],
  ['James Wilson', 'james.wilson', 'VIEWER', false],
  ['Priya Nair', 'priya.nair', 'ANALYST', true],
  ['Lucas Silva', 'lucas.silva', 'VIEWER', true],
];

const HOME: Record<string, [string, string]> = {};
const OFFICES: [string, string][] = [['Pakistan', '39.45.'], ['United Kingdom', '81.2.'], ['United States', '73.162.'], ['United Arab Emirates', '94.200.']];

export function demoUsers(): User[] {
  return PEOPLE.map(([name, handle, role, mfa], i) => {
    HOME[`${handle}@example.com`] = OFFICES[i % OFFICES.length];
    return { email: `${handle}@example.com`, name, role, mfaEnabled: mfa, locked: false, lastLoginAt: null };
  });
}

export function demoEvents(users: User[], now = new Date()): AuditEvent[] {
  const rand = rng(42);
  const events: Omit<AuditEvent, 'id'>[] = [];
  const end = now.getTime();
  const at = (minutesAgo: number) => new Date(end - minutesAgo * 60_000).toISOString();
  const pick = <T>(list: T[]) => list[Math.floor(rand() * list.length)];
  const homeOf = (email: string) => HOME[email] ?? OFFICES[0];
  const ipFor = (email: string) => `${homeOf(email)[1]}${1 + Math.floor(rand() * 200)}.${1 + Math.floor(rand() * 250)}`;

  // Normal day: sign-ins weighted to office hours, plus the odd typo.
  for (let i = 0; i < 260; i++) {
    const hour = rand() < 0.8 ? 9 + rand() * 9 : rand() * 24;
    const minutesAgo = Math.max(1, ((now.getHours() - hour + 24) % 24) * 60 + rand() * 60);
    const u = pick(users).email;
    const [country] = homeOf(u);
    if (rand() < 0.08) {
      events.push({ at: at(minutesAgo + 1), type: 'LOGIN_FAILED', user: u, ip: ipFor(u), country, detail: 'bad password' });
    }
    events.push({ at: at(minutesAgo), type: 'LOGIN_SUCCESS', user: u, ip: ipFor(u), country, detail: rand() < 0.6 ? 'password + MFA' : 'password' });
  }

  // Attack 1: brute force on one admin account, then the lockout kicks in.
  const target = 'omar.farooq@example.com';
  for (let i = 0; i < 9; i++) {
    events.push({ at: at(130 - i * 0.6), type: 'LOGIN_FAILED', user: target, ip: '185.220.101.37', country: 'Netherlands', detail: 'bad password' });
  }
  events.push({ at: at(124.5), type: 'ACCOUNT_LOCKED', user: target, ip: '185.220.101.37', country: 'Netherlands', detail: 'lockout threshold reached', actor: 'system' });

  // Attack 2: one IP trying a password list against many accounts.
  ['emily.carter', 'james.wilson', 'priya.nair', 'lucas.silva', 'nida.hussain', 'daniyal.raza'].forEach((h, i) => {
    events.push({ at: at(310 - i * 0.5), type: 'LOGIN_FAILED', user: `${h}@example.com`, ip: '45.155.205.99', country: 'Singapore', detail: 'unknown password' });
  });

  // Attack 3: a session from another continent 25 minutes after a normal sign-in.
  events.push({ at: at(75), type: 'LOGIN_SUCCESS', user: 'sara.malik@example.com', ip: '39.45.12.8', country: 'Pakistan', detail: 'password + MFA' });
  events.push({ at: at(50), type: 'LOGIN_SUCCESS', user: 'sara.malik@example.com', ip: '177.71.20.4', country: 'Brazil', detail: 'password + MFA' });

  // Admin work during the day.
  events.push({ at: at(480), type: 'ROLE_CHANGED', user: 'kamran.ali@example.com', ip: '39.45.3.10', country: 'Pakistan', detail: 'MANAGER → ADMIN', actor: 'ayesha.khan@example.com' });
  events.push({ at: at(470), type: 'ROLE_CHANGED', user: 'kamran.ali@example.com', ip: '39.45.3.10', country: 'Pakistan', detail: 'ADMIN → MANAGER', actor: 'ayesha.khan@example.com' });
  events.push({ at: at(600), type: 'PASSWORD_RESET', user: 'hina.shah@example.com', ip: '39.45.77.2', country: 'Pakistan', detail: 'self-service reset' });
  events.push({ at: at(200), type: 'MFA_FAILED', user: 'bilal.ahmed@example.com', ip: '81.2.69.140', country: 'United Kingdom', detail: 'wrong one-time code' });

  return events
    .sort((a, b) => b.at.localeCompare(a.at))
    .map((e, i, all) => ({ ...e, id: all.length - i }));
}
