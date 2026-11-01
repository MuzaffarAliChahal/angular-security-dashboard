import { describe, expect, it } from 'vitest';
import { adminsWithoutMfa, bruteForce, credentialStuffing, detect, impossibleTravel, peakInWindow, privilegeEscalation } from './detection';
import { AuditEvent, User } from './models';

const T0 = Date.parse('2026-10-01T12:00:00Z');
let id = 0;
const ev = (minute: number, type: AuditEvent['type'], user: string, ip = '10.0.0.1', country = 'Pakistan', detail = ''): AuditEvent => ({
  id: ++id, at: new Date(T0 + minute * 60_000).toISOString(), type, user, ip, country, detail,
});

describe('peakInWindow', () => {
  it('finds the busiest sliding window', () => {
    const list = [0, 1, 2, 30, 31].map((m) => ev(m, 'LOGIN_FAILED', 'a'));
    expect(peakInWindow(list, 10 * 60_000).count).toBe(3);
  });
});

describe('bruteForce', () => {
  it('alerts on 5 failures within 10 minutes', () => {
    const list = [0, 1, 2, 3, 4].map((m) => ev(m, 'LOGIN_FAILED', 'admin@x'));
    const alerts = bruteForce(list);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].severity).toBe('HIGH');
    expect(alerts[0].subject).toBe('admin@x');
  });

  it('ignores the same failures spread over an hour', () => {
    expect(bruteForce([0, 15, 30, 45, 60].map((m) => ev(m, 'LOGIN_FAILED', 'admin@x')))).toHaveLength(0);
  });
});

describe('credentialStuffing', () => {
  it('alerts when one IP fails against 3 accounts', () => {
    const list = ['a', 'b', 'c'].map((u, i) => ev(i, 'LOGIN_FAILED', u, '45.1.1.1'));
    expect(credentialStuffing(list)[0].subject).toBe('45.1.1.1');
  });

  it('does not alert for many failures on a single account', () => {
    expect(credentialStuffing([0, 1, 2, 3].map((m) => ev(m, 'LOGIN_FAILED', 'a', '45.1.1.1')))).toHaveLength(0);
  });
});

describe('impossibleTravel', () => {
  it('alerts on two countries within an hour', () => {
    const list = [ev(0, 'LOGIN_SUCCESS', 'sara', '1.1.1.1', 'Pakistan'), ev(25, 'LOGIN_SUCCESS', 'sara', '2.2.2.2', 'Brazil')];
    expect(impossibleTravel(list)[0].detail).toContain('25 minutes apart');
  });

  it('allows travel that takes a realistic time', () => {
    const list = [ev(0, 'LOGIN_SUCCESS', 'sara', '1.1.1.1', 'Pakistan'), ev(14 * 60, 'LOGIN_SUCCESS', 'sara', '2.2.2.2', 'Brazil')];
    expect(impossibleTravel(list)).toHaveLength(0);
  });
});

describe('adminsWithoutMfa', () => {
  const users: User[] = [
    { email: 'a', name: 'A', role: 'ADMIN', mfaEnabled: false, locked: false, lastLoginAt: null },
    { email: 'b', name: 'B', role: 'ADMIN', mfaEnabled: true, locked: false, lastLoginAt: null },
    { email: 'c', name: 'C', role: 'VIEWER', mfaEnabled: false, locked: false, lastLoginAt: null },
  ];

  it('flags active admins without MFA when the policy requires it', () => {
    expect(adminsWithoutMfa(users, true, new Date()).map((a) => a.subject)).toEqual(['a']);
  });

  it('flags nobody when the policy does not require it', () => {
    expect(adminsWithoutMfa(users, false, new Date())).toHaveLength(0);
  });
});

describe('detect', () => {
  it('sorts by severity, high first', () => {
    const list = [
      ...[0, 1, 2, 3, 4].map((m) => ev(m, 'LOGIN_FAILED', 'victim')),
      ev(5, 'ROLE_CHANGED', 'bob', '10.0.0.1', 'Pakistan', 'ANALYST → ADMIN'),
    ];
    expect(privilegeEscalation(list)).toHaveLength(1);
    expect(detect(list, [], false).map((a) => a.severity)).toEqual(['HIGH', 'LOW']);
  });
});
