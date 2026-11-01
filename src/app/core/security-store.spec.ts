import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { DemoSecurityApi, SecurityApi } from './security-api';
import { SecurityStore } from './security-store';

const settle = () => new Promise((r) => setTimeout(r, 450));

describe('SecurityStore with demo data', () => {
  let store: SecurityStore;

  beforeEach(async () => {
    TestBed.configureTestingModule({ providers: [{ provide: SecurityApi, useClass: DemoSecurityApi }] });
    store = TestBed.inject(SecurityStore);
    store.load();
    await settle();
  });

  it('finds the attacks planted in the demo data', () => {
    const rules = new Set(store.alerts().map((a) => a.rule));
    expect(rules).toContain('BRUTE_FORCE');
    expect(rules).toContain('CREDENTIAL_STUFFING');
    expect(rules).toContain('IMPOSSIBLE_TRAVEL');
    expect(rules).toContain('ADMIN_WITHOUT_MFA');
  });

  it('locks the brute-forced account', () => {
    expect(store.users().find((u) => u.email === 'omar.farooq@example.com')?.locked).toBe(true);
  });

  it('records a role change in the audit log and raises a privilege alert', async () => {
    const before = store.events().length;
    store.changeRole('hina.shah@example.com', 'ADMIN');
    await settle();
    expect(store.events().length).toBe(before + 1);
    expect(store.events()[0]).toMatchObject({ type: 'ROLE_CHANGED', detail: 'ANALYST → ADMIN', actor: 'ayesha.khan@example.com' });
    expect(store.alerts().some((a) => a.rule === 'PRIVILEGE_ESCALATION' && a.subject === 'hina.shah@example.com')).toBe(true);
  });

  it('removes acknowledged alerts from the open list', async () => {
    const first = store.openAlerts()[0];
    store.acknowledge(first.id);
    await settle();
    expect(store.openAlerts().some((a) => a.id === first.id)).toBe(false);
  });

  it('turning off required admin MFA clears that alert', async () => {
    await store.savePolicy({ ...store.policy(), requireMfaForAdmins: false });
    expect(store.alerts().some((a) => a.rule === 'ADMIN_WITHOUT_MFA')).toBe(false);
    expect(store.events()[0].detail).toContain('requireMfaForAdmins: true → false');
  });
});
