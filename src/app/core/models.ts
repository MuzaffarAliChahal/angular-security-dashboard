export type EventType =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'MFA_FAILED'
  | 'PASSWORD_RESET'
  | 'ROLE_CHANGED'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED'
  | 'POLICY_CHANGED';

export type Role = 'ADMIN' | 'MANAGER' | 'ANALYST' | 'VIEWER';
export const ROLES: Role[] = ['ADMIN', 'MANAGER', 'ANALYST', 'VIEWER'];

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

/** One entry in the append-only audit log. */
export interface AuditEvent {
  id: number;
  at: string;
  type: EventType;
  user: string;
  ip: string;
  country: string;
  detail: string;
  actor?: string;
}

export interface User {
  email: string;
  name: string;
  role: Role;
  mfaEnabled: boolean;
  locked: boolean;
  lastLoginAt: string | null;
}

export interface Alert {
  id: string;
  rule: 'BRUTE_FORCE' | 'CREDENTIAL_STUFFING' | 'IMPOSSIBLE_TRAVEL' | 'ADMIN_WITHOUT_MFA' | 'PRIVILEGE_ESCALATION';
  severity: Severity;
  title: string;
  detail: string;
  at: string;
  subject: string;
  acknowledged: boolean;
}

export interface SecurityPolicy {
  minPasswordLength: number;
  lockoutThreshold: number;
  lockoutMinutes: number;
  sessionTimeoutMinutes: number;
  requireMfaForAdmins: boolean;
}
