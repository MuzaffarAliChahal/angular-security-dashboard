import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', title: 'Overview · Security Console', loadComponent: () => import('./pages/overview').then((m) => m.OverviewPage) },
  { path: 'alerts', title: 'Alerts · Security Console', loadComponent: () => import('./pages/alerts').then((m) => m.AlertsPage) },
  { path: 'audit-log', title: 'Audit log · Security Console', loadComponent: () => import('./pages/audit-log').then((m) => m.AuditLogPage) },
  { path: 'users', title: 'Users & roles · Security Console', loadComponent: () => import('./pages/users').then((m) => m.UsersPage) },
  { path: 'policy', title: 'Security policy · Security Console', loadComponent: () => import('./pages/policy').then((m) => m.PolicyPage) },
  { path: '**', redirectTo: '' },
];
