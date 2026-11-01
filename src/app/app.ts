import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { SecurityApi } from './core/security-api';
import { CURRENT_ADMIN, SecurityStore } from './core/security-store';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand"><span class="brand-mark">S</span> Security Console</div>
        @for (item of nav; track item.path) {
          <a class="nav-link" [routerLink]="item.path" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: item.path === '/' }">
            {{ item.label }}
            @if (item.path === '/alerts' && store.openAlerts().length) { <span class="count">{{ store.openAlerts().length }}</span> }
          </a>
        }
        <div class="sidebar-foot">Signed in as {{ admin }}<br />Angular 21 · signals</div>
      </aside>
      <main class="main">
        @if (demo) {
          <div class="demo-banner">Demo mode: 24 hours of generated audit events, including a brute-force attack, credential stuffing and impossible travel for the detection rules to find.</div>
        }
        @if (store.error()) {
          <div class="card empty">Could not load data: {{ store.error() }}</div>
        } @else if (store.loaded()) {
          <router-outlet />
        } @else {
          <div class="card empty">Loading audit data…</div>
        }
      </main>
    </div>
  `,
  styles: `.count { float: right; background: var(--bad); color: #fff; border-radius: 999px; font-size: 11px; padding: 1px 7px; font-weight: 700; }`,
})
export class App {
  protected readonly store = inject(SecurityStore);
  protected readonly demo = inject(SecurityApi).mode === 'demo';
  protected readonly admin = CURRENT_ADMIN;
  protected readonly nav = [
    { path: '/', label: 'Overview' },
    { path: '/alerts', label: 'Alerts' },
    { path: '/audit-log', label: 'Audit log' },
    { path: '/users', label: 'Users & roles' },
    { path: '/policy', label: 'Security policy' },
  ];

  constructor() {
    this.store.load();
  }
}
