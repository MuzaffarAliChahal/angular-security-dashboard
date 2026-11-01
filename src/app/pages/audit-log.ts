import { DatePipe } from '@angular/common';
import { Component, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { EventType } from '../core/models';
import { SecurityStore } from '../core/security-store';

const TYPES: EventType[] = ['LOGIN_SUCCESS', 'LOGIN_FAILED', 'MFA_FAILED', 'PASSWORD_RESET', 'ROLE_CHANGED', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'POLICY_CHANGED'];
const PAGE_SIZE = 20;

@Component({
  selector: 'app-audit-log',
  imports: [DatePipe, FormsModule],
  template: `
    <h1>Audit log</h1>
    <p class="subtitle">Append-only record of authentication and administration events.</p>
    <div class="card">
      <div class="toolbar">
        <input type="search" placeholder="User, IP or country…" [ngModel]="query()" (ngModelChange)="query.set($event)" aria-label="Search" />
        <select [ngModel]="type()" (ngModelChange)="type.set($event)" aria-label="Event type">
          <option value="">All events</option>
          @for (t of types; track t) { <option [value]="t">{{ t }}</option> }
        </select>
        <span class="hint">{{ filtered().length }} events</span>
        <button class="ghost" style="margin-left: auto" (click)="exportCsv()">Export CSV</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Event</th><th>User</th><th>IP</th><th>Country</th><th>Detail</th></tr></thead>
          <tbody>
            @for (e of pageRows(); track e.id) {
              <tr>
                <td>{{ e.at | date: 'MMM d, HH:mm:ss' }}</td>
                <td><span class="badge" [class.ok]="e.type === 'LOGIN_SUCCESS' || e.type === 'ACCOUNT_UNLOCKED'" [class.bad]="e.type === 'LOGIN_FAILED' || e.type === 'ACCOUNT_LOCKED' || e.type === 'MFA_FAILED'" [class.warn]="e.type === 'ROLE_CHANGED' || e.type === 'POLICY_CHANGED'" [class.neutral]="e.type === 'PASSWORD_RESET'">{{ e.type }}</span></td>
                <td>{{ e.user }}</td>
                <td><code>{{ e.ip }}</code></td>
                <td>{{ e.country }}</td>
                <td>{{ e.detail }}@if (e.actor) { <span class="hint"> · by {{ e.actor }}</span> }</td>
              </tr>
            } @empty {
              <tr><td colspan="6" class="empty">No events match.</td></tr>
            }
          </tbody>
        </table>
      </div>
      <div class="toolbar" style="justify-content: flex-end; margin: 12px 0 0">
        <button class="ghost" [disabled]="page() === 0" (click)="page.set(page() - 1)">Previous</button>
        <span class="hint">Page {{ page() + 1 }} of {{ pages() }}</span>
        <button class="ghost" [disabled]="page() + 1 >= pages()" (click)="page.set(page() + 1)">Next</button>
      </div>
    </div>
  `,
})
export class AuditLogPage {
  private readonly store = inject(SecurityStore);
  protected readonly types = TYPES;
  protected readonly query = signal('');
  protected readonly type = signal<EventType | ''>('');
  protected readonly page = signal(0);

  protected readonly filtered = computed(() => {
    const q = this.query().trim().toLowerCase();
    const t = this.type();
    return this.store.events().filter(
      (e) => (!t || e.type === t) && (!q || e.user.includes(q) || e.ip.includes(q) || e.country.toLowerCase().includes(q)),
    );
  });
  protected readonly pages = computed(() => Math.max(1, Math.ceil(this.filtered().length / PAGE_SIZE)));
  protected readonly pageRows = computed(() => this.filtered().slice(this.page() * PAGE_SIZE, (this.page() + 1) * PAGE_SIZE));

  constructor() {
    // Back to the first page whenever the filters change.
    effect(() => {
      this.query();
      this.type();
      this.page.set(0);
    });
  }

  protected exportCsv() {
    const escape = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const rows = this.filtered().map((e) => [e.at, e.type, e.user, e.ip, e.country, e.detail, e.actor ?? ''].map(escape).join(','));
    const blob = new Blob([['time,event,user,ip,country,detail,actor', ...rows].join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'audit-log.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }
}
