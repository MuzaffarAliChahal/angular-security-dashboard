import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, computed, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { SecurityStore } from '../core/security-store';

@Component({
  selector: 'app-overview',
  imports: [DatePipe, DecimalPipe, RouterLink],
  template: `
    <h1>Security overview</h1>
    <p class="subtitle">Last 24 hours of authentication activity and what the detection rules found.</p>

    <div class="grid kpis">
      <div class="card"><div class="kpi-label">Sign-in attempts</div><div class="kpi-value">{{ store.signIns().length }}</div><div class="kpi-note">last 24 hours</div></div>
      <div class="card"><div class="kpi-label">Failed sign-ins</div><div class="kpi-value">{{ store.failedRate() | number: '1.1-1' }}%</div><div class="kpi-note">of all attempts</div></div>
      <div class="card"><div class="kpi-label">Open alerts</div><div class="kpi-value" [style.color]="high() ? 'var(--bad)' : null">{{ store.openAlerts().length }}</div><div class="kpi-note">{{ high() }} high severity</div></div>
      <div class="card"><div class="kpi-label">MFA coverage</div><div class="kpi-value">{{ store.mfaCoverage() | number: '1.0-0' }}%</div><div class="kpi-note">of {{ store.users().length }} users</div></div>
    </div>

    <div class="card" style="margin-bottom: 16px">
      <div class="toolbar" style="justify-content: space-between">
        <h2 style="margin: 0">Sign-ins per hour</h2>
        <span class="hint"><span class="legend ok"></span>successful <span class="legend bad"></span>failed</span>
      </div>
      <div class="chart" role="img" aria-label="Successful and failed sign-ins per hour">
        @for (b of store.hourly(); track b.hoursAgo) {
          <div class="col" [title]="b.label + ':00 · ' + b.ok + ' ok, ' + b.failed + ' failed'">
            <div class="stack">
              <div class="seg bad" [style.height.%]="(100 * b.failed) / max()"></div>
              <div class="seg ok" [style.height.%]="(100 * b.ok) / max()"></div>
            </div>
            <span class="tick">{{ b.label }}</span>
          </div>
        }
      </div>
    </div>

    <div class="grid two-col" style="align-items: start">
      <div class="card">
        <div class="toolbar" style="justify-content: space-between">
          <h2 style="margin: 0">Open alerts</h2>
          <a routerLink="/alerts">All alerts →</a>
        </div>
        @for (a of store.openAlerts().slice(0, 4); track a.id) {
          <div class="alert-row">
            <span class="badge" [class.bad]="a.severity === 'HIGH'" [class.warn]="a.severity === 'MEDIUM'" [class.neutral]="a.severity === 'LOW'">{{ a.severity }}</span>
            <div><strong>{{ a.title }}</strong><div class="hint">{{ a.detail }} · {{ a.at | date: 'HH:mm' }}</div></div>
          </div>
        } @empty {
          <p class="hint">No open alerts.</p>
        }
      </div>
      <div class="card">
        <h2>Top failing IP addresses</h2>
        <table>
          <thead><tr><th>IP</th><th>Country</th><th class="num">Failures</th><th class="num">Accounts</th></tr></thead>
          <tbody>
            @for (r of store.topFailingIps(); track r.ip) {
              <tr><td><code>{{ r.ip }}</code></td><td>{{ r.country }}</td><td class="num">{{ r.count }}</td><td class="num">{{ r.accounts }}</td></tr>
            }
          </tbody>
        </table>
      </div>
    </div>
  `,
  styles: `
    .chart { display: grid; grid-template-columns: repeat(24, 1fr); gap: 4px; height: 180px; align-items: end; }
    .col { display: flex; flex-direction: column; align-items: center; height: 100%; gap: 4px; }
    .stack { flex: 1; width: 100%; display: flex; flex-direction: column; justify-content: flex-end; }
    .seg { width: 100%; }
    .seg.ok { background: #5b8def; border-radius: 3px 3px 0 0; }
    .seg.bad { background: var(--bad); }
    .tick { font-size: 10px; color: var(--muted); }
    .legend { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin: 0 4px 0 10px; vertical-align: -1px; }
    .legend.ok { background: #5b8def; } .legend.bad { background: var(--bad); }
    .alert-row { display: grid; grid-template-columns: 72px 1fr; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--border); align-items: start; }
  `,
})
export class OverviewPage {
  protected readonly store = inject(SecurityStore);
  protected readonly high = computed(() => this.store.openAlerts().filter((a) => a.severity === 'HIGH').length);
  protected readonly max = computed(() => Math.max(1, ...this.store.hourly().map((b) => b.ok + b.failed)));
}
