import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { SecurityStore } from '../core/security-store';

const RULE_HELP: Record<string, string> = {
  BRUTE_FORCE: '5 or more failed sign-ins for one account within 10 minutes',
  CREDENTIAL_STUFFING: 'one IP failing against 3 or more accounts within 10 minutes',
  IMPOSSIBLE_TRAVEL: 'successful sign-ins from two countries less than an hour apart',
  ADMIN_WITHOUT_MFA: 'an active administrator without MFA while the policy requires it',
  PRIVILEGE_ESCALATION: 'a role change that grants ADMIN',
};

@Component({
  selector: 'app-alerts',
  imports: [DatePipe],
  template: `
    <h1>Alerts</h1>
    <p class="subtitle">Raised by detection rules over the audit log. Acknowledge an alert once it has been investigated.</p>

    <div class="toolbar">
      <button [class]="show() === 'open' ? 'primary' : 'ghost'" (click)="show.set('open')">Open ({{ store.openAlerts().length }})</button>
      <button [class]="show() === 'all' ? 'primary' : 'ghost'" (click)="show.set('all')">All ({{ store.alerts().length }})</button>
    </div>

    @for (a of list(); track a.id) {
      <div class="card alert" [class.acked]="a.acknowledged">
        <span class="badge" [class.bad]="a.severity === 'HIGH'" [class.warn]="a.severity === 'MEDIUM'" [class.neutral]="a.severity === 'LOW'">{{ a.severity }}</span>
        <div>
          <strong>{{ a.title }}</strong>
          <div>{{ a.detail }}</div>
          <div class="hint">{{ a.rule }}: {{ help[a.rule] }} · {{ a.at | date: 'MMM d, HH:mm' }}</div>
        </div>
        @if (a.acknowledged) {
          <span class="badge ok">Acknowledged</span>
        } @else {
          <button class="ghost" (click)="store.acknowledge(a.id)">Acknowledge</button>
        }
      </div>
    } @empty {
      <div class="card empty">Nothing to review.</div>
    }
  `,
  styles: `
    .alert { display: grid; grid-template-columns: 76px 1fr auto; gap: 14px; align-items: start; margin-bottom: 10px; }
    .alert.acked { opacity: 0.65; }
  `,
})
export class AlertsPage {
  protected readonly store = inject(SecurityStore);
  protected readonly help = RULE_HELP;
  protected readonly show = signal<'open' | 'all'>('open');
  protected readonly list = computed(() => (this.show() === 'open' ? this.store.openAlerts() : this.store.alerts()));
}
