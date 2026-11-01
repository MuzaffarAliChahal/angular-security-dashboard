import { DatePipe } from '@angular/common';
import { Component, inject } from '@angular/core';
import { ROLES, Role } from '../core/models';
import { CURRENT_ADMIN, SecurityStore } from '../core/security-store';

@Component({
  selector: 'app-users',
  imports: [DatePipe],
  template: `
    <h1>Users & roles</h1>
    <p class="subtitle">Role changes, locks and unlocks are written to the audit log. You can't change your own role or lock yourself out.</p>
    <div class="card table-wrap">
      <table>
        <thead><tr><th>User</th><th>Role</th><th>MFA</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead>
        <tbody>
          @for (u of store.users(); track u.email) {
            <tr>
              <td><strong>{{ u.name }}</strong><div class="hint">{{ u.email }}</div></td>
              <td>
                <select [value]="u.role" [disabled]="u.email === me" (change)="changeRole(u.email, $event)" [attr.aria-label]="'Role for ' + u.name">
                  @for (r of roles; track r) { <option [value]="r">{{ r }}</option> }
                </select>
              </td>
              <td>@if (u.mfaEnabled) { <span class="badge ok">On</span> } @else { <span class="badge warn">Off</span> }</td>
              <td>@if (u.locked) { <span class="badge bad">Locked</span> } @else { <span class="badge neutral">Active</span> }</td>
              <td>{{ u.lastLoginAt ? (u.lastLoginAt | date: 'MMM d, HH:mm') : '—' }}</td>
              <td class="num">
                @if (u.email !== me) {
                  <button class="ghost" (click)="store.setLocked(u.email, !u.locked)">{{ u.locked ? 'Unlock' : 'Lock' }}</button>
                }
              </td>
            </tr>
          }
        </tbody>
      </table>
    </div>
  `,
})
export class UsersPage {
  protected readonly store = inject(SecurityStore);
  protected readonly roles = ROLES;
  protected readonly me = CURRENT_ADMIN;

  protected changeRole(email: string, event: Event) {
    this.store.changeRole(email, (event.target as HTMLSelectElement).value as Role);
  }
}
