import { Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { SecurityStore } from '../core/security-store';

@Component({
  selector: 'app-policy',
  imports: [ReactiveFormsModule],
  template: `
    <h1>Security policy</h1>
    <p class="subtitle">Saving records a POLICY_CHANGED event with exactly what changed.</p>
    <form class="card" style="max-width: 680px" [formGroup]="form" (ngSubmit)="save()">
      <div class="form-grid">
        <div class="field">
          <label for="minPasswordLength">Minimum password length</label>
          <input id="minPasswordLength" type="number" formControlName="minPasswordLength" [class.invalid]="bad('minPasswordLength')" />
          <span [class]="bad('minPasswordLength') ? 'error' : 'hint'">Between 8 and 64 (NIST suggests at least 8, ideally 12+)</span>
        </div>
        <div class="field">
          <label for="lockoutThreshold">Lock after failed attempts</label>
          <input id="lockoutThreshold" type="number" formControlName="lockoutThreshold" [class.invalid]="bad('lockoutThreshold')" />
          <span [class]="bad('lockoutThreshold') ? 'error' : 'hint'">Between 3 and 20</span>
        </div>
        <div class="field">
          <label for="lockoutMinutes">Lockout duration (minutes)</label>
          <input id="lockoutMinutes" type="number" formControlName="lockoutMinutes" [class.invalid]="bad('lockoutMinutes')" />
          <span [class]="bad('lockoutMinutes') ? 'error' : 'hint'">Between 1 and 1440</span>
        </div>
        <div class="field">
          <label for="sessionTimeoutMinutes">Session timeout (minutes)</label>
          <input id="sessionTimeoutMinutes" type="number" formControlName="sessionTimeoutMinutes" [class.invalid]="bad('sessionTimeoutMinutes')" />
          <span [class]="bad('sessionTimeoutMinutes') ? 'error' : 'hint'">Between 5 and 720</span>
        </div>
        <label class="field" style="flex-direction: row; gap: 10px; align-items: center; grid-column: 1 / -1">
          <input type="checkbox" formControlName="requireMfaForAdmins" /> Require MFA for administrators
        </label>
      </div>
      <div class="actions">
        <button class="primary" type="submit" [disabled]="form.invalid || form.pristine || saving()">{{ saving() ? 'Saving…' : 'Save policy' }}</button>
        <button class="ghost" type="button" [disabled]="form.pristine" (click)="reset()">Discard changes</button>
        @if (saved()) { <span class="badge ok" style="align-self: center">Saved</span> }
      </div>
    </form>
  `,
})
export class PolicyPage {
  private readonly store = inject(SecurityStore);
  protected readonly saving = signal(false);
  protected readonly saved = signal(false);

  readonly form = inject(FormBuilder).nonNullable.group({
    minPasswordLength: [12, [Validators.required, Validators.min(8), Validators.max(64)]],
    lockoutThreshold: [5, [Validators.required, Validators.min(3), Validators.max(20)]],
    lockoutMinutes: [15, [Validators.required, Validators.min(1), Validators.max(1440)]],
    sessionTimeoutMinutes: [30, [Validators.required, Validators.min(5), Validators.max(720)]],
    requireMfaForAdmins: [true],
  });

  constructor() {
    this.reset();
  }

  protected bad(name: keyof typeof this.form.controls) {
    const c = this.form.controls[name];
    return c.invalid && (c.dirty || c.touched);
  }

  async save() {
    if (this.form.invalid) return;
    this.saving.set(true);
    await this.store.savePolicy(this.form.getRawValue());
    this.saving.set(false);
    this.saved.set(true);
    this.form.markAsPristine();
    setTimeout(() => this.saved.set(false), 2500);
  }

  reset() {
    this.form.reset(this.store.policy());
  }
}
