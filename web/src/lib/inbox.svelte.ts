import { api } from './api';

// Transfers waiting for a decision of the signed-in user, shown next to the
// Teams section and its Transfers tab, and whether transfers need a second
// approver (unknown until the team list is read).
class Inbox {
  count = $state(0);
  secondApprover = $state<boolean | undefined>(undefined);
  private loading: Promise<void> | null = null;
  private mode: Promise<void> | null = null;

  /** Reads the approval mode once. */
  loadMode(): Promise<void> {
    this.mode ??= api
      .teams()
      .then((l) => {
        this.secondApprover = l.require_second_approver;
      })
      .catch(() => {
        this.mode = null;
      });
    return this.mode;
  }

  load(force = false): Promise<void> {
    if (this.loading && !force) return this.loading;
    this.loading = api
      .transfers({ status: 'proposed', limit: 100 })
      .then((p) => {
        this.count = p.transfers.filter((t) => t.can_decide).length;
      })
      .catch(() => {
        this.count = 0;
      });
    return this.loading;
  }
}

export const inbox = new Inbox();
