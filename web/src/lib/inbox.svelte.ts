import { api } from './api';

// Transfers waiting for a decision of the signed-in user, shown next to the
// Teams section and its Transfers tab.
class Inbox {
  count = $state(0);
  private loading: Promise<void> | null = null;

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
