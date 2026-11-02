// A shared, slowly ticking clock so relative times stay fresh.
class Clock {
  now = $state(Date.now());
  constructor() {
    setInterval(() => (this.now = Date.now()), 30_000);
  }
}
export const clock = new Clock();
