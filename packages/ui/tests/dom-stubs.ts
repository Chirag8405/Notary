// React Flow needs ResizeObserver, which jsdom lacks (same stub as apps/web/tests/setup.ts).
class ResizeObserverStub {
  observe(): void {
    // no-op
  }
  unobserve(): void {
    // no-op
  }
  disconnect(): void {
    // no-op
  }
}
globalThis.ResizeObserver = ResizeObserverStub;
