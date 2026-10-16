// React Flow needs ResizeObserver, which jsdom lacks.
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
