import '@testing-library/jest-dom/vitest'
import { afterEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// Recharts' ResponsiveContainer needs real element dimensions, which jsdom
// doesn't provide. Force a fixed size so charts render in tests.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
global.ResizeObserver = ResizeObserverStub

Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 300 })
Object.defineProperty(HTMLElement.prototype, 'offsetWidth', { configurable: true, value: 600 })
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
})
