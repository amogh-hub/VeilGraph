declare module 'react' {
  export function useState<T>(initial: T): [T, (value: T | ((previous: T) => T)) => void]
  export function useEffect(effect: () => void | (() => void), dependencies?: unknown[]): void
  export function useMemo<T>(factory: () => T, dependencies: unknown[]): T
  export const StrictMode: (props: { children?: unknown }) => unknown
}

declare module 'react-dom/client' {
  export function createRoot(element: Element): { render(node: unknown): void }
}

declare module 'react/jsx-runtime' {
  export const Fragment: unknown
  export function jsx(type: unknown, props: unknown, key?: unknown): unknown
  export function jsxs(type: unknown, props: unknown, key?: unknown): unknown
}

declare namespace JSX {
  interface IntrinsicElements {
    [elementName: string]: any
  }
}
