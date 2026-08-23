export interface RectLike {
  left: number
  top: number
  right: number
  bottom: number
}

function clampBp(value: number): number {
  return Math.max(0, Math.min(10_000, Math.round(value)))
}

/**
 * Convert a CSS/screenshot rectangle into viewport-normalized basis points.
 * Content outside the visible viewport is clipped rather than collapsed onto
 * an edge, so semantic geometry always corresponds to the captured raster.
 */
export function clipRectToViewport(
  rect: RectLike,
  viewportWidth: number,
  viewportHeight: number,
): [number, number, number, number] | null {
  const width = Math.max(1, viewportWidth)
  const height = Math.max(1, viewportHeight)
  const left = Math.max(0, Math.min(width, rect.left))
  const top = Math.max(0, Math.min(height, rect.top))
  const right = Math.max(0, Math.min(width, rect.right))
  const bottom = Math.max(0, Math.min(height, rect.bottom))
  if (right <= left || bottom <= top) return null
  return [
    clampBp((left / width) * 10_000),
    clampBp((top / height) * 10_000),
    clampBp((right / width) * 10_000),
    clampBp((bottom / height) * 10_000),
  ]
}
