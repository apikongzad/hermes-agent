// Clipboard image validation for `hermes:saveClipboardImage`.
//
// The W3C `clipboard.read()` path hands us an arbitrary `image/*` Blob (PNG,
// JPEG, GIF, BMP, WebP, ...). Saving those raw bytes as `.png` trusts the
// clipboard and mislabels non-PNG bytes. Decode through Electron's own
// `nativeImage` (same decoder `app-icon.ts` uses) and re-encode via `toPNG()`:
// only a non-empty decode that re-encodes to a PNG signature within the size
// budget is saved. Anything else (empty, oversize, undecodable, toPNG
// failure) is null so the caller falls through to the WSL fallback / empty.

import { nativeImage } from 'electron'

export const CLIPBOARD_IMAGE_MAX_BYTES = 32 * 1024 * 1024

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]

function hasPngSignature(buf: Buffer): boolean {
  if (buf.length < PNG_SIGNATURE.length) {
    return false
  }

  return PNG_SIGNATURE.every((byte, i) => buf[i] === byte)
}

export function decodeClipboardBufferToPng(buffer: Buffer): Buffer | null {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0 || buffer.length > CLIPBOARD_IMAGE_MAX_BYTES) {
    return null
  }

  try {
    const image = nativeImage.createFromBuffer(buffer)

    if (!image || image.isEmpty()) {
      return null
    }

    const png = image.toPNG()

    if (!png || png.length === 0 || png.length > CLIPBOARD_IMAGE_MAX_BYTES) {
      return null
    }

    if (!hasPngSignature(png)) {
      return null
    }

    return png
  } catch {
    return null
  }
}

export type ClipboardReadItem = {
  types: string[]
  getType: (type: string) => Promise<unknown>
}

export async function pickClipboardPng(
  read: () => Promise<ClipboardReadItem[]>
): Promise<Buffer | null> {
  let items: ClipboardReadItem[]

  try {
    items = await read()
  } catch {
    return null
  }

  if (!Array.isArray(items)) {
    return null
  }

  for (const item of items) {
    const types = Array.isArray(item?.types) ? item.types : []

    for (const type of types) {
      const lower = String(type || '').toLowerCase()

      if (lower !== 'image/png' && !lower.startsWith('image/')) {
        continue
      }

      try {
        const blob = await item.getType(type)

        if (!(blob instanceof Blob)) {
          continue
        }

        const raw = Buffer.from(await blob.arrayBuffer())
        const png = decodeClipboardBufferToPng(raw)

        if (png) {
          return png
        }
      } catch {
        continue
      }
    }
  }

  return null
}
