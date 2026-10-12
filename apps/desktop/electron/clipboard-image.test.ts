import assert from 'node:assert/strict'

import { test, vi } from 'vitest'

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01, 0x02])

vi.mock('electron', () => ({
  nativeImage: {
    createFromBuffer: (buf: Buffer) => {
      // Empty input decodes empty; the byte 0xFF simulates an undecodable image.
      if (!buf || buf.length === 0 || buf.includes(0xff)) {
        return { isEmpty: () => true, toPNG: () => Buffer.alloc(0) }
      }

      return { isEmpty: () => false, toPNG: () => PNG }
    }
  }
}))

import { CLIPBOARD_IMAGE_MAX_BYTES, decodeClipboardBufferToPng, pickClipboardPng } from './clipboard-image'

test('decodeClipboardBufferToPng returns PNG for decodable bytes', () => {
  const png = decodeClipboardBufferToPng(Buffer.from([0x01, 0x02, 0x03]))
  assert.ok(png && png.equals(PNG))
})

test('decodeClipboardBufferToPng rejects empty, oversize, and undecodable', () => {
  assert.equal(decodeClipboardBufferToPng(Buffer.alloc(0)), null)
  assert.equal(decodeClipboardBufferToPng(Buffer.alloc(CLIPBOARD_IMAGE_MAX_BYTES + 1)), null)
  assert.equal(decodeClipboardBufferToPng(Buffer.from([0xff, 0x00])), null)
  assert.equal(decodeClipboardBufferToPng('not-a-buffer' as any), null)
})

test('pickClipboardPng decodes first valid image and ignores text types', async () => {
  const pngBytes = Buffer.from([0x01, 0x02])
  const makeBlob = (bytes: Buffer) =>
    new Blob([new Uint8Array(bytes).buffer as ArrayBuffer], { type: 'image/jpeg' })

  const items = [
    { types: ['text/plain'], getType: async () => new Blob(['hi'], { type: 'text/plain' }) },
    {
      types: ['image/jpeg'],
      getType: async () => makeBlob(pngBytes)
    }
  ]

  const png = await pickClipboardPng(async () => items as any)
  assert.ok(png && png.equals(PNG))
})

test('pickClipboardPng skips undecodable images and returns null when none valid', async () => {
  const bad = new Blob([new Uint8Array([0xff]).buffer as ArrayBuffer], { type: 'image/png' })
  const png = await pickClipboardPng(async () => [{ types: ['image/png'], getType: async () => bad } as any])
  assert.equal(png, null)
  assert.equal(await pickClipboardPng(async () => []), null)
  assert.equal(
    await pickClipboardPng(async () => {
      throw new Error('clipboard busy')
    }),
    null
  )
})
