class Bytes {
  buf: Uint8Array<ArrayBuffer>;
  length = 0;
  constructor(size: number) {
    this.buf = new Uint8Array(Math.max(4096, size));
  }
  push(byte: number) {
    if (this.length === this.buf.length) {
      const bigger = new Uint8Array(this.buf.length * 2);
      bigger.set(this.buf);
      this.buf = bigger;
    }
    this.buf[this.length++] = byte;
  }
}

function decompress(input: Uint8Array, out: Bytes) {
  for (let i = 0; i < input.length; ) {
    const c = input[i++]!;
    if (c === 0 || (c >= 0x09 && c <= 0x7f)) out.push(c);
    else if (c <= 0x08) for (let k = 0; k < c && i < input.length; k++) out.push(input[i++]!);
    else if (c >= 0xc0) {
      out.push(0x20);
      out.push(c ^ 0x80);
    } else {
      const pair = ((c << 8) | (input[i++] ?? 0)) & 0x3fff;
      const distance = pair >> 3;
      const start = out.length - distance;
      if (distance === 0 || start < 0) continue;
      for (let k = 0; k < (pair & 7) + 3; k++) out.push(out.buf[start + k]!);
    }
  }
}

/** The text of a PalmDOC book (TEXtREAd), uncompressed or with PalmDOC compression. Bytes in the book's encoding. */
export function palmDocText(bytes: Uint8Array): Uint8Array {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 86 || new TextDecoder('latin1').decode(bytes.subarray(60, 68)) !== 'TEXtREAd') throw new Error('Not a PalmDOC book');
  const count = view.getUint16(76);
  const offset = (i: number) => (i < count ? view.getUint32(78 + i * 8) : bytes.length);
  const record0 = offset(0);
  const compression = view.getUint16(record0);
  if (view.getUint16(record0 + 12) !== 0) throw new Error('The book is encrypted');
  const out = new Bytes(view.getUint32(record0 + 4));
  const records = view.getUint16(record0 + 8);
  for (let i = 1; i <= records && i < count; i++) {
    const record = bytes.subarray(offset(i), offset(i + 1));
    if (compression === 2) decompress(record, out);
    else for (const b of record) out.push(b);
  }
  return out.buf.slice(0, out.length);
}
