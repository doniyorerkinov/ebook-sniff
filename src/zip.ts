export interface ZipEntry {
  name: string;
  method: number;
  encrypted: boolean;
  compressedSize: number;
  size: number;
  offset: number;
}

const u16 = (v: DataView, at: number) => v.getUint16(at, true);
const u32 = (v: DataView, at: number) => v.getUint32(at, true);

export async function readEntries(bytes: Uint8Array): Promise<ZipEntry[] | null> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const min = Math.max(0, bytes.length - 65557);
  let end = -1;
  for (let i = bytes.length - 22; i >= min; i--) {
    if (u32(view, i) === 0x06054b50) {
      end = i;
      break;
    }
  }
  if (end < 0) return null;
  const count = u16(view, end + 10);
  let at = u32(view, end + 16);
  const entries: ZipEntry[] = [];
  const utf8 = new TextDecoder();
  const latin1 = new TextDecoder('latin1');
  for (let n = 0; n < count; n++) {
    if (at + 46 > bytes.length || u32(view, at) !== 0x02014b50) return entries.length ? entries : null;
    const flags = u16(view, at + 8);
    const nameLength = u16(view, at + 28);
    const extra = u16(view, at + 30);
    const comment = u16(view, at + 32);
    const raw = bytes.subarray(at + 46, at + 46 + nameLength);
    entries.push({
      name: (flags & 0x800 ? utf8 : latin1).decode(raw),
      method: u16(view, at + 10),
      encrypted: (flags & 1) === 1,
      compressedSize: u32(view, at + 20),
      size: u32(view, at + 24),
      offset: u32(view, at + 42),
    });
    at += 46 + nameLength + extra + comment;
  }
  return entries;
}

export async function readEntry(bytes: Uint8Array, entry: ZipEntry): Promise<Uint8Array | null> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const at = entry.offset;
  if (at + 30 > bytes.length || u32(view, at) !== 0x04034b50) return null;
  const start = at + 30 + u16(view, at + 26) + u16(view, at + 28);
  const data = bytes.subarray(start, start + entry.compressedSize);
  if (entry.method === 0) return data;
  if (entry.method !== 8) return null;
  try {
    const stream = new Blob([data.slice()]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

export async function readText(bytes: Uint8Array, entries: ZipEntry[], name: string): Promise<string> {
  const entry = entries.find((e) => e.name === name);
  const data = entry && (await readEntry(bytes, entry));
  return data ? new TextDecoder().decode(data) : '';
}
