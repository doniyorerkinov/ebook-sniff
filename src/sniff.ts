import { readEntries, readText, type ZipEntry } from './zip.ts';

export type Format =
  | 'epub' | 'mobi' | 'azw3' | 'palmdoc' | 'kfx' | 'topaz' | 'fb2' | 'fbz' | 'cbz'
  | 'pdf' | 'djvu' | 'rar' | '7z' | 'acsm' | 'html' | 'text' | 'rtf' | 'docx' | 'pptx' | 'xlsx' | 'odt' | 'zip'
  | 'empty' | 'unknown';

export type Drm = 'adobe' | 'lcp' | 'kindle' | 'encrypted';

export type Problem = 'password' | 'compression' | 'images';

export interface Sniffed {
  format: Format;
  drm: Drm | null;
  /** EPUB package version, "2" or "3". */
  epubVersion?: string;
  /** A MOBI that also carries a KF8 (AZW3) book. */
  kf8?: boolean;
  /** The format the file name promises, when the bytes say something else. */
  named?: Format;
  /** Why a comic won't open in a browser: a password, compression browsers can't unpack, or TIFF/HEIC pages. */
  problem?: Problem;
  /** An ebook format a reader can open as it is: no DRM, not a container for something else. */
  readable: boolean;
}

export type Input = Blob | ArrayBuffer | Uint8Array;

const READABLE = new Set<Format>(['epub', 'mobi', 'azw3', 'palmdoc', 'fb2', 'fbz', 'cbz', 'html', 'text']);
const OBFUSCATION = new Set(['http://www.idpf.org/2008/embedding', 'http://ns.adobe.com/pdf/enc#RC']);
const IMAGE = /\.(jpe?g|png|gif|webp|avif|bmp|jxl|tiff?|hei[cf])$/i;
const UNSHOWN = /\.(tiff?|hei[cf])$/i;

const BY_NAME: [RegExp, Format[]][] = [
  [/\.epub$/i, ['epub']],
  [/\.(mobi|prc|pdb|azw)$/i, ['mobi', 'azw3', 'palmdoc']],
  [/\.azw3$/i, ['azw3', 'mobi']],
  [/\.kfx$/i, ['kfx']],
  [/\.(fbz|fb2\.zip)$/i, ['fbz']],
  [/\.fb2$/i, ['fb2']],
  [/\.cbz$/i, ['cbz']],
  [/\.cbr$/i, ['cbz', 'rar']],
  [/\.cb7$/i, ['cbz', '7z']],
  [/\.pdf$/i, ['pdf']],
  [/\.djvu?$/i, ['djvu']],
  [/\.acsm$/i, ['acsm']],
  [/\.(x?html?|xht)$/i, ['html']],
  [/\.txt$/i, ['text']],
  [/\.rtf$/i, ['rtf']],
  [/\.docx$/i, ['docx']],
];

async function toBytes(input: Input): Promise<Uint8Array> {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(await input.arrayBuffer());
}

const ascii = (b: Uint8Array, from: number, to: number) => String.fromCharCode(...b.subarray(from, Math.min(to, b.length)));
const starts = (b: Uint8Array, sig: number[]) => sig.every((x, i) => b[i] === x);

function palm(b: Uint8Array): { type: string; record0: number } | null {
  if (b.length < 86) return null;
  const type = ascii(b, 60, 68);
  if (type !== 'BOOKMOBI' && type !== 'TEXtREAd') return null;
  return { type, record0: new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(78) };
}

function mobi(b: Uint8Array, record0: number): Pick<Sniffed, 'format' | 'drm' | 'kf8'> {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const drm: Drm | null = record0 + 14 <= b.length && view.getUint16(record0 + 12) !== 0 ? 'kindle' : null;
  if (ascii(b, record0 + 16, record0 + 20) !== 'MOBI') return { format: 'mobi', drm };
  const headerLength = view.getUint32(record0 + 20);
  const version = view.getUint32(record0 + 36);
  if (version >= 8) return { format: 'azw3', drm };
  let kf8 = false;
  const exth = record0 + 16 + headerLength;
  if (ascii(b, exth, exth + 4) === 'EXTH') {
    const count = view.getUint32(exth + 8);
    for (let i = 0, at = exth + 12; i < count && at + 8 <= b.length; i++) {
      const type = view.getUint32(at);
      if (type === 121 && view.getUint32(at + 8) !== 0xffffffff) kf8 = true;
      at += view.getUint32(at + 4) || 8;
    }
  }
  return { format: 'mobi', drm, kf8 };
}

async function zip(b: Uint8Array): Promise<Pick<Sniffed, 'format' | 'drm' | 'epubVersion' | 'problem'>> {
  const entries = await readEntries(b);
  if (!entries) return { format: 'zip', drm: null };
  const names = new Set(entries.map((e) => e.name));
  const mimetype = (await readText(b, entries, 'mimetype')).trim();
  if (mimetype === 'application/epub+zip' || names.has('META-INF/container.xml')) return epub(b, entries, names);
  if (mimetype.startsWith('application/vnd.oasis.opendocument.text')) return { format: 'odt', drm: null };
  if (names.has('[Content_Types].xml')) {
    const office = [...names].find((n) => /^(word|ppt|xl)\//.test(n))?.split('/')[0];
    if (office) return { format: office === 'word' ? 'docx' : office === 'ppt' ? 'pptx' : 'xlsx', drm: null };
  }
  const files = entries.filter((e) => !e.name.endsWith('/') && !/(^|\/)(__MACOSX\/|\.)/.test(e.name));
  if (files.some((e) => /\.fb2$/i.test(e.name))) return { format: 'fbz', drm: null };
  const images = files.filter((e) => IMAGE.test(e.name));
  if (!images.length || images.length < files.length / 2) return { format: 'zip', drm: null };
  if (images.some((e) => e.encrypted)) return { format: 'cbz', drm: null, problem: 'password' };
  if (images.some((e) => e.method !== 0 && e.method !== 8)) return { format: 'cbz', drm: null, problem: 'compression' };
  if (images.every((e) => UNSHOWN.test(e.name))) return { format: 'cbz', drm: null, problem: 'images' };
  return { format: 'cbz', drm: null };
}

async function epub(b: Uint8Array, entries: ZipEntry[], names: Set<string>): Promise<Pick<Sniffed, 'format' | 'drm' | 'epubVersion'>> {
  let drm: Drm | null = null;
  if (names.has('META-INF/rights.xml')) drm = 'adobe';
  else if (names.has('META-INF/license.lcpl')) drm = 'lcp';
  else if (names.has('META-INF/encryption.xml')) {
    const xml = await readText(b, entries, 'META-INF/encryption.xml');
    const algorithms = [...xml.matchAll(/EncryptionMethod\b[^>]*\bAlgorithm\s*=\s*["']([^"']+)["']/g)].map((m) => m[1]!);
    if (algorithms.some((a) => !OBFUSCATION.has(a))) drm = 'encrypted';
  }
  const opf = (await readText(b, entries, 'META-INF/container.xml')).match(/<rootfile\b[^>]*\bfull-path\s*=\s*["']([^"']+)["']/)?.[1];
  const epubVersion = opf ? (await readText(b, entries, opf)).match(/<package\b[^>]*\bversion\s*=\s*["']\s*(\d)/)?.[1] : undefined;
  return { format: 'epub', drm, ...(epubVersion ? { epubVersion } : {}) };
}

function text(b: Uint8Array): Format {
  const utf16 = starts(b, [0xff, 0xfe]) || starts(b, [0xfe, 0xff]);
  const head = utf16
    ? new TextDecoder(b[0] === 0xff ? 'utf-16le' : 'utf-16be').decode(b.subarray(0, 4096))
    : new TextDecoder('latin1').decode(b.subarray(0, 4096));
  const start = head
    .replace(/^(\u{FEFF}|\xEF\xBB\xBF)/u, '')
    .replace(/^(\s|<\?xml[^>]*>|<!--[\s\S]*?-->)+/, '')
    .toLowerCase();
  if (start.startsWith('<fictionbook')) return 'fb2';
  if (/<fulfillmenttoken\b/.test(head.toLowerCase()) && /ns\.adobe\.com\/adept/.test(head)) return 'acsm';
  if (/^<(!doctype html|html[\s>]|head[\s>]|meta[\s>]|body[\s>]|title[\s>]|script[\s>])/.test(start)) return 'html';
  if (utf16) return 'text';
  const sample = b.subarray(0, 4096);
  let control = 0;
  for (const c of sample) {
    if (c === 0) return 'unknown';
    if (c < 0x09 || (c > 0x0d && c < 0x20)) control++;
  }
  return control <= sample.length * 0.02 ? 'text' : 'unknown';
}

async function detect(b: Uint8Array): Promise<Omit<Sniffed, 'readable' | 'named'>> {
  if (!b.length) return { format: 'empty', drm: null };
  if (starts(b, [0x25, 0x50, 0x44, 0x46, 0x2d])) return { format: 'pdf', drm: null };
  if (ascii(b, 0, 8) === 'AT&TFORM') return { format: 'djvu', drm: null };
  if (starts(b, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return { format: 'rar', drm: null };
  if (starts(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { format: '7z', drm: null };
  if (ascii(b, 0, 5) === '{\\rtf') return { format: 'rtf', drm: null };
  if (ascii(b, 0, 3) === 'TPZ') return { format: 'topaz', drm: null };
  if (ascii(b, 0, 4) === 'CONT') return { format: 'kfx', drm: null };
  if (b[0] === 0xea && ascii(b, 1, 7) === 'DRMION') return { format: 'kfx', drm: 'kindle' };
  const p = palm(b);
  if (p?.type === 'BOOKMOBI') return mobi(b, p.record0);
  if (p?.type === 'TEXtREAd') {
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
    return { format: 'palmdoc', drm: p.record0 + 14 <= b.length && view.getUint16(p.record0 + 12) !== 0 ? 'kindle' : null };
  }
  if (starts(b, [0x50, 0x4b, 0x03, 0x04]) || starts(b, [0x50, 0x4b, 0x05, 0x06])) return zip(b);
  return { format: text(b), drm: null };
}

/** What an ebook file really is, from its bytes. Pass the file name to learn when it promises something else. */
export async function sniff(input: Input, name = typeof File !== 'undefined' && input instanceof File ? input.name : ''): Promise<Sniffed> {
  const found = await detect(await toBytes(input));
  const promised = BY_NAME.find(([re]) => re.test(name))?.[1];
  const named = promised && !promised.includes(found.format) ? promised[0] : undefined;
  return { ...found, ...(named ? { named } : {}), readable: READABLE.has(found.format) && !found.drm && !found.problem };
}
