import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { sniff, palmDocText } from '../dist/index.js';

const enc = new TextEncoder();
const u8 = (s) => (typeof s === 'string' ? enc.encode(s) : s);

function zip(files, { deflate = false } = {}) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const [name, content, { method, encrypted } = {}] of files) {
    const raw = u8(content);
    const data = deflate && name !== 'mimetype' ? deflateRawSync(raw) : raw;
    const m = method ?? (data === raw ? 0 : 8);
    const flags = 0x800 | (encrypted ? 1 : 0);
    const n = enc.encode(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(m, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(n.length, 26);
    parts.push(local, n, data);
    const dir = Buffer.alloc(46);
    dir.writeUInt32LE(0x02014b50, 0);
    dir.writeUInt16LE(20, 4);
    dir.writeUInt16LE(20, 6);
    dir.writeUInt16LE(flags, 8);
    dir.writeUInt16LE(m, 10);
    dir.writeUInt32LE(data.length, 20);
    dir.writeUInt32LE(raw.length, 24);
    dir.writeUInt16LE(n.length, 28);
    dir.writeUInt32LE(offset, 42);
    central.push(dir, n);
    offset += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...parts, cd, end]));
}

const container = '<?xml version="1.0"?><container xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="OEBPS/content.opf"/></rootfiles></container>';
const opf = (v) => `<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="${v}"></package>`;
const epubFiles = (v, extra = []) => [['mimetype', 'application/epub+zip'], ['META-INF/container.xml', container], ['OEBPS/content.opf', opf(v)], ...extra];
const encryption = (alg) => `<encryption xmlns="urn:oasis:names:tc:opendocument:xmlns:container" xmlns:enc="http://www.w3.org/2001/04/xmlenc#"><enc:EncryptedData><enc:EncryptionMethod Algorithm="${alg}"/></enc:EncryptedData></encryption>`;

function pdb(type, record0, records) {
  const all = [record0, ...records];
  const header = Buffer.alloc(78);
  Buffer.from('book').copy(header, 0);
  Buffer.from(type).copy(header, 60);
  header.writeUInt16BE(all.length, 76);
  const table = Buffer.alloc(all.length * 8 + 2);
  let offset = 78 + table.length;
  all.forEach((r, i) => {
    table.writeUInt32BE(offset, i * 8);
    table.writeUInt32BE(i, i * 8 + 4);
    offset += r.length;
  });
  return new Uint8Array(Buffer.concat([header, table, ...all.map((r) => Buffer.from(r))]));
}

function palmdoc(text, { compress = false, encrypted = false } = {}) {
  const raw = Buffer.from(text, 'latin1');
  const r0 = Buffer.alloc(16);
  r0.writeUInt16BE(compress ? 2 : 1, 0);
  r0.writeUInt32BE(raw.length, 4);
  r0.writeUInt16BE(1, 8);
  r0.writeUInt16BE(4096, 10);
  r0.writeUInt16BE(encrypted ? 1 : 0, 12);
  return pdb('TEXtREAd', r0, [compress ? lz77(raw) : raw]);
}

function lz77(data) {
  const out = [];
  for (let i = 0; i < data.length; ) {
    let best = 0;
    let dist = 0;
    for (let d = 1; d <= Math.min(i, 2047); d++) {
      let n = 0;
      while (n < 10 && i + n < data.length && data[i + n - d] === data[i + n]) n++;
      if (n > best) [best, dist] = [n, d];
    }
    if (best >= 3) {
      const v = 0x8000 | (dist << 3) | (best - 3);
      out.push(v >> 8, v & 0xff);
      i += best;
    } else if (data[i] === 0x20 && data[i + 1] >= 0x40 && data[i + 1] <= 0x7f) {
      out.push(data[i + 1] ^ 0x80);
      i += 2;
    } else out.push(data[i++]);
  }
  return Buffer.from(out);
}

function mobi({ version = 6, kf8 = false, encrypted = false } = {}) {
  const exth = Buffer.alloc(12 + (kf8 ? 12 : 0));
  exth.write('EXTH', 0);
  exth.writeUInt32BE(exth.length, 4);
  exth.writeUInt32BE(kf8 ? 1 : 0, 8);
  if (kf8) {
    exth.writeUInt32BE(121, 12);
    exth.writeUInt32BE(12, 16);
    exth.writeUInt32BE(5, 20);
  }
  const r0 = Buffer.alloc(16 + 232);
  r0.writeUInt16BE(2, 0);
  r0.writeUInt16BE(encrypted ? 2 : 0, 12);
  r0.write('MOBI', 16);
  r0.writeUInt32BE(232, 20);
  r0.writeUInt32BE(version, 36);
  return pdb('BOOKMOBI', Buffer.concat([r0, exth]), [Buffer.from('text')]);
}

const html = '<!-- served by nginx -->\n<!DOCTYPE html><html><head><title>Sign in</title></head><body>Sign in</body></html>';
const fb2 = '<?xml version="1.0" encoding="utf-8"?>\n<FictionBook xmlns="http://www.gribuser.ru/xml/fictionbook/2.0"><body/></FictionBook>';
const acsm = '<fulfillmentToken fulfillmentType="buy" xmlns="http://ns.adobe.com/adept"><resourceItemInfo/></fulfillmentToken>';

const cases = [
  ['EPUB 3', zip(epubFiles('3.0')), 'book.epub', { format: 'epub', drm: null, epubVersion: '3', readable: true }],
  ['EPUB 2, deflated', zip(epubFiles('2.0'), { deflate: true }), 'book.epub', { format: 'epub', drm: null, epubVersion: '2', readable: true }],
  ['EPUB with font obfuscation only', zip(epubFiles('3.0', [['META-INF/encryption.xml', encryption('http://www.idpf.org/2008/embedding')]])), 'a.epub', { format: 'epub', drm: null, epubVersion: '3', readable: true }],
  ['EPUB with encrypted content', zip(epubFiles('3.0', [['META-INF/encryption.xml', encryption('http://www.w3.org/2001/04/xmlenc#aes128-cbc')]])), 'a.epub', { format: 'epub', drm: 'encrypted', epubVersion: '3', readable: false }],
  ['EPUB with Adobe DRM', zip(epubFiles('2.0', [['META-INF/rights.xml', '<rights/>']])), 'a.epub', { format: 'epub', drm: 'adobe', epubVersion: '2', readable: false }],
  ['EPUB with Readium LCP', zip(epubFiles('3.0', [['META-INF/license.lcpl', '{}']])), 'a.epub', { format: 'epub', drm: 'lcp', epubVersion: '3', readable: false }],
  ['MOBI 6', mobi(), 'book.mobi', { format: 'mobi', drm: null, kf8: false, readable: true }],
  ['MOBI with KF8 inside', mobi({ kf8: true }), 'book.mobi', { format: 'mobi', drm: null, kf8: true, readable: true }],
  ['AZW3', mobi({ version: 8 }), 'book.azw3', { format: 'azw3', drm: null, readable: true }],
  ['Kindle DRM', mobi({ encrypted: true }), 'book.azw', { format: 'mobi', drm: 'kindle', kf8: false, readable: false }],
  ['PalmDOC named .mobi', palmdoc('Old book'), 'old.mobi', { format: 'palmdoc', drm: null, readable: true }],
  ['KFX', new Uint8Array([...enc.encode('CONT'), 2, 0, 0, 0]), 'book.kfx', { format: 'kfx', drm: null, readable: false }],
  ['KFX with DRM named .azw3', new Uint8Array([0xea, ...enc.encode('DRMION'), 0xee, 0]), 'book.azw3', { format: 'kfx', drm: 'kindle', named: 'azw3', readable: false }],
  ['Topaz', u8('TPZ0' + '\0'.repeat(20)), 'book.azw', { format: 'topaz', drm: null, named: 'mobi', readable: false }],
  ['FB2', u8(fb2), 'book.fb2', { format: 'fb2', drm: null, readable: true }],
  ['zipped FB2', zip([['book.fb2', fb2]]), 'book.fb2.zip', { format: 'fbz', drm: null, readable: true }],
  ['CBZ', zip([['001.jpg', 'x'], ['002.jpg', 'x'], ['ComicInfo.xml', '<x/>']]), 'comic.cbz', { format: 'cbz', drm: null, readable: true }],
  ['CBR that is a ZIP', zip([['p1.png', 'x']]), 'comic.cbr', { format: 'cbz', drm: null, readable: true }],
  ['RAR named .cbz', new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 1, 0]), 'comic.cbz', { format: 'rar', drm: null, named: 'cbz', readable: false }],
  ['RAR named .cbr', new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0, 0]), 'comic.cbr', { format: 'rar', drm: null, readable: false }],
  ['7-Zip named .cb7', new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]), 'comic.cb7', { format: '7z', drm: null, readable: false }],
  ['comic with a password', zip([['1.jpg', 'x', { encrypted: true }], ['2.jpg', 'x', { encrypted: true }]]), 'c.cbz', { format: 'cbz', drm: null, problem: 'password', readable: false }],
  ['comic compressed with LZMA', zip([['1.png', 'x', { method: 14 }]]), 'c.cbz', { format: 'cbz', drm: null, problem: 'compression', readable: false }],
  ['comic of HEIC pages', zip([['1.heic', 'x'], ['2.heic', 'x']]), 'c.cbz', { format: 'cbz', drm: null, problem: 'images', readable: false }],
  ['PDF named .cbz', u8('%PDF-1.7\n'), 'comic.cbz', { format: 'pdf', drm: null, named: 'cbz', readable: false }],
  ['web page saved as .epub', u8(html), 'book.epub', { format: 'html', drm: null, named: 'epub', readable: true }],
  ['ACSM ticket', u8(acsm), 'URLLink.acsm', { format: 'acsm', drm: null, readable: false }],
  ['DOCX', zip([['[Content_Types].xml', '<Types/>'], ['word/document.xml', '<w:document/>']]), 'a.docx', { format: 'docx', drm: null, readable: false }],
  ['DjVu', u8('AT&TFORM\0\0'), 'a.djvu', { format: 'djvu', drm: null, readable: false }],
  ['UTF-8 text', u8('﻿Глава 1\nТекст.'), 'book.txt', { format: 'text', drm: null, readable: true }],
  ['UTF-16 text', new Uint8Array([0xff, 0xfe, 0x41, 0, 0x42, 0]), 'book.txt', { format: 'text', drm: null, readable: true }],
  ['windows-1251 text', new Uint8Array([0xc3, 0xeb, 0xe0, 0xe2, 0xe0, 0x20, 0x31, 0x0d, 0x0a]), 'book.txt', { format: 'text', drm: null, readable: true }],
  ['binary', new Uint8Array([1, 2, 0, 4, 5]), 'x.bin', { format: 'unknown', drm: null, readable: false }],
  ['empty', new Uint8Array(), 'empty.epub', { format: 'empty', drm: null, named: 'epub', readable: false }],
];

for (const [label, bytes, name, expected] of cases) {
  test(label, async () => assert.deepEqual(await sniff(bytes, name), expected));
}

test('accepts a Blob and an ArrayBuffer', async () => {
  const bytes = zip(epubFiles('3.0'));
  assert.equal((await sniff(new Blob([bytes]))).format, 'epub');
  assert.equal((await sniff(bytes.buffer)).format, 'epub');
});

test('takes the name from a File', async () => {
  assert.equal((await sniff(new File([u8(html)], 'book.epub'))).named, 'epub');
});

test('PalmDOC text, plain and compressed', () => {
  const text = 'The same sentence repeats. The same sentence repeats. The end.';
  assert.equal(Buffer.from(palmDocText(palmdoc(text))).toString('latin1'), text);
  assert.equal(Buffer.from(palmDocText(palmdoc(text, { compress: true }))).toString('latin1'), text);
});

test('PalmDOC refuses what it cannot read', () => {
  assert.throws(() => palmDocText(mobi()), /Not a PalmDOC book/);
  assert.throws(() => palmDocText(palmdoc('x', { encrypted: true })), /encrypted/);
});
