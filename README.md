# ebook-sniff

Tell what an ebook file really is from its bytes, and why it won't open.

A file called `book.epub` can be a sign-in page saved by a broken download. `comic.cbz` can be a RAR archive or a PDF.
`book.azw3` can be a KFX file only Kindle apps read. `ebook-sniff` looks inside and says so — no dependencies, in the
browser and in Node 20+.

```sh
npm install ebook-sniff
```

```js
import { sniff } from 'ebook-sniff';

input.addEventListener('change', async () => {
  const result = await sniff(input.files[0]);
  // { format: 'html', drm: null, named: 'epub', readable: true }
});
```

```js
import { readFile } from 'node:fs/promises';
import { sniff } from 'ebook-sniff';

await sniff(await readFile('Dune.azw'), 'Dune.azw');
// { format: 'mobi', drm: 'kindle', kf8: true, readable: false }
```

```sh
npx ebook-sniff books/*
```

## Result

| Field | |
|---|---|
| `format` | `epub` `mobi` `azw3` `palmdoc` `kfx` `topaz` `fb2` `fbz` `cbz` `pdf` `djvu` `rar` `7z` `acsm` `html` `text` `rtf` `docx` `pptx` `xlsx` `odt` `zip` `empty` `unknown` |
| `drm` | `adobe` (ADEPT), `lcp` (Readium LCP), `kindle`, `encrypted` (other EPUB encryption), or `null`. Font obfuscation is not DRM. |
| `epubVersion` | `"2"` or `"3"` |
| `kf8` | a MOBI that also carries a KF8 (AZW3) book |
| `named` | the format the file name promises, when the bytes say something else |
| `problem` | a comic that won't show in a browser: `password`, `compression` (LZMA, BZip2, Deflate64, Zstandard), `images` (TIFF, HEIC) |
| `readable` | an ebook format a reader can open as it is |

`sniff(input, name?)` takes a `File`, `Blob`, `ArrayBuffer` or `Uint8Array`; a `File` brings its own name.

## PalmDOC

Old Palm books (`.pdb`, `.prc`, and some files named `.mobi`) are plain text in records. `palmDocText` unpacks them;
the bytes are in the book's own encoding, usually windows-1252 or windows-1251.

```js
import { palmDocText } from 'ebook-sniff';

const text = new TextDecoder('windows-1252').decode(palmDocText(bytes));
```

## Used in

[Readkave](https://readkave.com) — a Chrome extension that reads EPUB, MOBI, AZW3, FB2, CBZ and TXT books in the
browser, and says why when a book won't open.

## License

MIT
