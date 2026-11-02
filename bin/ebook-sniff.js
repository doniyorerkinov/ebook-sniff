#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { sniff } from '../dist/index.js';

const files = process.argv.slice(2);
if (!files.length) {
  console.error('usage: ebook-sniff <file> [file …]');
  process.exit(2);
}
for (const file of files) {
  try {
    const result = await sniff(await readFile(file), basename(file));
    console.log(JSON.stringify({ file, ...result }));
  } catch (e) {
    console.log(JSON.stringify({ file, error: e.message }));
  }
}
