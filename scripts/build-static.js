const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');
const outputDir = path.join(projectRoot, 'public');
const candidateEntries = [
  'index.html',
  'favicon.ico',
  'favicon.png',
  'favicon.svg',
  'assets',
  'static',
  'images',
  'styles'
];

function log(message) {
  console.log(`[build-static] ${message}`);
}

function ensureOutputDir() {
  fs.rmSync(outputDir, { recursive: true, force: true });
  fs.mkdirSync(outputDir, { recursive: true });
  log(`Prepared output directory at ${path.relative(projectRoot, outputDir)}`);
}

function copyEntry(entry) {
  const srcPath = path.join(projectRoot, entry);
  if (!fs.existsSync(srcPath)) {
    return false;
  }
  const destPath = path.join(outputDir, entry);
  const stats = fs.statSync(srcPath);
  if (stats.isDirectory()) {
    fs.cpSync(srcPath, destPath, { recursive: true });
  } else {
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
  }
  log(`Copied ${entry}`);
  return true;
}

function main() {
  ensureOutputDir();
  const copied = candidateEntries.filter(copyEntry);
  if (!copied.length) {
    throw new Error('No static assets were copied. Add at least one entry to candidateEntries.');
  }
  log('Static assets ready for deployment.');
}

main();
