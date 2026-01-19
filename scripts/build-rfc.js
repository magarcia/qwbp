#!/usr/bin/env node

/**
 * Build RFC-style specification from SPECIFICATION.md
 * 
 * This script:
 * 1. Prepends TOML front matter required by mmark
 * 2. Runs mmark to generate RFC XML
 * 3. Fixes any XML issues
 * 4. Runs xml2rfc to generate HTML and TXT
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');

// TOML front matter for mmark
const frontMatter = `%%%
title = "QR-WebRTC Bootstrap Protocol (QWBP)"
abbrev = "QWBP"
docname = "draft-qwbp-spec-01"
category = "info"
ipr = "none"
submissiontype = "independent"
area = "Internet"
workgroup = "Independent"
keyword = ["WebRTC", "QR Code", "Signaling", "P2P"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-qwbp-spec-01"
stream = "independent"
status = "informational"

[[author]]
initials = "M."
surname = "Garcia Monterde"
fullname = "Martin Garcia Monterde"
organization = "Independent"
  [author.address]
  email = "martin@magarcia.io"

[pi]
toc = "yes"
sortrefs = "yes"
symrefs = "yes"
%%%

`;

// Ensure output directory exists
const outputDir = join(rootDir, 'build');
mkdirSync(outputDir, { recursive: true });

// Read the specification
const specPath = join(rootDir, 'SPECIFICATION.md');
let specContent = readFileSync(specPath, 'utf-8');

// Find where the actual content starts (after the initial metadata)
const lines = specContent.split('\n');
let startIndex = 0;

for (let i = 0; i < lines.length; i++) {
  const line = lines[i].trim();
  if (line === '## Abstract') {
    startIndex = i;
    break;
  }
}

// Get content from the Abstract section onwards
let mainContent = lines.slice(startIndex).join('\n');

// Remove the manual Table of Contents section (mmark generates its own)
mainContent = mainContent.replace(
  /## Table of Contents\n\n[\s\S]*?\n---\n/,
  ''
);

// Remove horizontal rules (---) as they can cause issues
mainContent = mainContent.replace(/\n---\n/g, '\n\n');

// Fix section numbering - handle patterns like "## 1. Title", "### 1.1 Title"
mainContent = mainContent.replace(/^(#{1,6})\s*[\d.]+\s+/gm, '$1 ');

// Handle "Appendix A:" style headers
mainContent = mainContent.replace(/^(#{1,6})\s*Appendix\s+([A-Z])[:.]?\s*/gm, '$1 Appendix $2: ');

// Convert the Abstract to use mmark's special .# syntax
mainContent = mainContent.replace(
  /^## Abstract\n\n([\s\S]*?)(?=\n## )/,
  (match, abstractContent) => {
    return `.# Abstract\n\n${abstractContent.trim()}\n\n{mainmatter}\n\n`;
  }
);

// Remove "Document History" section and everything after it
mainContent = mainContent.replace(/\n## Document History[\s\S]*$/, '\n');

// Remove trailing "_End of Specification_" marker
mainContent = mainContent.replace(/\n_End of Specification_\s*$/, '\n');

// Combine front matter with spec content
const combined = frontMatter + mainContent;

// Write the combined file
const mdPath = join(outputDir, 'spec.md');
writeFileSync(mdPath, combined);
console.log(`✓ Generated ${mdPath}`);

// Check if mmark is available
try {
  execSync('which mmark', { stdio: 'pipe' });
} catch {
  console.log('⚠ mmark not found - skipping XML/HTML/TXT generation');
  console.log('  Install mmark to generate RFC outputs locally');
  process.exit(0);
}

// Run mmark to generate XML
const xmlPath = join(outputDir, 'spec.xml');
try {
  execSync(`mmark "${mdPath}" > "${xmlPath}"`, { 
    stdio: 'pipe',
    cwd: rootDir 
  });
  console.log(`✓ Generated ${xmlPath}`);
} catch (error) {
  console.error('✗ mmark failed:', error.message);
  process.exit(1);
}

// Fix XML - count section tags and fix any mismatch
let xmlContent = readFileSync(xmlPath, 'utf-8');

// Count opening and closing section tags
const openCount = (xmlContent.match(/<section/g) || []).length;
const closeCount = (xmlContent.match(/<\/section>/g) || []).length;

if (closeCount > openCount) {
  console.log(`  Fixing XML: ${closeCount - openCount} extra </section> tag(s)`);
  
  // Remove extra closing tags from the end (before </middle>)
  for (let i = 0; i < closeCount - openCount; i++) {
    xmlContent = xmlContent.replace(
      /(<\/section>\s*)(<\/middle>)/,
      '$2'
    );
  }
  
  writeFileSync(xmlPath, xmlContent);
  console.log(`✓ Fixed ${xmlPath}`);
}

// Check if xml2rfc is available
try {
  execSync('which xml2rfc', { stdio: 'pipe' });
} catch {
  console.log('⚠ xml2rfc not found - skipping HTML/TXT generation');
  console.log('  Install xml2rfc (pip install xml2rfc) to generate outputs locally');
  process.exit(0);
}

// Run xml2rfc to generate HTML and TXT
const demoDir = join(rootDir, 'demo');
const htmlPath = join(demoDir, 'spec.html');
const txtPath = join(demoDir, 'spec.txt');

try {
  execSync(`xml2rfc --html "${xmlPath}" -o "${htmlPath}"`, { 
    stdio: 'pipe',
    cwd: rootDir 
  });
  console.log(`✓ Generated ${htmlPath}`);
} catch (error) {
  console.error('✗ xml2rfc HTML failed:', error.stderr?.toString() || error.message);
  process.exit(1);
}

try {
  execSync(`xml2rfc --text "${xmlPath}" -o "${txtPath}"`, { 
    stdio: 'pipe',
    cwd: rootDir 
  });
  console.log(`✓ Generated ${txtPath}`);
} catch (error) {
  console.error('✗ xml2rfc TXT failed:', error.stderr?.toString() || error.message);
  process.exit(1);
}

console.log('\n✓ RFC specification build complete!');
