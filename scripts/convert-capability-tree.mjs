// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(scriptDir, '..');
const sourcePath = path.join(rootDir, 'docs', 'GBT4754-2017_industry_tree.json');
const outputPath = path.join(rootDir, 'docs', 'capability-tree-v1.json');

function toCapabilityNode(node) {
  const capabilityNode = {
    id: `gbt4754-2017.${node.code}`,
    label: node.name,
  };

  if (Array.isArray(node.children) && node.children.length > 0) {
    capabilityNode.children = node.children.map(toCapabilityNode);
  }

  return capabilityNode;
}

async function main() {
  const sourceText = await fs.readFile(sourcePath, 'utf8');
  const source = JSON.parse(sourceText);
  const tree = Array.isArray(source.tree) ? source.tree.map(toCapabilityNode) : [];
  const output = {
    version: 1,
    tree,
  };

  await fs.writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  console.log(`Wrote ${outputPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
