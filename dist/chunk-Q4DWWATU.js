import { buildEngine, parsePayloadFile } from './chunk-QUON4ZVC.js';
import { THREAT_CATEGORIES } from './chunk-PTK2JL2Y.js';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

var CATEGORY_FILES = {
  sqli: "sqli.txt",
  xss: "xss.txt",
  lfi: "lfi.txt",
  ssrf: "ssrf.txt",
  "path-traversal": "path-traversal.txt"
};
async function loadPayloadsFromDir(dir, categories = THREAT_CATEGORIES) {
  const patterns = /* @__PURE__ */ new Map();
  const categoryCounts = {
    sqli: 0,
    xss: 0,
    lfi: 0,
    ssrf: 0,
    "path-traversal": 0
  };
  for (const category of categories) {
    const filename = CATEGORY_FILES[category];
    const filepath = join(dir, filename);
    if (!existsSync(filepath)) {
      console.warn(
        `[xpecto-shield] Payload file not found: ${filepath} \u2014 skipping ${category}`
      );
      continue;
    }
    try {
      const content = readFileSync(filepath, "utf-8");
      const categoryPatterns = parsePayloadFile(content, category);
      for (const [pattern, cat] of categoryPatterns) {
        if (!patterns.has(pattern)) {
          patterns.set(pattern, cat);
          categoryCounts[cat]++;
        }
      }
    } catch (error) {
      console.error(
        `[xpecto-shield] Error loading ${filepath}:`,
        error instanceof Error ? error.message : error
      );
    }
  }
  return {
    patterns,
    totalCount: patterns.size,
    categoryCounts
  };
}

// src/core/detection-engine.ts
async function createDetectionEngine(config = {}) {
  const {
    payloadDir,
    categories = THREAT_CATEGORIES,
    confidenceThreshold = 0.7,
    whitelist = []
  } = config;
  let payloadDb;
  if (payloadDir) {
    payloadDb = await loadPayloadsFromDir(payloadDir, categories);
  } else {
    payloadDb = {
      patterns: /* @__PURE__ */ new Map(),
      totalCount: 0,
      categoryCounts: {
        sqli: 0,
        xss: 0,
        lfi: 0,
        ssrf: 0,
        "path-traversal": 0
      }
    };
  }
  const { engine, buildTimeMs } = buildEngine(payloadDb, confidenceThreshold, whitelist);
  console.log(
    `[xpecto-shield] Detection engine built in ${buildTimeMs.toFixed(1)}ms \u2014 ${payloadDb.totalCount} patterns loaded across ${categories.length} categories`
  );
  return engine;
}

export { createDetectionEngine };
//# sourceMappingURL=chunk-Q4DWWATU.js.map
//# sourceMappingURL=chunk-Q4DWWATU.js.map