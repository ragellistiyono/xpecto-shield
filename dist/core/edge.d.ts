import { T as ThreatCategory, b as AhoCorasickMatch, e as DetectionEngineConfig, d as DetectionEngine, j as PayloadDatabase } from '../types-wAOtwm6s.js';
export { A as AIConfig, a as AIReport, c as AppwriteConfig, B as BlockedIP, C as CATEGORY_LABELS, D as DateRange, f as DetectionResult, E as EngineStats, I as IncidentFilters, g as IncidentLog, h as IncidentStats, P as PaginatedResult, i as PaginationOptions, S as ShieldAPIConfig, k as ShieldAppwriteClient, l as ShieldMiddlewareConfig, n as THREAT_CATEGORIES, m as ThreatMatch } from '../types-wAOtwm6s.js';

/**
 * Aho-Corasick Automaton for high-performance multi-pattern string matching.
 *
 * Usage:
 * ```typescript
 * const ac = new AhoCorasickAutomaton()
 * ac.addPattern("SELECT", "sqli")
 * ac.addPattern("<script>", "xss")
 * ac.build()
 * const matches = ac.search("try SELECT * FROM <script>alert(1)</script>")
 * ```
 */
declare class AhoCorasickAutomaton {
    private root;
    private patternCount;
    private isBuilt;
    constructor();
    /**
     * Add a pattern to the automaton.
     * Must be called BEFORE build().
     *
     * @param pattern - The pattern string to match against
     * @param category - The threat category this pattern belongs to
     */
    addPattern(pattern: string, category: ThreatCategory): void;
    /**
     * Build the failure links using BFS.
     * Must be called after all patterns are added and before search().
     */
    build(): void;
    /**
     * Search the input text for all pattern matches in a single pass.
     *
     * @param input - The text to scan
     * @returns Array of all matches found, including overlapping matches
     */
    search(input: string): AhoCorasickMatch[];
    /**
     * Reset the automaton — clears all patterns and failure links.
     * Call this if you need to rebuild with different patterns.
     */
    reset(): void;
    /**
     * Get the total number of patterns added to the automaton.
     */
    getPatternCount(): number;
    /**
     * Check if the automaton has been built and is ready for searching.
     */
    getIsBuilt(): boolean;
    /** Create a new trie node */
    private createNode;
}

/**
 * Create a detection engine from pre-compiled payload data.
 * Used for serverless/Edge environments where fs access is unavailable.
 *
 * @param compiledData - Pre-compiled patterns as { pattern: category }
 * @param config - Additional engine configuration
 * @returns DetectionEngine instance
 */
declare function createDetectionEngineFromCompiled(compiledData: Record<string, ThreatCategory>, config?: Omit<DetectionEngineConfig, 'payloadDir'>): Promise<DetectionEngine>;

/**
 * Main decoding pipeline — applies all decoding layers sequentially.
 * This is the primary function used by the detection engine before scanning.
 *
 * @param raw - The raw input string from the HTTP request
 * @returns The fully decoded and normalized string
 */
declare function decodeInput(raw: string): string;

/**
 * Parse a single payload file's content into a Map of patterns.
 *
 * File format:
 * - One payload per line
 * - Lines starting with # are comments
 * - Empty lines are skipped
 * - Lines ending with : are category headers (e.g., "MySQL Blind (Time Based):")
 * - All patterns are lowercased for case-insensitive matching
 *
 * @param content - Raw file content
 * @param category - The threat category for these patterns
 * @returns Map of normalized pattern → category
 */
declare function parsePayloadFile(content: string, category: ThreatCategory): Map<string, ThreatCategory>;
/**
 * Load payloads from pre-compiled data (for serverless environments
 * where fs access may not be available at runtime).
 *
 * @param compiledData - Pre-compiled patterns as a plain object { pattern: category }
 * @returns PayloadDatabase
 */
declare function loadPayloadsFromCompiled(compiledData: Record<string, ThreatCategory>): PayloadDatabase;

export { AhoCorasickAutomaton, AhoCorasickMatch, DetectionEngine, DetectionEngineConfig, PayloadDatabase, ThreatCategory, createDetectionEngineFromCompiled, decodeInput, loadPayloadsFromCompiled, parsePayloadFile };
