import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const VERSION = '0.0.75';
const MACOS_MARKER = 'pi-sentinel: SRT 0.0.75 profile file spill';
const RULES_MARKER = 'pi-sentinel: split SBPL data objects below 48 KiB';
const DENY_GROUPS_MARKER = 'pi-sentinel: compact exact sibling deny leaves';
const AFFIX_MARKER = 'pi-sentinel: factor exact deny leaf affixes';
const TRIE_MARKER = 'pi-sentinel: compact exact deny leaf tries';
const READ_DENIES_MARKER = 'pi-sentinel: compact exact read-deny path families';
const MANAGER_MARKER = 'pi-sentinel: SRT profile cleanup on reset';

if (process.platform !== 'darwin') process.exit(0);

const require = createRequire(import.meta.url);
const packageJsonPath = require.resolve('@anthropic-ai/sandbox-runtime/package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
if (packageJson.version !== VERSION) {
  throw new Error('SRT profile patch requires sandbox-runtime ' + VERSION);
}

const packageRoot = dirname(packageJsonPath);
const macPath = join(packageRoot, 'dist/sandbox/macos-sandbox-utils.js');
const managerPath = join(packageRoot, 'dist/sandbox/sandbox-manager.js');
let mac = readFileSync(macPath, 'utf8');
let manager = readFileSync(managerPath, 'utf8');
const macProfilePatched = mac.includes(MACOS_MARKER);
const macRulesPatched = mac.includes(RULES_MARKER);
const macDenyGroupsPatched = mac.includes(DENY_GROUPS_MARKER);
const macAffixesPatched = mac.includes(AFFIX_MARKER);
const macTriesPatched = mac.includes(TRIE_MARKER);
const macReadDeniesPatched = mac.includes(READ_DENIES_MARKER);
const managerPatched = manager.includes(MANAGER_MARKER);
if (macProfilePatched && macRulesPatched && macDenyGroupsPatched && macAffixesPatched && macTriesPatched && macReadDeniesPatched && managerPatched) process.exit(0);
if (macProfilePatched !== managerPatched || (macRulesPatched && !macProfilePatched) || (macDenyGroupsPatched && (!macProfilePatched || !macRulesPatched)) || (macAffixesPatched && (!macProfilePatched || !macRulesPatched || !macDenyGroupsPatched)) || (macTriesPatched && (!macProfilePatched || !macRulesPatched || !macDenyGroupsPatched || !macAffixesPatched)) || (macReadDeniesPatched && (!macProfilePatched || !macRulesPatched || !macDenyGroupsPatched || !macAffixesPatched || !macTriesPatched))) {
  throw new Error('Partial SRT profile patch detected; reinstall sandbox-runtime ' + VERSION);
}

function replaceOnce(source, before, after, label) {
  const first = source.indexOf(before);
  if (first < 0 || source.indexOf(before, first + before.length) >= 0) {
    throw new Error('Unexpected sandbox-runtime ' + VERSION + ' source at ' + label);
  }
  return source.slice(0, first) + after + source.slice(first + before.length);
}

if (!macProfilePatched) {
  const imports = "import { spawn } from 'child_process';\nimport * as path from 'path';\n";
  mac = replaceOnce(
    mac,
    imports,
    "import { spawn } from 'child_process';\nimport { mkdtempSync, rmSync, writeFileSync } from 'node:fs';\nimport { tmpdir } from 'node:os';\nimport * as path from 'path';\n",
    'macOS imports',
  );
  const stateAnchor = "import { shouldIgnoreViolation } from './sandbox-violation-store.js';\n";
  mac = replaceOnce(
    mac,
    stateAnchor,
    stateAnchor + "\n// " + MACOS_MARKER + "\nconst MAX_INLINE_PROFILE_BYTES = 64 * 1024;\nconst pendingProfileDirectories = new Set();\nexport function cleanupMacOSSandboxProfiles() {\n    for (const directory of pendingProfileDirectories) {\n        try {\n            rmSync(directory, { recursive: true, force: true });\n        }\n        catch {\n            // The wrapper EXIT trap retries cleanup.\n        }\n    }\n    pendingProfileDirectories.clear();\n}\n",
    'macOS profile state',
  );
  const oldWrapper = [
    '    const wrappedCommand = quote([',
    "        'env',",
    '        ...unsetEnvArgs,',
    '        ...setEnvArgs,',
    '        ...proxyEnvArgs,',
    "        '/usr/bin/sandbox-exec',",
    "        '-p',",
    '        profile,',
    '        shell,',
    "        '-c',",
    '        command,',
    '    ]);',
  ].join('\n');
  const newWrapper = [
    '    let profileDirectory;',
    "    let profileArgs = ['-p', profile];",
    '    if (Buffer.byteLength(profile, \'utf8\') > MAX_INLINE_PROFILE_BYTES) {',
    "        profileDirectory = mkdtempSync(path.join(tmpdir(), 'pi-srt-profile-'));",
    '        try {',
    "            const profileFile = path.join(profileDirectory, 'profile.sb');",
    "            writeFileSync(profileFile, profile, { encoding: 'utf8', flag: 'wx', mode: 0o600 });",
    '            pendingProfileDirectories.add(profileDirectory);',
    "            profileArgs = ['-f', profileFile];",
    '        }',
    '        catch (error) {',
    '            rmSync(profileDirectory, { recursive: true, force: true });',
    '            throw error;',
    '        }',
    '    }',
    '    let wrappedCommand;',
    '    try {',
    '        wrappedCommand = quote([',
    "            'env',",
    '            ...unsetEnvArgs,',
    '            ...setEnvArgs,',
    '            ...proxyEnvArgs,',
    "            '/usr/bin/sandbox-exec',",
    '            ...profileArgs,',
    '            shell,',
    "            '-c',",
    '            command,',
    '        ]);',
    '        if (profileDirectory) {',
    "            const cleanup = '/bin/rm -rf ' + quote([profileDirectory]);",
    "            wrappedCommand = 'trap ' + quote([cleanup]) + ' EXIT; ' + wrappedCommand;",
    '        }',
    '    }',
    '    catch (error) {',
    '        if (profileDirectory) {',
    '            pendingProfileDirectories.delete(profileDirectory);',
    '            rmSync(profileDirectory, { recursive: true, force: true });',
    '        }',
    '        throw error;',
    '    }',
  ].join('\n');
  mac = replaceOnce(mac, oldWrapper, newWrapper, 'sandbox-exec profile argv');
}

if (!macRulesPatched) {
  const renderStart = mac.indexOf('function renderRule(action, operations, filters, logTag) {');
  const renderEnd = mac.indexOf('\n}', renderStart);
  if (renderStart < 0 || renderEnd < 0) throw new Error('Unexpected renderRule shape in sandbox-runtime ' + VERSION);
  const currentRenderRule = mac.slice(renderStart, renderEnd + 2);
  if (!currentRenderRule.includes('filters.size') || !currentRenderRule.includes('with message')) throw new Error('Unexpected renderRule body in sandbox-runtime ' + VERSION);
  const newRenderRule = [
    '// ' + RULES_MARKER,
    'const MAX_SBPL_RULE_BYTES = 48 * 1024;',
    'function renderRule(action, operations, filters, logTag) {',
    '    if (filters.size === 0) return [];',
    "    const header = '(' + action + ' ' + operations.join(' ');",
    "    const footer = '  (with message \"' + logTag + '\"))';",
    "    const fixedBytes = Buffer.byteLength(header, 'utf8') + Buffer.byteLength(footer, 'utf8') + 2;",
    '    const rules = [];',
    '    let lines = [header];',
    "    let ruleBytes = fixedBytes;",
    '    for (const filter of filters) {',
    "        const line = '  ' + filter;",
    "        const lineBytes = Buffer.byteLength(line, 'utf8') + 1;",
    '        if (ruleBytes + lineBytes > MAX_SBPL_RULE_BYTES && lines.length > 1) {',
    '            lines.push(footer);',
    '            rules.push(...lines);',
    '            lines = [header];',
    "            ruleBytes = fixedBytes;",
    '        }',
    '        if (ruleBytes + lineBytes > MAX_SBPL_RULE_BYTES) {',
    "            throw new Error('SBPL filter exceeds safe rule size');",
    '        }',
    '        lines.push(line);',
    '        ruleBytes += lineBytes;',
    '    }',
    '    lines.push(footer);',
    '    rules.push(...lines);',
    '    return rules;',
    '}',
  ].join('\n');
  mac = mac.slice(0, renderStart) + newRenderRule + mac.slice(renderEnd + 2);
}


if (!macDenyGroupsPatched) {
  const groupAnchor = [
    '        for (const group of bySignature.values()) {',
    '            const fixedLength = regexLength(groupRegexPrefix(group)) + regexLength(groupDenyTail(group));',
  ].join('\n');
  const compactSiblingGroups = [
    '        for (const group of bySignature.values()) {',
    '            // Compact many unique sibling leaves while retaining the shared parent pin.',
    '            if (group.names.length === 1 && group.leaves.length >= MIN_DENY_GROUP_SIZE) {',
    '                const name = group.names[0];',
    '                let leafChunk = [];',
    '                const flushLeafChunk = () => {',
    '                    if (leafChunk.length < MIN_DENY_GROUP_SIZE) return;',
    '                    groups.push({ dir: group.dir, names: [name], leaves: leafChunk });',
    '                    for (const leaf of leafChunk) {',
    '                        grouped.add(path.join(group.dir, name, leaf));',
    '                    }',
    '                };',
    '                for (const leaf of group.leaves) {',
    '                    const candidate = { dir: group.dir, names: [name], leaves: [...leafChunk, leaf] };',
    '                    const candidateLength = regexLength(groupRegexPrefix(candidate)) + regexLength(groupDenyTail(candidate)) + regexLength(escapeRegexLiteral(name));',
    '                    if (candidateLength > SBPL_STRING_MAX_BYTES) {',
    '                        flushLeafChunk();',
    '                        leafChunk = [];',
    '                        const single = { dir: group.dir, names: [name], leaves: [leaf] };',
    '                        const singleLength = regexLength(groupRegexPrefix(single)) + regexLength(groupDenyTail(single)) + regexLength(escapeRegexLiteral(name));',
    '                        if (singleLength <= SBPL_STRING_MAX_BYTES) leafChunk.push(leaf);',
    '                    }',
    '                    else {',
    '                        leafChunk.push(leaf);',
    '                    }',
    '                }',
    '                flushLeafChunk();',
    '                continue;',
    '            }',
    '            const fixedLength = regexLength(groupRegexPrefix(group)) + regexLength(groupDenyTail(group));',
  ].join('\n');
  mac = replaceOnce(mac, groupAnchor, '        // ' + DENY_GROUPS_MARKER + '\n' + compactSiblingGroups, 'literal deny sibling grouping');
}


if (!macAffixesPatched) {
  const helperAnchor = 'function groupLiteralDenyPaths(normalizedPaths) {';
  const helper = String.raw`// ${AFFIX_MARKER}
const MIN_DENY_AFFIX_LENGTH = 4;
function splitLiteralDenyLeaves(leaves) {
    const groups = [];
    const rest = [];
    const entries = leaves.map((value) => ({ value, characters: Array.from(value) }));
    const visit = (values, depth) => {
        if (values.length < MIN_DENY_GROUP_SIZE) {
            rest.push(...values.map((entry) => entry.value));
            return;
        }
        const first = values[0].characters;
        let prefixLength = 0;
        while (prefixLength < first.length && values.every((entry) => entry.characters[prefixLength] === first[prefixLength])) {
            prefixLength++;
        }
        let minLength = first.length;
        for (const entry of values) {
            if (entry.characters.length < minLength) minLength = entry.characters.length;
        }
        let suffixLength = 0;
        while (suffixLength < minLength - prefixLength && values.every((entry) => entry.characters[entry.characters.length - suffixLength - 1] === first[first.length - suffixLength - 1])) {
            suffixLength++;
        }
        if (prefixLength >= MIN_DENY_AFFIX_LENGTH || suffixLength >= MIN_DENY_AFFIX_LENGTH) {
            groups.push({
                prefix: first.slice(0, prefixLength).join(''),
                suffix: suffixLength === 0 ? '' : first.slice(first.length - suffixLength).join(''),
                leaves: values.map((entry) => entry.characters.slice(prefixLength, entry.characters.length - suffixLength).join('')),
                originalLeaves: values.map((entry) => entry.value),
            });
            return;
        }
        let maxLength = 0;
        for (const entry of values) {
            if (entry.characters.length > maxLength) maxLength = entry.characters.length;
        }
        if (depth >= maxLength) {
            rest.push(...values.map((entry) => entry.value));
            return;
        }
        const byCharacter = new Map();
        for (const entry of values) {
            const character = entry.characters[depth];
            let bucket = byCharacter.get(character);
            if (!bucket) {
                bucket = [];
                byCharacter.set(character, bucket);
            }
            bucket.push(entry);
        }
        if (byCharacter.size === 1) {
            visit(values, depth + 1);
            return;
        }
        for (const bucket of byCharacter.values()) {
            visit(bucket, depth + 1);
        }
    };
    visit(entries, 0);
    return { groups, rest };
}`;
  mac = replaceOnce(mac, helperAnchor, helper + '\n' + helperAnchor, 'literal sibling affix helper');

  const oldComment = '            // Compact many unique sibling leaves while retaining the shared parent pin.';
  const branchAnchor = '            if (group.names.length === 1 && group.leaves.length >= MIN_DENY_GROUP_SIZE) {';
  const fixedLine = '            const fixedLength = regexLength(groupRegexPrefix(group)) + regexLength(groupDenyTail(group));';
  const commentAt = mac.indexOf(oldComment);
  const branchStart = mac.indexOf(branchAnchor, commentAt);
  const branchEnd = mac.indexOf(fixedLine, commentAt);
  if (commentAt < 0 || branchStart < 0 || branchEnd < 0) throw new Error('Unexpected sibling grouping branch in sandbox-runtime ' + VERSION);
  const compactSiblingGroups = String.raw`            if (group.names.length === 1 && group.leaves.length >= MIN_DENY_GROUP_SIZE) {
                const name = group.names[0];
                const { groups: affixGroups, rest: rawLeaves } = splitLiteralDenyLeaves(group.leaves);
                const ungroupedLeaves = [];
                for (const affixGroup of affixGroups) {
                    let leafChunk = [];
                    let originalLeafChunk = [];
                    const flushAffixChunk = () => {
                        if (leafChunk.length >= MIN_DENY_GROUP_SIZE) {
                            groups.push({ dir: group.dir, names: [name], leaves: leafChunk, leafPrefix: affixGroup.prefix, leafSuffix: affixGroup.suffix });
                            for (const originalLeaf of originalLeafChunk) {
                                grouped.add(path.join(group.dir, name, originalLeaf));
                            }
                        }
                        else {
                            ungroupedLeaves.push(...originalLeafChunk);
                        }
                        leafChunk = [];
                        originalLeafChunk = [];
                    };
                    for (let index = 0; index < affixGroup.leaves.length; index++) {
                        const leaf = affixGroup.leaves[index];
                        const originalLeaf = affixGroup.originalLeaves[index];
                        const candidate = { dir: group.dir, names: [name], leaves: [...leafChunk, leaf], leafPrefix: affixGroup.prefix, leafSuffix: affixGroup.suffix };
                        const candidateLength = regexLength(groupRegexPrefix(candidate)) + regexLength(groupDenyTail(candidate)) + regexLength(escapeRegexLiteral(name));
                        if (candidateLength > SBPL_STRING_MAX_BYTES) {
                            flushAffixChunk();
                            const single = { dir: group.dir, names: [name], leaves: [leaf], leafPrefix: affixGroup.prefix, leafSuffix: affixGroup.suffix };
                            const singleLength = regexLength(groupRegexPrefix(single)) + regexLength(groupDenyTail(single)) + regexLength(escapeRegexLiteral(name));
                            if (singleLength <= SBPL_STRING_MAX_BYTES) {
                                leafChunk.push(leaf);
                                originalLeafChunk.push(originalLeaf);
                            }
                            else {
                                ungroupedLeaves.push(originalLeaf);
                            }
                        }
                        else {
                            leafChunk.push(leaf);
                            originalLeafChunk.push(originalLeaf);
                        }
                    }
                    flushAffixChunk();
                }
                const leavesToChunk = [...rawLeaves, ...ungroupedLeaves];
                ungroupedLeaves.length = 0;
                let rawLeafChunk = [];
                const flushRawChunk = () => {
                    if (rawLeafChunk.length >= MIN_DENY_GROUP_SIZE) {
                        groups.push({ dir: group.dir, names: [name], leaves: rawLeafChunk });
                        for (const leaf of rawLeafChunk) {
                            grouped.add(path.join(group.dir, name, leaf));
                        }
                    }
                    else {
                        ungroupedLeaves.push(...rawLeafChunk);
                    }
                    rawLeafChunk = [];
                };
                for (const leaf of leavesToChunk) {
                    const candidate = { dir: group.dir, names: [name], leaves: [...rawLeafChunk, leaf] };
                    const candidateLength = regexLength(groupRegexPrefix(candidate)) + regexLength(groupDenyTail(candidate)) + regexLength(escapeRegexLiteral(name));
                    if (candidateLength > SBPL_STRING_MAX_BYTES) {
                        flushRawChunk();
                        const single = { dir: group.dir, names: [name], leaves: [leaf] };
                        const singleLength = regexLength(groupRegexPrefix(single)) + regexLength(groupDenyTail(single)) + regexLength(escapeRegexLiteral(name));
                        if (singleLength <= SBPL_STRING_MAX_BYTES) rawLeafChunk.push(leaf);
                        else ungroupedLeaves.push(leaf);
                    }
                    else {
                        rawLeafChunk.push(leaf);
                    }
                }
                flushRawChunk();
                continue;
            }`;
  mac = mac.slice(0, branchStart) + compactSiblingGroups + '\n' + mac.slice(branchEnd);

  const tailStart = mac.indexOf('function groupDenyTail(group) {');
  const tailEnd = mac.indexOf('\n}', tailStart);
  if (tailStart < 0 || tailEnd < 0) throw new Error('Unexpected groupDenyTail shape in sandbox-runtime ' + VERSION);
  const oldTail = mac.slice(tailStart, tailEnd + 2);
  if (!oldTail.includes('group.leaves.map(escapeRegexLiteral)')) throw new Error('Unexpected groupDenyTail body in sandbox-runtime ' + VERSION);
  const newTail = String.raw`function groupDenyTail(group) {
    const alternatives = group.leaves.map(escapeRegexLiteral).join('|');
    if (group.leafPrefix === undefined) {
        return ')/(' + alternatives + ')(/.*)?$';
    }
    return ')/' + escapeRegexLiteral(group.leafPrefix) + '(' + alternatives + ')' + escapeRegexLiteral(group.leafSuffix) + '(/.*)?$';
}`;
  mac = replaceOnce(mac, oldTail, newTail, 'factored literal deny tail');
}
if (!macTriesPatched) {
  const groupStart = mac.indexOf('function groupLiteralDenyPaths(normalizedPaths) {');
  const groupEnd = mac.indexOf('\n/** Bytes a regex fragment occupies inside an SBPL string literal. */', groupStart);
  if (groupStart < 0 || groupEnd < 0) throw new Error('Unexpected literal deny grouping shape in sandbox-runtime ' + VERSION);
  let groupSource = mac.slice(groupStart, groupEnd);
  if ((groupSource.match(/groupDenyTail\(candidate\)/g) || []).length !== 2 || (groupSource.match(/groupDenyTail\(single\)/g) || []).length !== 2) {
    throw new Error('Unexpected literal deny chunk sizing in sandbox-runtime ' + VERSION);
  }
  groupSource = groupSource
    .replaceAll('groupDenyTail(candidate)', 'groupDenyTail(candidate, false)')
    .replaceAll('groupDenyTail(single)', 'groupDenyTail(single, false)');
  mac = mac.slice(0, groupStart) + groupSource + mac.slice(groupEnd);

  const tailStart = mac.indexOf('function groupDenyTail(group) {');
  if (tailStart < 0) throw new Error('Unexpected groupDenyTail shape in sandbox-runtime ' + VERSION);
  const helper = String.raw`// ${TRIE_MARKER}
function exactLiteralAlternation(values) {
    const root = { terminal: false, children: new Map() };
    for (const value of values) {
        let node = root;
        for (const character of Array.from(value)) {
            let child = node.children.get(character);
            if (!child) {
                child = { terminal: false, children: new Map() };
                node.children.set(character, child);
            }
            node = child;
        }
        node.terminal = true;
    }
    const characterPattern = (characters) => {
        if (characters.length === 1) return escapeRegexLiteral(characters[0]);
        if (characters.every((character) => character >= '0' && character <= '9')) {
            const digits = characters.map(Number).sort((left, right) => left - right);
            const consecutive = digits[digits.length - 1] - digits[0] + 1 === digits.length;
            return consecutive
                ? '[' + digits[0] + '-' + digits[digits.length - 1] + ']'
                : '[' + digits.join('') + ']';
        }
        return '(' + characters.map(escapeRegexLiteral).join('|') + ')';
    };
    const render = (current) => {
        const branches = current.terminal ? [''] : [];
        const suffixGroups = new Map();
        for (const [character, child] of current.children) {
            const suffix = render(child);
            let characters = suffixGroups.get(suffix);
            if (!characters) {
                characters = [];
                suffixGroups.set(suffix, characters);
            }
            characters.push(character);
        }
        for (const [suffix, characters] of suffixGroups) {
            branches.push(characterPattern(characters) + suffix);
        }
        if (branches.length === 1) return branches[0];
        return '(' + branches.join('|') + ')';
    };
    const compact = render(root);
    const expanded = values.map(escapeRegexLiteral).join('|');
    return regexLength(compact) < regexLength(expanded) ? compact : expanded;
}`;
  mac = mac.slice(0, tailStart) + helper + '\n' + mac.slice(tailStart);

  const currentTailStart = mac.indexOf('function groupDenyTail(group) {');
  const tailEnd = mac.indexOf('\n}', currentTailStart);
  if (currentTailStart < 0 || tailEnd < 0) throw new Error('Unexpected groupDenyTail body in sandbox-runtime ' + VERSION);
  const oldTail = mac.slice(currentTailStart, tailEnd + 2);
  if (!oldTail.includes('group.leaves.map(escapeRegexLiteral)')) throw new Error('Unexpected groupDenyTail body in sandbox-runtime ' + VERSION);
  const newTail = String.raw`function groupDenyTail(group, compactLeaves = true) {
    const alternatives = compactLeaves
        ? exactLiteralAlternation(group.leaves)
        : group.leaves.map(escapeRegexLiteral).join('|');
    if (group.leafPrefix === undefined) {
        return ')/(' + alternatives + ')(/.*)?$';
    }
    return ')/' + escapeRegexLiteral(group.leafPrefix) + '(' + alternatives + ')' + escapeRegexLiteral(group.leafSuffix) + '(/.*)?$';
}`;
  mac = replaceOnce(mac, oldTail, newTail, 'exact literal trie deny tail');
}
if (!macReadDeniesPatched) {
  const oldReadDeny = String.raw`    const denyFilters = new Set(resolved.denies.map(d => denyPathFilter(d.path)));
    rules.push(...renderRule('deny', ['file-read*'], denyFilters, logTag));`;
  const newReadDeny = String.raw`    // ${READ_DENIES_MARKER}
    const { groups: denyGroups, rest: ungroupedDenies } = groupLiteralDenyPaths(resolved.denies.map(d => d.path));
    const denyFilters = new Set(ungroupedDenies.map(denyPathFilter));
    for (const group of denyGroups) {
        for (const filter of literalDenyGroupFilters(group).deny) denyFilters.add(filter);
    }
    rules.push(...renderRule('deny', ['file-read*'], denyFilters, logTag));`;
  mac = replaceOnce(mac, oldReadDeny, newReadDeny, 'exact read-deny grouping');

  const lateStart = mac.indexOf('function lateReadDenyFilters(resolved) {');
  const lateEnd = mac.indexOf('\n}', lateStart);
  if (lateStart < 0 || lateEnd < 0) throw new Error('Unexpected lateReadDenyFilters shape in sandbox-runtime ' + VERSION);
  const oldLate = mac.slice(lateStart, lateEnd + 2);
  if (!oldLate.includes('literalAllowDirs') || !oldLate.includes('denyGlobCovers')) throw new Error('Unexpected late read-deny logic in sandbox-runtime ' + VERSION);
  const newLate = String.raw`function lateReadDenyFilters(resolved) {
    const filters = [];
    let coversRoot = false;
    const literalAllowDirs = resolved.allows.filter(a => !a.glob).map(a => a.path);
    const nestedLiteralDenies = [];
    for (const deny of resolved.denies) {
        if (!deny.glob) {
            if (literalAllowDirs.some(a => deny.path.startsWith(a + '/'))) {
                nestedLiteralDenies.push(deny.path);
            }
            continue;
        }
        const denyRegex = new RegExp(denyGlobRegex(deny.path));
        if (denyRegex.test('/')) coversRoot = true;
        const carveOuts = resolved.allows
            .filter(a => denyGlobCovers(denyRegex, a))
            .map(a => pathFilter(a.path));
        filters.push(carveFilter(denyPathFilter(deny.path), carveOuts));
    }
    const { groups, rest } = groupLiteralDenyPaths(nestedLiteralDenies);
    for (const group of groups) filters.push(...literalDenyGroupFilters(group).deny);
    filters.push(...rest.map(denyPathFilter));
    return { filters, coversRoot };
}`;
  mac = replaceOnce(mac, oldLate, newLate, 'group exact late read denies');

  const oldMoveRules = String.raw`function generateMoveBlockingRules(pathPatterns, logTag) {
    return renderRule('deny', ['file-write-unlink', 'file-write-create'], moveBlockingFilters(pathPatterns.map(normalizePathForSandbox)), logTag);
}`;
  const newMoveRules = String.raw`function generateMoveBlockingRules(pathPatterns, logTag) {
    return renderRule('deny', ['file-write-unlink', 'file-write-create'], groupedMoveBlockingFilters(pathPatterns.map(normalizePathForSandbox)), logTag);
}`;
  mac = replaceOnce(mac, oldMoveRules, newMoveRules, 'group exact read move blockers');

  const moveDocAnchor = String.raw`/**
 * Generate deny rules for file movement`;
  const groupedMoveHelper = String.raw`/** Group exact denied paths without dropping parent move pins. */
function groupedMoveBlockingFilters(normalizedPaths) {
    const { groups, rest } = groupLiteralDenyPaths(normalizedPaths);
    const filters = moveBlockingFilters(rest);
    for (const group of groups) {
        const { deny, pins } = literalDenyGroupFilters(group);
        for (const filter of [...deny, ...pins]) filters.add(filter);
        for (const ancestorDir of [group.dir, ...getAncestorDirectories(group.dir)]) {
            filters.add('(literal ' + escapePath(ancestorDir) + ')');
        }
    }
    return filters;
}`;
  mac = replaceOnce(mac, moveDocAnchor, groupedMoveHelper + '\n' + moveDocAnchor, 'group exact move blockers');

  const unlinkStart = mac.indexOf('function generateReadDenyUnlinkRules(resolved, logTag) {');
  const unlinkEnd = mac.indexOf('\n}', unlinkStart);
  if (unlinkStart < 0 || unlinkEnd < 0) throw new Error('Unexpected generateReadDenyUnlinkRules shape in sandbox-runtime ' + VERSION);
  const oldUnlink = mac.slice(unlinkStart, unlinkEnd + 2);
  if (!oldUnlink.includes('carveOutsInside') || !oldUnlink.includes('strictlyBelowWriteRoot')) throw new Error('Unexpected read unlink protection in sandbox-runtime ' + VERSION);
  const newUnlink = String.raw`function generateReadDenyUnlinkRules(resolved, logTag) {
    const { denies, allows, writeRoots } = resolved;
    if (writeRoots.length === 0) return [];
    const writeRootRegexes = writeRoots
        .filter(w => w.glob)
        .map(w => new RegExp(globToRegex(w.path)));
    const literalWriteRoots = writeRoots.filter(w => !w.glob).map(w => w.path);
    const strictlyBelowWriteRoot = p => literalWriteRoots.some(w => isStrictlyUnder({ path: p, glob: false }, w)) ||
        writeRootRegexes.some(re => re.test(p));
    const carveOutsInside = dir => [...allows, ...writeRoots]
        .filter(e => isStrictlyUnder(e, dir))
        .map(e => pathFilter(e.path));
    const filters = new Set();
    const groupableLiteralDenies = [];
    const protectDirs = dirs => {
        for (const dir of dirs) {
            if (strictlyBelowWriteRoot(dir)) filters.add('(literal ' + escapePath(dir) + ')');
        }
    };
    for (const deny of denies) {
        if (deny.glob) {
            const baseDir = globBaseDir(deny.path);
            const intersectsWriteRoot = writeRootRegexes.length > 0 ||
                literalWriteRoots.some(w => baseDir === w ||
                    isStrictlyUnder({ path: baseDir, glob: false }, w) ||
                    isStrictlyUnder({ path: w, glob: false }, baseDir));
            if (!intersectsWriteRoot) continue;
            const denyRegex = new RegExp(denyGlobRegex(deny.path));
            const carveOuts = [...allows, ...writeRoots]
                .filter(e => denyGlobCovers(denyRegex, e))
                .map(e => pathFilter(e.path));
            filters.add(carveFilter(denyPathFilter(deny.path), carveOuts));
            if (baseDir !== '/') protectDirs([baseDir, ...getAncestorDirectories(baseDir)]);
            continue;
        }
        if (!strictlyBelowWriteRoot(deny.path)) continue;
        const carveOuts = carveOutsInside(deny.path);
        if (carveOuts.length === 0) groupableLiteralDenies.push(deny.path);
        else filters.add(carveFilter(denyPathFilter(deny.path), carveOuts));
        protectDirs(getAncestorDirectories(deny.path));
    }
    const { groups, rest } = groupLiteralDenyPaths(groupableLiteralDenies);
    for (const group of groups) {
        for (const filter of literalDenyGroupFilters(group).deny) filters.add(filter);
    }
    for (const denyPath of rest) filters.add(denyPathFilter(denyPath));
    return renderRule('deny', ['file-write-unlink'], filters, logTag);
}`;
  mac = replaceOnce(mac, oldUnlink, newUnlink, 'group exact read-deny unlink filters');
}

if (!managerPatched) {
  const oldManagerImport = "import { wrapCommandWithSandboxMacOS, startMacOSSandboxLogMonitor, } from './macos-sandbox-utils.js';";
  manager = replaceOnce(
    manager,
    oldManagerImport,
    "import { wrapCommandWithSandboxMacOS, startMacOSSandboxLogMonitor, cleanupMacOSSandboxProfiles, } from './macos-sandbox-utils.js';",
    'SandboxManager import',
  );
  const resetAnchor = '    cleanupBwrapMountPoints({ force: true });\n    // Stop log monitor';
  manager = replaceOnce(
    manager,
    resetAnchor,
    '    cleanupBwrapMountPoints({ force: true });\n    // ' + MANAGER_MARKER + '\n    cleanupMacOSSandboxProfiles();\n    // Stop log monitor',
    'SandboxManager.reset cleanup',
  );
}

writeFileSync(macPath, mac);
writeFileSync(managerPath, manager);
