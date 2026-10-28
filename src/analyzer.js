import crypto from 'crypto';
import { GoogleGenAI } from '@google/genai';
import { CONFIG, PLATFORM_RULES } from './config.js';

const CANARY_REGEX = /\b(?:v?\d+\.\d+\.\d+-(?:canary|alpha|beta|rc|experimental|insiders|nightly)\b)/i;

const HIGH_PRIORITY_PATTERNS = /\b(critical|zero[- ]day|0-day|actively\s+exploited|rce|remote\s+code\s+execution|unauthenticated|authentication\s+bypass|auth\s+bypass|privilege\s+escalation|sql\s+injection|sqli|supply[- ]chain\s+attack|malicious\s+package|backdoor|ransomware|data\s+breach|arbitrary\s+file\s+upload|php2shell|update\s+immediately|update\s+now|security\s+advisory|cvss\s*(?:9\.|10\.|8\.[5-9])|breaking\s+change|outage|downtime|service\s+disruption)\b/i;

const MEDIUM_PRIORITY_PATTERNS = /\b(vulnerability|cve-202\d-\d+|xss|cross[- ]site\s+scripting|csrf|ssrf|denial\s+of\s+service|path\s+traversal|directory\s+traversal|open\s+redirect|security\s+release|security\s+update|major\s+release|deprecat)\b/i;

const URGENT_EMERGENCY_PATTERNS = /\b(critical\s+.*(?:vulnerability|vulnerabilities|rce|security\s+release|security\s+update|security\s+advisory)|security\s+advisory.*critical|unauthenticated\s+remote\s+code\s+execution|rce\s+vulnerability|zero[- ]day|0-day|actively\s+exploited|update\s+immediately|emergency\s+(?:patch|update|security)|php2shell)\b/i;

const HOSTING_INCIDENT_PATTERNS = /\b(cloudflare|kinsta|wp\s*engine|fly\.io|pantheon|ploi\.?io|siteground)\b.*\b(outage|down|downtime|incident|degraded|disruption|unreachable|breach)\b|\b(outage|down|downtime|incident|degraded|disruption)\b.*\b(cloudflare|kinsta|wp\s*engine|fly\.io|pantheon|ploi\.?io|siteground)\b/i;

const OFFICIAL_PLATFORM_SOURCES = new Set([
  'PHP Official News & Releases',
  'WordPress Official News',
  'Node.js Blog & Security',
  'Next.js Releases',
  'Nuxt.js Releases',
  'Statamic CMS Releases',
  'Sanity CMS Releases',
]);

const CORE_STACK_PACKAGES = /\b(next|@next\/|@sentry\/nextjs|nuxt|@nuxt\/|nitro|nitropack|h3|unjs|sanity|@sanity\/|statamic|laravel|livewire|filament|symfony|wordpress|woocommerce|elementor|acf|php|composer|react|vue|vite|typescript|express|axios|prisma|tailwindcss|postcss|stripe|jsonwebtoken|jose|nodemailer|guzzle|phpmailer|monolog|phpunit|sharp|ws|undici|node)\b/i;

export function createItemFingerprint(item) {
  const normalizedUrl = (item.url || '')
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/+$/, '');
  return crypto.createHash('sha256').update(`${normalizedUrl}|${item.title || ''}`).digest('hex').slice(0, 24);
}

export function createTitleFingerprint(title = '') {
  const cleaned = title
    .toLowerCase()
    .replace(/\s*\([^)]+\)\s*$/, '')
    .replace(/\s+-\s+[^-]+$/, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
  return crypto.createHash('sha256').update(cleaned).digest('hex').slice(0, 24);
}

function detectPlatform(item) {
  if (item.isInfrastructureIncident && item.defaultPlatform) {
    return item.defaultPlatform;
  }

  if (
    item.category === 'release' &&
    item.defaultPlatform &&
    ['Next.js', 'Nuxt.js', 'Statamic CMS', 'Sanity CMS', 'PHP', 'WordPress'].includes(item.defaultPlatform)
  ) {
    return item.defaultPlatform;
  }

  const text = `${item.title} ${item.summary || ''} ${(item.packages || []).join(' ')}`;

  for (const rule of PLATFORM_RULES) {
    if (rule.pattern.test(text)) {
      return rule.platform;
    }
  }

  return item.defaultPlatform || null;
}

export function scoreAndClassifyItem(item) {
  const fullText = `${item.title} ${item.summary || ''} ${(item.packages || []).join(' ')}`;

  if (item.isInfrastructureIncident) {
    const displayTitle = item.title.trim();
    return {
      ...item,
      title: displayTitle,
      platform: item.defaultPlatform || 'Infrastructure',
      priority: 'HIGH',
      score: 125,
      isUrgentEmergency: true,
      isInfrastructureIncident: true,
      isOfficialSecurityNotification: false,
      fingerprint: createItemFingerprint(item),
      titleFingerprint: createTitleFingerprint(displayTitle),
    };
  }

  if (CANARY_REGEX.test(item.title) && !/security|cve|vulnerability|rce|critical/i.test(fullText)) {
    return null;
  }

  if (/\b(?:rc\d*|release\s+candidate|beta\s*\d*|alpha\s*\d*)\b/i.test(item.title) && !/security|cve|vulnerability|rce|critical/i.test(fullText)) {
    return null;
  }

  let displayTitle = item.title.trim();
  const platform = detectPlatform(item);
  if (!platform) return null;

  if (/^v?\d+\.\d+\.\d+/i.test(displayTitle) && item.defaultPlatform) {
    const isMinorOrMajor = /\bv?\d+\.\d+\.0\b/.test(displayTitle);
    const suffix = isMinorOrMajor ? 'Feature Release' : 'Patch Release';
    displayTitle = `${item.defaultPlatform} ${displayTitle} (${suffix})`;
  }

  if (item.source.startsWith('GitHub Security Advisory')) {
    const matchesCorePkg = CORE_STACK_PACKAGES.test(fullText);
    const isCritical = item.severityHint === 'CRITICAL';
    if (!matchesCorePkg && !isCritical) {
      return null;
    }
  }

  if (!item.alwaysRelevant && !item.source.startsWith('GitHub Security Advisory')) {
    const hasRelevantMatch = PLATFORM_RULES.some(r => r.pattern.test(fullText));
    if (!hasRelevantMatch) {
      return null;
    }
  }

  const isHostingIncident = HOSTING_INCIDENT_PATTERNS.test(fullText);

  let priority = 'LOW';
  let score = 50;

  if (
    isHostingIncident ||
    item.severityHint === 'CRITICAL' ||
    item.severityHint === 'HIGH' ||
    HIGH_PRIORITY_PATTERNS.test(fullText)
  ) {
    priority = 'HIGH';
    score = isHostingIncident ? 115 : 90;
  } else if (
    item.severityHint === 'MODERATE' ||
    MEDIUM_PRIORITY_PATTERNS.test(fullText) ||
    item.category === 'security'
  ) {
    priority = 'MEDIUM';
    score = 72;
  } else if (item.category === 'release') {
    if (/\bv?\d+\.\d+\.0\b/.test(item.title) || /breaking|major/i.test(fullText)) {
      priority = 'MEDIUM';
      score = 68;
    } else {
      priority = 'LOW';
      score = 55;
    }
  }

  if (['WordPress', 'PHP', 'Sanity CMS', 'Statamic CMS', 'Next.js', 'Nuxt.js'].includes(platform)) {
    score += 10;
  }

  if (OFFICIAL_PLATFORM_SOURCES.has(item.source) && /security|critical|vulnerability|cve-|rce/i.test(fullText)) {
    score += 18;
  }

  const isPreReleaseTitle =
    /\b(?:rc\d*|release\s+candidate|beta|alpha)\b/i.test(item.title) &&
    !/security|critical/i.test(item.title);

  const isOfficialSecurityNotification =
    !isPreReleaseTitle &&
    OFFICIAL_PLATFORM_SOURCES.has(item.source) &&
    /\b(security\s+advisory|security\s+release|security\s+releases|upcoming.*security|advance\s+notice.*security|critical.*security|critical.*rce|critical.*vulnerabilit|update\s+immediately|update\s+now)\b/i.test(
      fullText
    ) &&
    !/^PHP\s+\d+\.\d+\.\d+\s+Released!$/i.test(item.title);

  const isCriticalStackVulnerability =
    !isPreReleaseTitle &&
    ['WordPress', 'PHP', 'Sanity CMS', 'Statamic CMS', 'Next.js', 'Nuxt.js', 'JavaScript'].includes(platform) &&
    URGENT_EMERGENCY_PATTERNS.test(fullText) &&
    !/^PHP\s+\d+\.\d+\.\d+\s+Released!$/i.test(item.title);

  const isUrgentEmergency =
    isHostingIncident || isOfficialSecurityNotification || isCriticalStackVulnerability;

  return {
    ...item,
    title: displayTitle,
    platform,
    priority,
    score,
    isUrgentEmergency,
    isInfrastructureIncident: isHostingIncident,
    isOfficialSecurityNotification,
    fingerprint: createItemFingerprint(item),
    titleFingerprint: createTitleFingerprint(displayTitle),
  };
}

function selectCriticalDigestItems(scoredItems, maxItems = CONFIG.maxItemsPerDigest) {
  const sortByScoreAndDate = (a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return b.publishedAt - a.publishedAt;
  };

  const highPool = scoredItems.filter(i => i.priority === 'HIGH').sort(sortByScoreAndDate);

  const selected = [];
  const platformCounts = {};
  const sourceCounts = {};
  let php2shellCount = 0;

  function pickFromHighPool(targetCount, maxPerPlatform = 3, maxPerSource = 3) {
    let picked = 0;
    for (const item of highPool) {
      if (picked >= targetCount || selected.length >= maxItems) break;
      if (selected.some(s => s.fingerprint === item.fingerprint)) continue;

      if (item.isInfrastructureIncident) {
        selected.push(item);
        picked++;
        continue;
      }

      if (
        /^PHP\s+\d+\.\d+\.\d+\s+Released!$/i.test(item.title) &&
        highPool.some(p => /Security advisory:/i.test(p.title))
      ) {
        continue;
      }

      if (/php2shell/i.test(item.title)) {
        if (php2shellCount >= 2) continue;
      }

      const pCount = platformCounts[item.platform] || 0;
      const sCount = sourceCounts[item.source] || 0;
      if (pCount >= maxPerPlatform || sCount >= maxPerSource) continue;

      selected.push(item);
      platformCounts[item.platform] = pCount + 1;
      sourceCounts[item.source] = sCount + 1;
      if (/php2shell/i.test(item.title)) php2shellCount++;
      picked++;
    }
  }

  pickFromHighPool(6, 1, 2);
  if (selected.length < maxItems) {
    pickFromHighPool(maxItems - selected.length, 3, 4);
  }

  return selected;
}

async function refineWithGeminiIfAvailable(candidates) {
  if (!CONFIG.geminiApiKey || candidates.length === 0) {
    return candidates;
  }

  try {
    const client = new GoogleGenAI({ apiKey: CONFIG.geminiApiKey });

    const schema = {
      type: 'object',
      properties: {
        items: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              index: { type: 'integer', description: 'Original index from candidate list' },
              priority: {
                type: 'string',
                enum: ['HIGH', 'MEDIUM', 'LOW'],
              },
              platform: { type: 'string' },
              cleanTitle: { type: 'string' },
            },
            required: ['index', 'priority', 'platform', 'cleanTitle'],
          },
        },
      },
      required: ['items'],
    };

    const promptLines = candidates.map(
      (c, i) => `[${i}] (${c.platform} | ${c.source} | DefaultPriority=${c.priority}) ${c.title} — ${c.summary?.slice(0, 180) || ''}`
    );

    const prompt = `You are a Senior Cybersecurity & Web Stack Intelligence Analyst.
Review these critical security & infrastructure incident items for a developer whose stack is: PHP, WordPress, Sanity CMS, Statamic CMS, JavaScript, Nuxt.js, Next.js, and hosting on Cloudflare, Kinsta, WP Engine, Fly.io, Pantheon, Ploi.io, SiteGround.
Keep only genuinely HIGH/CRITICAL items.

Candidate items:
${promptLines.join('\n')}`;

    const interaction = await Promise.race([
      client.interactions.create({
        model: CONFIG.geminiModel,
        input: prompt,
        response_format: {
          type: 'text',
          mime_type: 'application/json',
          schema,
        },
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Gemini API timeout/rate-limit fallback (6s)')), 6000)
      ),
    ]);

    const parsed = JSON.parse(interaction.output_text || '{}');
    if (!Array.isArray(parsed.items) || parsed.items.length === 0) {
      return candidates;
    }

    const refined = [];
    for (const entry of parsed.items) {
      const orig = candidates[entry.index];
      if (!orig) continue;
      const finalPriority = orig.isInfrastructureIncident
        ? 'HIGH'
        : ['HIGH', 'MEDIUM', 'LOW'].includes(entry.priority)
          ? entry.priority
          : orig.priority;
      if (finalPriority !== 'HIGH') continue;
      refined.push({
        ...orig,
        priority: 'HIGH',
        platform: entry.platform || orig.platform,
        title: entry.cleanTitle || orig.title,
      });
    }

    console.error(`[AI Agent] Refined ${refined.length} critical items via ${CONFIG.geminiModel}.`);
    return refined.length > 0 ? refined : candidates;
  } catch {
    console.error(`[AI Agent] Using built-in deterministic cybersecurity & stack prioritization engine.`);
    return candidates;
  }
}

export async function filterAndPrioritizeItems(
  rawItems,
  sentHistory = {},
  {
    lookbackHours = CONFIG.lookbackHours,
    releaseLookbackHours = CONFIG.releaseLookbackHours,
    maxItems = CONFIG.maxItemsPerDigest,
    platforms = null,
  } = {}
) {
  const now = Date.now();
  const securityCutoffMs = Number(lookbackHours) * 60 * 60 * 1000;
  const releaseCutoffMs = Number(releaseLookbackHours) * 60 * 60 * 1000;
  const normalizedPlatforms =
    Array.isArray(platforms) && platforms.length > 0
      ? platforms.map(p => String(p).toLowerCase().trim())
      : null;

  const seenUrls = new Set();
  const seenTitles = new Set();
  const candidates = [];

  for (const raw of rawItems) {
    const ageMs = now - raw.publishedAt.getTime();
    const maxAgeMs = raw.category === 'release' ? releaseCutoffMs : securityCutoffMs;
    if (!raw.isInfrastructureIncident && (ageMs > maxAgeMs || ageMs < -24 * 60 * 60 * 1000)) {
      continue;
    }

    const scored = scoreAndClassifyItem(raw);
    if (!scored || scored.priority !== 'HIGH') continue;

    if (
      normalizedPlatforms &&
      !normalizedPlatforms.some(
        p => scored.platform.toLowerCase().includes(p) || p.includes(scored.platform.toLowerCase())
      )
    ) {
      continue;
    }

    if (!scored.isInfrastructureIncident && (sentHistory[scored.fingerprint] || sentHistory[scored.titleFingerprint])) {
      continue;
    }

    if (seenUrls.has(scored.fingerprint) || seenTitles.has(scored.titleFingerprint)) {
      continue;
    }

    seenUrls.add(scored.fingerprint);
    seenTitles.add(scored.titleFingerprint);
    candidates.push(scored);
  }

  const selectedHigh = selectCriticalDigestItems(candidates, Number(maxItems));
  const refined = await refineWithGeminiIfAvailable(selectedHigh);

  const grouped = {
    HIGH: refined,
    MEDIUM: [],
    LOW: [],
  };

  return {
    allSelected: refined,
    grouped,
    totalCandidates: candidates.length,
    infrastructureStatuses: rawItems.infrastructureStatuses || [],
    domainHealth: rawItems.domainHealth || null,
  };
}

export function filterUrgentEmergencyItems(
  rawItems,
  sentHistory = {},
  urgentHistory = {},
  { lookbackHours = CONFIG.urgentLookbackHours } = {}
) {
  const now = Date.now();
  const urgentCutoffMs = Number(lookbackHours) * 60 * 60 * 1000;

  const seenUrls = new Set();
  const seenTitles = new Set();
  const urgentCandidates = [];

  for (const raw of rawItems) {
    const ageMs = now - raw.publishedAt.getTime();
    if (!raw.isInfrastructureIncident && (ageMs > urgentCutoffMs || ageMs < -24 * 60 * 60 * 1000)) {
      continue;
    }

    const scored = scoreAndClassifyItem(raw);
    if (!scored || !scored.isUrgentEmergency) continue;

    if (
      sentHistory[scored.fingerprint] ||
      sentHistory[scored.titleFingerprint] ||
      urgentHistory[scored.fingerprint] ||
      urgentHistory[scored.titleFingerprint]
    ) {
      continue;
    }

    if (seenUrls.has(scored.fingerprint) || seenTitles.has(scored.titleFingerprint)) {
      continue;
    }

    seenUrls.add(scored.fingerprint);
    seenTitles.add(scored.titleFingerprint);
    urgentCandidates.push(scored);
  }

  urgentCandidates.sort((a, b) => {
    if (Boolean(b.isInfrastructureIncident) !== Boolean(a.isInfrastructureIncident)) {
      return Number(Boolean(b.isInfrastructureIncident)) - Number(Boolean(a.isInfrastructureIncident));
    }
    if (Boolean(b.isOfficialSecurityNotification) !== Boolean(a.isOfficialSecurityNotification)) {
      return Number(Boolean(b.isOfficialSecurityNotification)) - Number(Boolean(a.isOfficialSecurityNotification));
    }
    if (b.score !== a.score) return b.score - a.score;
    return b.publishedAt - a.publishedAt;
  });

  const selectedUrgent = [];
  const platformCounts = {};
  for (const item of urgentCandidates) {
    if (selectedUrgent.length >= 6) break;
    if (item.isInfrastructureIncident) {
      selectedUrgent.push(item);
      continue;
    }
    const pCount = platformCounts[item.platform] || 0;
    if (pCount >= 2 && !item.isOfficialSecurityNotification) continue;
    selectedUrgent.push(item);
    platformCounts[item.platform] = pCount + 1;
  }

  return {
    selectedUrgent,
    allMatchedUrgent: urgentCandidates,
  };
}

export function searchStackAdvisories(
  rawItems,
  {
    query = '',
    platform = '',
    priority = '',
    lookbackHours = 168,
    limit = 15,
  } = {}
) {
  const now = Date.now();
  const maxAgeMs = Number(lookbackHours) * 60 * 60 * 1000;
  const q = String(query || '').toLowerCase().trim();
  const pFilter = String(platform || '').toLowerCase().trim();
  const prioFilter = String(priority || '').toUpperCase().trim();

  const seenFingerprints = new Set();
  const matches = [];

  for (const raw of rawItems) {
    const ageMs = now - raw.publishedAt.getTime();
    if (!raw.isInfrastructureIncident && (ageMs > maxAgeMs || ageMs < -24 * 60 * 60 * 1000)) continue;

    const scored = scoreAndClassifyItem(raw);
    const itemToInspect = scored || {
      ...raw,
      platform: raw.defaultPlatform || 'General Security',
      priority: raw.severityHint === 'CRITICAL' || raw.severityHint === 'HIGH' ? 'HIGH' : 'MEDIUM',
      score: 50,
      fingerprint: createItemFingerprint(raw),
    };

    if (seenFingerprints.has(itemToInspect.fingerprint)) continue;

    const searchable = `${itemToInspect.title} ${itemToInspect.summary || ''} ${itemToInspect.platform || ''} ${itemToInspect.source || ''} ${(itemToInspect.packages || []).join(' ')}`.toLowerCase();

    if (q && !searchable.includes(q)) continue;
    if (pFilter && !String(itemToInspect.platform || '').toLowerCase().includes(pFilter)) continue;
    if (prioFilter && ['HIGH', 'MEDIUM', 'LOW'].includes(prioFilter) && itemToInspect.priority !== prioFilter) continue;

    if (!q && !pFilter && !scored) continue;

    seenFingerprints.add(itemToInspect.fingerprint);
    matches.push(itemToInspect);
  }

  matches.sort((a, b) => {
    if ((b.score || 0) !== (a.score || 0)) return (b.score || 0) - (a.score || 0);
    return b.publishedAt - a.publishedAt;
  });

  return matches.slice(0, Number(limit) || 15);
}
