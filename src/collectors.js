import dns from 'dns';
import { XMLParser } from 'fast-xml-parser';
import { RSS_FEEDS, INFRASTRUCTURE_PROVIDERS, MONITORED_DOMAINS } from './config.js';

// Prefer IPv4 first on macOS + Tailscale to avoid undici Happy Eyeballs timeouts
dns.setDefaultResultOrder('ipv4first');

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  trimValues: true,
  stopNodes: [
    'rss.channel.item.description',
    'rss.channel.item.content:encoded',
    'feed.entry.summary',
    'feed.entry.content',
  ],
});

let cachedRawItems = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60 * 1000;

function decodeHtmlEntities(str = '') {
  return String(str)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&#8211;/g, '–')
    .replace(/&#8212;/g, '—')
    .replace(/&#8216;/g, '‘')
    .replace(/&#8217;/g, '’')
    .replace(/&#8220;/g, '“')
    .replace(/&#8221;/g, '”')
    .replace(/&nbsp;/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractAtomLink(linkField) {
  if (!linkField) return '';
  if (typeof linkField === 'string') return linkField.trim();
  if (Array.isArray(linkField)) {
    const alternate = linkField.find(l => l?.['@_rel'] === 'alternate' && l?.['@_href']);
    if (alternate) return alternate['@_href'].trim();
    const firstHref = linkField.find(l => l?.['@_href']);
    if (firstHref) return firstHref['@_href'].trim();
    const firstStr = linkField.find(l => typeof l === 'string');
    if (firstStr) return firstStr.trim();
  }
  if (typeof linkField === 'object') {
    return (linkField['@_href'] || linkField['#text'] || '').trim();
  }
  return '';
}

function extractText(field) {
  if (!field) return '';
  if (typeof field === 'string' || typeof field === 'number') return String(field);
  if (Array.isArray(field)) {
    return field.map(extractText).filter(Boolean).join(' ');
  }
  if (typeof field === 'object') {
    if (field['#text'] && Object.keys(field).length === 1) {
      return String(field['#text']);
    }
    if (field.__cdata) return String(field.__cdata);
    const parts = [];
    for (const [k, v] of Object.entries(field)) {
      if (k.startsWith('@_')) continue;
      const sub = extractText(v);
      if (sub) parts.push(sub);
    }
    return parts.join(' ');
  }
  return '';
}

function normalizeUrl(rawUrl = '') {
  try {
    const u = new URL(rawUrl.trim());
    for (const param of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content']) {
      u.searchParams.delete(param);
    }
    return u.toString();
  } catch {
    return rawUrl.trim();
  }
}

async function fetchWithRetry(url, options = {}, retries = 2) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(15000),
      });
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 1200 * (attempt + 1)));
      }
    }
  }
  throw lastErr;
}

async function fetchRssOrAtomFeed(feedConfig) {
  try {
    const res = await fetchWithRetry(feedConfig.url, {
      headers: {
        'User-Agent': 'CybersecurityDigestMCP/1.0 (+https://github.com/williambulk/cybersecurity-digest-mcp)',
        Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
      },
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const xml = await res.text();
    const parsed = xmlParser.parse(xml);
    const items = [];

    const rssItems = parsed?.rss?.channel?.item;
    if (rssItems) {
      const list = Array.isArray(rssItems) ? rssItems : [rssItems];
      for (const entry of list) {
        const title = decodeHtmlEntities(extractText(entry.title));
        const link = normalizeUrl(extractAtomLink(entry.link));
        const description = decodeHtmlEntities(
          extractText(entry.description || entry['content:encoded'] || '')
        ).slice(0, 600);
        const pubDateRaw = extractText(entry.pubDate || entry['dc:date'] || '');
        const publishedAt = pubDateRaw ? new Date(pubDateRaw) : new Date();

        if (title && link) {
          items.push({
            title,
            url: link,
            summary: description,
            publishedAt: isNaN(publishedAt.getTime()) ? new Date() : publishedAt,
            source: feedConfig.name,
            category: feedConfig.category,
            defaultPlatform: feedConfig.defaultPlatform,
            alwaysRelevant: Boolean(feedConfig.alwaysRelevant),
          });
        }
      }
    }

    const atomEntries = parsed?.feed?.entry;
    if (atomEntries) {
      const list = Array.isArray(atomEntries) ? atomEntries : [atomEntries];
      for (const entry of list) {
        const title = decodeHtmlEntities(extractText(entry.title));
        const link = normalizeUrl(extractAtomLink(entry.link) || extractText(entry.id));
        const summary = decodeHtmlEntities(
          extractText(entry.summary || entry.content || '')
        ).slice(0, 600);
        const pubDateRaw = extractText(entry.published || entry.updated || entry['dc:date'] || '');
        const publishedAt = pubDateRaw ? new Date(pubDateRaw) : new Date();

        if (title && link && link.startsWith('http')) {
          items.push({
            title,
            url: link,
            summary,
            publishedAt: isNaN(publishedAt.getTime()) ? new Date() : publishedAt,
            source: feedConfig.name,
            category: feedConfig.category,
            defaultPlatform: feedConfig.defaultPlatform,
            alwaysRelevant: Boolean(feedConfig.alwaysRelevant),
          });
        }
      }
    }

    return items;
  } catch (err) {
    console.error(`[Collector Warning] Failed to fetch ${feedConfig.name}: ${err.message}`);
    return [];
  }
}

async function fetchGitHubAdvisories(ecosystem) {
  const url = `https://api.github.com/advisories?ecosystem=${encodeURIComponent(ecosystem)}&per_page=30`;
  try {
    const res = await fetchWithRetry(url, {
      headers: {
        'User-Agent': 'CybersecurityDigestMCP/1.0',
        Accept: 'application/vnd.github+json',
      },
    });

    if (!res.ok) return [];
    const data = await res.json();
    if (!Array.isArray(data)) return [];

    return data.map(adv => {
      const pkgNames = (adv.vulnerabilities || [])
        .map(v => v?.package?.name)
        .filter(Boolean);
      const uniquePkgs = [...new Set(pkgNames)];
      const pkgPrefix = uniquePkgs.length > 0 ? `${uniquePkgs.slice(0, 2).join(', ')}: ` : '';
      const cveLabel = adv.cve_id ? ` (${adv.cve_id})` : ` (${adv.ghsa_id})`;
      const severity = (adv.severity || 'moderate').toUpperCase();

      return {
        title: `${pkgPrefix}${decodeHtmlEntities(adv.summary || 'Security Advisory')}${cveLabel}`,
        url: adv.html_url || `https://github.com/advisories/${adv.ghsa_id}`,
        summary: decodeHtmlEntities(adv.description || '').slice(0, 600),
        publishedAt: new Date(adv.published_at || adv.updated_at || Date.now()),
        source: `GitHub Security Advisory (${ecosystem})`,
        category: 'security',
        severityHint: severity,
        ecosystem,
        packages: uniquePkgs,
        defaultPlatform: ecosystem === 'composer' ? 'PHP' : 'JavaScript',
        alwaysRelevant: false,
      };
    });
  } catch (err) {
    console.error(`[Collector Warning] GitHub Advisories (${ecosystem}) failed: ${err.message}`);
    return [];
  }
}

async function fetchCisaKev() {
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  try {
    const res = await fetchWithRetry(url, {
      headers: { 'User-Agent': 'CybersecurityDigestMCP/1.0' },
    });
    if (!res.ok) return [];
    const data = await res.json();
    const vulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];

    const recent = vulns
      .slice()
      .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
      .slice(0, 25);

    return recent.map(v => ({
      title: `[Actively Exploited] ${v.vendorProject} ${v.product}: ${v.vulnerabilityName} (${v.cveID})`,
      url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      summary: decodeHtmlEntities(v.shortDescription || ''),
      publishedAt: new Date(`${v.dateAdded}T12:00:00Z`),
      source: 'CISA Known Exploited Vulnerabilities',
      category: 'security',
      severityHint: 'CRITICAL',
      defaultPlatform: 'SecOps / Breach',
      alwaysRelevant: false,
    }));
  } catch (err) {
    console.error(`[Collector Warning] CISA KEV fetch failed: ${err.message}`);
    return [];
  }
}

async function checkSingleDomainHealth(domainEntry) {
  const raw = typeof domainEntry === 'string' ? domainEntry.trim() : domainEntry?.domain || domainEntry?.url || '';
  const provider = typeof domainEntry === 'object' && domainEntry?.provider ? domainEntry.provider : 'Hosting';
  if (!raw) return null;
  const label = raw.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  const candidateUrls = [`https://${label}`, `http://${label}`];

  let lastStatus = 0;
  let lastError = null;

  for (const url of candidateUrls) {
    try {
      const res = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SiteHealthCheck/1.0',
        },
        signal: AbortSignal.timeout(9000),
      });
      lastStatus = res.status;
      if (res.status < 500) {
        return {
          domain: label,
          provider,
          url,
          up: true,
          status: res.status,
          statusText: `Online (HTTP ${res.status})`,
        };
      }
      lastError = `HTTP ${res.status}`;
    } catch (err) {
      lastError = err?.cause?.code || err.message || 'Unreachable';
    }
  }

  return {
    domain: label,
    provider,
    url: `https://${label}`,
    up: false,
    status: lastStatus || 0,
    statusText: lastError || 'Unreachable',
  };
}

export async function checkMonitoredDomains(domains = MONITORED_DOMAINS) {
  if (!Array.isArray(domains) || domains.length === 0) {
    return {
      configured: false,
      totalChecked: 0,
      allUp: true,
      downSites: [],
      results: [],
      byProvider: {},
    };
  }

  const results = [];
  const batchSize = 16;
  for (let i = 0; i < domains.length; i += batchSize) {
    const batch = domains.slice(i, i + batchSize);
    const checked = await Promise.all(batch.map(d => checkSingleDomainHealth(d)));
    results.push(...checked.filter(Boolean));
  }

  const downSites = results.filter(r => !r.up);
  const byProvider = {};
  for (const r of results) {
    if (!byProvider[r.provider]) {
      byProvider[r.provider] = { total: 0, up: 0, down: [] };
    }
    byProvider[r.provider].total += 1;
    if (r.up) {
      byProvider[r.provider].up += 1;
    } else {
      byProvider[r.provider].down.push(r);
    }
  }

  return {
    configured: true,
    totalChecked: results.length,
    allUp: downSites.length === 0,
    downSites,
    results,
    byProvider,
  };
}

async function checkStatuspageProvider(provider) {
  try {
    const res = await fetchWithRetry(provider.summaryUrl, {
      headers: {
        'User-Agent': 'CybersecurityDigestMCP/1.0',
        Accept: 'application/json',
      },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const indicator = data?.status?.indicator || 'none';
    const description = data?.status?.description || 'All Systems Operational';
    const rawIncidents = Array.isArray(data?.incidents) ? data.incidents : [];

    const activeIncidents = rawIncidents.filter(inc => {
      const impact = String(inc?.impact || '').toLowerCase();
      const status = String(inc?.status || '').toLowerCase();
      const name = String(inc?.name || '');
      if (impact === 'maintenance' || status === 'scheduled' || status === 'completed') return false;
      if (/\b(scheduled\s+maintenance|maintenance\s+window)\b/i.test(name)) return false;
      return status !== 'resolved' && status !== 'postmortem';
    });

    const rawComponents = Array.isArray(data?.components) ? data.components : [];
    const degradedComponents = rawComponents.filter(c => {
      const st = String(c?.status || '').toLowerCase();
      if (!['degraded_performance', 'partial_outage', 'major_outage'].includes(st)) return false;
      if (provider.name === 'Cloudflare' && /\([A-Z]{3}\)/.test(c?.name || '')) return false;
      return true;
    });

    const hasIssue =
      activeIncidents.length > 0 ||
      (indicator !== 'none' && indicator !== 'maintenance' && degradedComponents.length > 0);

    let detail = description;
    let incidentUrl = provider.pageUrl;
    let latestUpdateText = '';
    let incidentUpdatedAt = new Date();

    if (activeIncidents.length > 0) {
      const top = activeIncidents[0];
      detail = `${top.name} (${top.status || indicator})`;
      incidentUrl = top.shortlink || provider.pageUrl;
      const latestUpdate = Array.isArray(top.incident_updates) ? top.incident_updates[0] : null;
      latestUpdateText = decodeHtmlEntities(latestUpdate?.body || '');
      incidentUpdatedAt = new Date(top.updated_at || top.created_at || Date.now());
    } else if (degradedComponents.length > 0) {
      const compNames = degradedComponents.slice(0, 3).map(c => c.name).join(', ');
      detail = `Degraded/Outage: ${compNames}`;
    }

    return {
      name: provider.name,
      operational: !hasIssue,
      statusText: hasIssue ? detail : 'Operational',
      url: incidentUrl,
      pageUrl: provider.pageUrl,
      summary: latestUpdateText,
      updatedAt: incidentUpdatedAt,
    };
  } catch {
    return {
      name: provider.name,
      operational: true,
      statusText: 'Operational',
      url: provider.pageUrl,
      pageUrl: provider.pageUrl,
      summary: '',
      updatedAt: new Date(),
    };
  }
}

async function checkHtmlOrRssStatusProvider(provider) {
  try {
    if (provider.rssUrl) {
      try {
        const rssItems = await fetchRssOrAtomFeed({
          name: `${provider.name} Status`,
          url: provider.rssUrl,
          category: 'status',
          defaultPlatform: provider.name,
          alwaysRelevant: true,
        });

        const now = Date.now();
        const recentIncident = rssItems.find(item => {
          const ageHours = (now - item.publishedAt.getTime()) / (1000 * 60 * 60);
          if (ageHours > 12) return false;
          const text = `${item.title} ${item.summary}`;
          if (
            /\b(scheduled\s+maintenance|resolved|completed|all\s+systems\s+operational)\b/i.test(text) &&
            !/\b(investigating|identified|outage|down|degraded)\b/i.test(item.title)
          ) {
            return false;
          }
          return /\b(investigating|identified|outage|down|degraded|incident|issue|disruption|unava)\b/i.test(text);
        });

        if (recentIncident) {
          return {
            name: provider.name,
            operational: false,
            statusText: recentIncident.title,
            url: recentIncident.url || provider.pageUrl,
            pageUrl: provider.pageUrl,
            summary: recentIncident.summary || '',
            updatedAt: recentIncident.publishedAt,
          };
        }
      } catch {
        // Fallback to HTML check
      }
    }

    const res = await fetchWithRetry(provider.pageUrl, {
      headers: { 'User-Agent': 'CybersecurityDigestMCP/1.0' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const html = await res.text();
    const cleanText = decodeHtmlEntities(html);

    const hasOperationalBanner =
      /\b(all\s+systems\s+operational|all\s+services\s+are\s+operating\s+normally|no\s+problems\s+detected|fully\s+operational)\b/i.test(
        cleanText
      );
    const hasActiveIncidentBanner =
      /\b(currently\s+investigating|we\s+are\s+investigating|active\s+incident|experiencing\s+issues)\b/i.test(
        cleanText
      );
    const isOperational = hasOperationalBanner || !hasActiveIncidentBanner;

    return {
      name: provider.name,
      operational: isOperational,
      statusText: isOperational ? 'Operational' : 'Service Notice / Degraded Performance',
      url: provider.pageUrl,
      pageUrl: provider.pageUrl,
      summary: isOperational ? '' : `Check ${provider.pageUrl} for live component details.`,
      updatedAt: new Date(),
    };
  } catch {
    return {
      name: provider.name,
      operational: true,
      statusText: 'Operational',
      url: provider.pageUrl,
      pageUrl: provider.pageUrl,
      summary: '',
      updatedAt: new Date(),
    };
  }
}

async function checkSiteGroundStatus(provider) {
  try {
    const res = await fetchWithRetry(provider.checkUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' },
    });

    if (res.status >= 500) {
      return {
        name: provider.name,
        operational: false,
        statusText: `HTTP ${res.status} Server Error on ${provider.checkUrl}`,
        url: provider.pageUrl,
        pageUrl: provider.pageUrl,
        summary: `SiteGround control panel endpoint returned HTTP ${res.status}.`,
        updatedAt: new Date(),
      };
    }

    return {
      name: provider.name,
      operational: true,
      statusText: 'Operational',
      url: provider.pageUrl,
      pageUrl: provider.pageUrl,
      summary: '',
      updatedAt: new Date(),
    };
  } catch (err) {
    return {
      name: provider.name,
      operational: false,
      statusText: `Connection Timeout / Unreachable (${err.message})`,
      url: provider.pageUrl,
      pageUrl: provider.pageUrl,
      summary: `Could not reach ${provider.checkUrl}: ${err.message}`,
      updatedAt: new Date(),
    };
  }
}

export async function collectInfrastructureStatuses() {
  const [domainHealth, providerChecks] = await Promise.all([
    checkMonitoredDomains(MONITORED_DOMAINS),
    Promise.all(
      INFRASTRUCTURE_PROVIDERS.map(provider => {
        if (provider.type === 'statuspage') return checkStatuspageProvider(provider);
        if (provider.type === 'siteground') return checkSiteGroundStatus(provider);
        return checkHtmlOrRssStatusProvider(provider);
      })
    ),
  ]);

  const incidentItems = [];

  if (domainHealth.configured && !domainHealth.allUp) {
    const providerStatusMap = Object.fromEntries(providerChecks.map(p => [p.name, p]));
    const cloudflareStatus = providerStatusMap['Cloudflare'];

    for (const downSite of domainHealth.downSites) {
      const hostStatus = providerStatusMap[downSite.provider];
      const correlatedIssues = [];
      if (hostStatus && !hostStatus.operational) {
        correlatedIssues.push(`${hostStatus.name} reports: ${hostStatus.statusText}`);
      }
      if (cloudflareStatus && !cloudflareStatus.operational) {
        correlatedIssues.push(`Cloudflare reports: ${cloudflareStatus.statusText}`);
      }

      const correlationNote =
        correlatedIssues.length > 0
          ? correlatedIssues.join(' | ')
          : `${downSite.provider} & Cloudflare status pages report Operational — issue appears isolated to ${downSite.domain}.`;

      incidentItems.push({
        title: `[${downSite.provider}] ${downSite.domain} is unreachable (${downSite.statusText})`,
        url: hostStatus && !hostStatus.operational ? hostStatus.url : downSite.url,
        summary: correlationNote,
        publishedAt: new Date(),
        source: 'Site Health Monitor',
        category: 'incident',
        severityHint: 'CRITICAL',
        defaultPlatform: downSite.provider,
        alwaysRelevant: true,
        isInfrastructureIncident: true,
      });
    }
  }

  return {
    statuses: providerChecks,
    domainHealth,
    incidentItems,
  };
}

export async function collectAllRawItems({ forceRefresh = false } = {}) {
  const now = Date.now();
  if (!forceRefresh && cachedRawItems && now - cacheTimestamp < CACHE_TTL_MS) {
    return cachedRawItems;
  }

  const flatRss = [];
  const batchSize = 4;
  for (let i = 0; i < RSS_FEEDS.length; i += batchSize) {
    const batch = RSS_FEEDS.slice(i, i + batchSize);
    const results = await Promise.all(batch.map(f => fetchRssOrAtomFeed(f)));
    flatRss.push(...results.flat());
  }

  const [npmAdvisories, composerAdvisories, cisaItems, infraResult] = await Promise.all([
    fetchGitHubAdvisories('npm'),
    fetchGitHubAdvisories('composer'),
    fetchCisaKev(),
    collectInfrastructureStatuses(),
  ]);

  const all = [
    ...infraResult.incidentItems,
    ...flatRss,
    ...npmAdvisories,
    ...composerAdvisories,
    ...cisaItems,
  ];
  all.infrastructureStatuses = infraResult.statuses;
  all.domainHealth = infraResult.domainHealth;
  cachedRawItems = all;
  cacheTimestamp = Date.now();
  return all;
}
