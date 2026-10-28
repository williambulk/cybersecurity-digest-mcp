import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ROOT_DIR = path.resolve(__dirname, '..');
dotenv.config({ path: path.join(ROOT_DIR, '.env'), quiet: true });

export const DATA_DIR = path.join(ROOT_DIR, 'data');
export const LOGS_DIR = path.join(ROOT_DIR, 'logs');
export const STATE_FILE = path.join(DATA_DIR, 'state.json');
export const HISTORY_FILE = path.join(DATA_DIR, 'sent_history.json');
export const URGENT_HISTORY_FILE = path.join(DATA_DIR, 'urgent_history.json');

export const CONFIG = {
  slackWebhookUrl: (process.env.SLACK_WEBHOOK_URL || '').trim(),
  geminiApiKey: (process.env.GEMINI_API_KEY || '').trim(),
  geminiModel: (process.env.GEMINI_MODEL || 'gemini-3.8-flash').trim(),
  timezone: process.env.TIMEZONE || 'America/Vancouver',
  businessHoursStart: Number(process.env.BUSINESS_HOURS_START ?? 8),
  businessHoursEnd: Number(process.env.BUSINESS_HOURS_END ?? 18),
  lookbackHours: Number(process.env.LOOKBACK_HOURS || 72),
  urgentLookbackHours: Number(process.env.URGENT_LOOKBACK_HOURS || 72),
  releaseLookbackHours: Number(process.env.RELEASE_LOOKBACK_HOURS || 240),
  maxItemsPerDigest: Number(process.env.MAX_ITEMS_PER_DIGEST || 12),
  dataDir: DATA_DIR,
  stateFile: STATE_FILE,
  sentHistoryFile: HISTORY_FILE,
  urgentHistoryFile: URGENT_HISTORY_FILE,
};

export function parseMonitoredDomains(raw = '') {
  const trimmed = String(raw || '').trim();
  if (!trimmed) return [];

  // Support JSON array format: [{"domain":"example.com","provider":"Kinsta"}]
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return parsed
          .filter(d => d && d.domain)
          .map(d => ({
            domain: String(d.domain).trim().replace(/^https?:\/\//i, '').replace(/\/+$/, ''),
            provider: String(d.provider || 'Hosted').trim(),
          }));
      }
    } catch {}
  }

  // Support compact provider-grouped format: "WP Engine=d1,d2|Kinsta=d3,d4"
  const results = [];
  const groups = trimmed.split('|').map(g => g.trim()).filter(Boolean);
  for (const group of groups) {
    const eqIdx = group.indexOf('=');
    if (eqIdx === -1) continue;
    const provider = group.slice(0, eqIdx).trim();
    const domainsList = group
      .slice(eqIdx + 1)
      .split(',')
      .map(d => d.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, ''))
      .filter(Boolean);
    for (const domain of domainsList) {
      results.push({ domain, provider });
    }
  }
  return results;
}

// Production domains grouped by their hosting provider (loaded from MONITORED_DOMAINS in .env)
export const MONITORED_DOMAINS = parseMonitoredDomains(process.env.MONITORED_DOMAINS);

export const INFRASTRUCTURE_PROVIDERS = [
  {
    name: 'Cloudflare',
    type: 'statuspage',
    summaryUrl: 'https://www.cloudflarestatus.com/api/v2/summary.json',
    pageUrl: 'https://www.cloudflarestatus.com',
  },
  {
    name: 'Kinsta',
    type: 'statuspage',
    summaryUrl: 'https://status.kinsta.com/api/v2/summary.json',
    pageUrl: 'https://status.kinsta.com',
  },
  {
    name: 'WP Engine',
    type: 'wpengine',
    rssUrl: 'https://wpenginestatus.com/rss',
    pageUrl: 'https://wpenginestatus.com',
  },
  {
    name: 'Fly.io',
    type: 'statuspage',
    summaryUrl: 'https://status.flyio.net/api/v2/summary.json',
    pageUrl: 'https://status.flyio.net',
  },
  {
    name: 'Pantheon',
    type: 'statuspage',
    summaryUrl: 'https://status.pantheon.io/api/v2/summary.json',
    pageUrl: 'https://status.pantheon.io',
  },
  {
    name: 'Ploi.io',
    type: 'ploi',
    rssUrl: 'https://status.ploi.io/rss',
    pageUrl: 'https://status.ploi.io',
  },
  {
    name: 'SiteGround',
    type: 'siteground',
    checkUrl: 'https://login.siteground.com',
    isDownUrl: 'https://isdown.app/integrations/siteground',
    pageUrl: 'https://www.siteground.com',
  },
];

export const RSS_FEEDS = [
  // Official Platform Releases & Breaking Changes
  {
    name: 'Next.js Releases',
    url: 'https://github.com/vercel/next.js/releases.atom',
    category: 'release',
    defaultPlatform: 'Next.js',
    alwaysRelevant: true,
  },
  {
    name: 'Nuxt.js Releases',
    url: 'https://github.com/nuxt/nuxt/releases.atom',
    category: 'release',
    defaultPlatform: 'Nuxt.js',
    alwaysRelevant: true,
  },
  {
    name: 'Statamic CMS Releases',
    url: 'https://github.com/statamic/cms/releases.atom',
    category: 'release',
    defaultPlatform: 'Statamic CMS',
    alwaysRelevant: true,
  },
  {
    name: 'Sanity CMS Releases',
    url: 'https://github.com/sanity-io/sanity/releases.atom',
    category: 'release',
    defaultPlatform: 'Sanity CMS',
    alwaysRelevant: true,
  },
  {
    name: 'WordPress Official News',
    url: 'https://wordpress.org/news/feed/',
    category: 'release',
    defaultPlatform: 'WordPress',
    alwaysRelevant: true,
  },
  {
    name: 'PHP Official News & Releases',
    url: 'https://www.php.net/feed.atom',
    category: 'release',
    defaultPlatform: 'PHP',
    alwaysRelevant: true,
  },
  {
    name: 'Node.js Blog & Security',
    url: 'https://nodejs.org/en/feed/blog.xml',
    category: 'release',
    defaultPlatform: 'JavaScript',
    alwaysRelevant: true,
  },

  // Authoritative Cybersecurity & Vulnerability Research Feeds
  {
    name: 'Wordfence Threat Intelligence',
    url: 'https://www.wordfence.com/feed/',
    category: 'security',
    defaultPlatform: 'WordPress',
    alwaysRelevant: true,
  },
  {
    name: 'Patchstack Security',
    url: 'https://patchstack.com/feed/',
    category: 'security',
    defaultPlatform: 'WordPress',
    alwaysRelevant: true,
  },
  {
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    category: 'security',
    defaultPlatform: null,
    alwaysRelevant: false,
  },
  {
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    category: 'security',
    defaultPlatform: null,
    alwaysRelevant: false,
  },
];

export const PLATFORM_RULES = [
  {
    platform: 'WordPress',
    pattern: /\b(wordpress|wp-content|wp-admin|woocommerce|elementor|gutenberg|acf|advanced custom fields|yoast|wpforms|contact form 7|wordfence|patchstack|wpscan|litespeed cache|jetpack)\b/i,
  },
  {
    platform: 'Next.js',
    pattern: /\b(next\.?js|@next\/|@sentry\/nextjs|vercel|turbopack|next-auth|auth\.js)\b/i,
  },
  {
    platform: 'Nuxt.js',
    pattern: /\b(nuxt\.?js|@nuxt\/|nuxt\s*[34]?|unjs|nitro|nitropack|h3|ofetch)\b/i,
  },
  {
    platform: 'Sanity CMS',
    pattern: /\b(sanity(?:\s+cms|\s+studio|\.io)?|groq|@sanity\/)\b/i,
  },
  {
    platform: 'Statamic CMS',
    pattern: /\b(statamic(?:\s+cms)?|antlers|laravel|livewire|filament|symfony)\b/i,
  },
  {
    platform: 'PHP',
    pattern: /\b(php\s*[789]?|php2shell|composer|packagist|phpmailer|guzzle|phpunit|pdo|xdebug|fpm)\b/i,
  },
  {
    platform: 'JavaScript',
    pattern: /\b(javascript|typescript|node\.?js|npm|pnpm|yarn|bun|deno|v8\s+engine|react|vue\.?js|vite|webpack|axios|express\.?js|eslint|polyfill|supply[- ]chain\s+attack)\b/i,
  },
  {
    platform: 'SecOps / Breach',
    pattern: /\b(cloudflare|kinsta|wp\s*engine|fly\.io|pantheon|ploi\.?io|siteground|digitalocean|github|gitlab|aws|s3\s+bucket|docker|nginx|apache|openssh|openssl|let's\s+encrypt|oauth|jwt|passkey|ransomware|data\s+breach|zero[- ]day|actively\s+exploited|cve-202\d-\d+|supply[- ]chain)\b/i,
  },
];
