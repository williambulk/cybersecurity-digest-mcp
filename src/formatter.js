import { CONFIG } from './config.js';

export function getLocalDateString(date = new Date()) {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: CONFIG.timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });
  return formatter.format(date); // YYYY-MM-DD
}

export function getReadableDateHeader(date = new Date()) {
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: CONFIG.timezone,
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
  return formatter.format(date);
}

export function getReadableDateTimeHeader(date = new Date()) {
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: CONFIG.timezone,
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
  });
  return formatter.format(date);
}

function sanitizeForSlackPlainText(str = '') {
  return String(str)
    .replace(/`([^`]+)`/g, "'$1'")
    .replace(/(^|\s)##+\s*/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .trim();
}

function formatSectionItems(items, { useMarkdown = true } = {}) {
  return items
    .map(item => {
      const prefix = item.platform ? `[${item.platform}] ` : '';
      const cleanTitle = item.title.startsWith(`[${item.platform}]`)
        ? item.title
        : `${prefix}${item.title}`;
      if (!useMarkdown) {
        return `• ${sanitizeForSlackPlainText(cleanTitle)}\n  🔗 ${item.url}`;
      }
      return `• *${cleanTitle}*\n  🔗 ${item.url}`;
    })
    .join('\n\n');
}

function formatSiteAndHostingStatusBlock(
  infrastructureStatuses = [],
  domainHealth = null,
  { useMarkdown = true } = {}
) {
  const lines = [];

  if (domainHealth && domainHealth.configured) {
    const breakdownParts = Object.entries(domainHealth.byProvider || {}).map(
      ([prov, stats]) => `${prov}: ${stats.up}/${stats.total}`
    );
    const breakdownStr = breakdownParts.length > 0 ? ` (${breakdownParts.join(' • ')})` : '';

    if (domainHealth.allUp) {
      lines.push(
        useMarkdown
          ? `✅ *Monitored Sites (${domainHealth.totalChecked}/${domainHealth.totalChecked} Online)*${breakdownStr}`
          : `✅ Monitored Sites (${domainHealth.totalChecked}/${domainHealth.totalChecked} Online)${breakdownStr}`
      );
    } else {
      const upCount = domainHealth.totalChecked - domainHealth.downSites.length;
      lines.push(
        useMarkdown
          ? `⚠️ *Monitored Sites (${upCount}/${domainHealth.totalChecked} Online)*${breakdownStr}`
          : `⚠️ Monitored Sites (${upCount}/${domainHealth.totalChecked} Online)${breakdownStr}`
      );
      for (const down of domainHealth.downSites) {
        lines.push(
          useMarkdown
            ? `   • *[${down.provider}] ${down.domain}:* ${down.statusText}`
            : `   • [${down.provider}] ${down.domain}: ${down.statusText}`
        );
      }
    }
  }

  if (Array.isArray(infrastructureStatuses) && infrastructureStatuses.length > 0) {
    const names = infrastructureStatuses.map(s => s.name).join(' • ');
    if (!domainHealth || domainHealth.allUp) {
      lines.push(
        useMarkdown
          ? `🟢 *Hosting & CDN:* No Impact on Our Sites (${names})`
          : `🟢 Hosting & CDN: No Impact on Our Sites (${names})`
      );
    } else {
      for (const s of infrastructureStatuses) {
        const icon = s.operational ? '🟢' : '⚠️';
        const label = useMarkdown ? `*${s.name}:*` : `${s.name}:`;
        if (s.operational) {
          lines.push(`${icon} ${label} Operational`);
        } else {
          lines.push(`${icon} ${label} ${s.statusText} (${s.url})`);
        }
      }
    }
  }

  return lines.join('\n');
}

export function formatWhatsAppDigest({
  grouped,
  allSelected,
  infrastructureStatuses = [],
  domainHealth = null,
}) {
  const dateHeader = getReadableDateHeader();
  const devNewsItems = grouped?.HIGH || allSelected || [];
  const statusBlock = formatSiteAndHostingStatusBlock(infrastructureStatuses, domainHealth, {
    useMarkdown: true,
  });

  const lines = [
    `🗞️ *Daily Stack & Dev Digest — ${dateHeader}*`,
    `_Stack: PHP • WordPress • Sanity • Statamic • JS • Nuxt • Next.js_`,
  ];

  if (statusBlock) {
    lines.push(``, `🌐 *SITES & HOSTING STATUS*`, statusBlock);
  }

  if (devNewsItems.length === 0) {
    lines.push(
      ``,
      `📰 *DEV NEWS (0)*`,
      `✅ No major stack advisories or breaking updates in the last 24h.`
    );
  } else {
    lines.push(
      ``,
      `📰 *DEV NEWS (${devNewsItems.length})*`,
      `_Notable stack updates, security advisories & release notes_`,
      ``,
      formatSectionItems(devNewsItems, { useMarkdown: true })
    );
  }

  return lines.join('\n');
}

export function formatSlackDigest(
  { grouped, allSelected, infrastructureStatuses = [], domainHealth = null },
  webhookUrl = CONFIG.slackWebhookUrl
) {
  const isWorkflowTrigger = String(webhookUrl || '').includes('/triggers/');
  if (!isWorkflowTrigger) {
    return formatWhatsAppDigest({ grouped, allSelected, infrastructureStatuses, domainHealth });
  }

  const dateHeader = getReadableDateHeader();
  const devNewsItems = grouped?.HIGH || allSelected || [];
  const statusBlock = formatSiteAndHostingStatusBlock(infrastructureStatuses, domainHealth, {
    useMarkdown: false,
  });

  const lines = [
    `🗞️ Daily Stack & Dev Digest — ${dateHeader}`,
    `Stack: PHP • WordPress • Sanity • Statamic • JS • Nuxt • Next.js`,
  ];

  if (statusBlock) {
    lines.push(
      ``,
      `────────────────────────────────────────`,
      `🌐 SITES & HOSTING STATUS`,
      statusBlock
    );
  }

  if (devNewsItems.length === 0) {
    lines.push(
      ``,
      `────────────────────────────────────────`,
      `📰 DEV NEWS (0)`,
      `✅ No major stack advisories or breaking updates in the last 24h.`
    );
  } else {
    lines.push(
      ``,
      `────────────────────────────────────────`,
      `📰 DEV NEWS (${devNewsItems.length})`,
      `Notable stack updates, security advisories & release notes`,
      ``,
      formatSectionItems(devNewsItems, { useMarkdown: false })
    );
  }

  return lines.join('\n');
}

export function formatUrgentFlashAlert(
  urgentItems,
  { forSlackWebhook = false, webhookUrl = CONFIG.slackWebhookUrl } = {}
) {
  const isWorkflowTrigger = forSlackWebhook && String(webhookUrl || '').includes('/triggers/');
  const dateTimeHeader = getReadableDateTimeHeader();
  const hasSiteOutage = urgentItems.some(i => i.isInfrastructureIncident);

  const headerTitle = hasSiteOutage
    ? '⚠️ Site & Hosting Status Update'
    : '🔔 Dev News & Stack Update';

  const itemBlocks = urgentItems
    .map(item => {
      const prefix = item.platform ? `[${item.platform}] ` : '';
      const cleanTitle = item.title.startsWith(`[${item.platform}]`)
        ? item.title
        : `${prefix}${item.title}`;
      const rawSnippet = item.summary
        ? `${item.summary.slice(0, 140).trim()}${item.summary.length > 140 ? '…' : ''}`
        : '';

      if (isWorkflowTrigger) {
        const plainTitle = sanitizeForSlackPlainText(cleanTitle);
        const plainSnippet = sanitizeForSlackPlainText(rawSnippet);
        const snippet = plainSnippet ? `\n  ${plainSnippet}` : '';
        return `• ${plainTitle}${snippet}\n  🔗 ${item.url}`;
      }

      const snippet = rawSnippet ? `\n  _${rawSnippet}_` : '';
      return `• *${cleanTitle}*${snippet}\n  🔗 ${item.url}`;
    })
    .join('\n\n');

  if (isWorkflowTrigger) {
    return [
      `${headerTitle} — ${dateTimeHeader}`,
      `────────────────────────────────────────`,
      itemBlocks,
    ].join('\n');
  }

  return [
    `*${headerTitle}*`,
    `_${dateTimeHeader}_`,
    ``,
    itemBlocks,
  ].join('\n');
}
