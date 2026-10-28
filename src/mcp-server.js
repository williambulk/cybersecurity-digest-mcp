#!/usr/bin/env node
import fs from 'fs';
import {
  CONFIG,
  DATA_DIR,
  HISTORY_FILE,
  URGENT_HISTORY_FILE,
  RSS_FEEDS,
} from './config.js';
import { collectAllRawItems } from './collectors.js';
import {
  filterAndPrioritizeItems,
  filterUrgentEmergencyItems,
  searchStackAdvisories,
} from './analyzer.js';
import {
  formatSlackDigest,
  formatMarkdownDigest,
  formatUrgentFlashAlert,
} from './formatter.js';
import { postToSlackWebhook } from './slack.js';

const SERVER_INFO = {
  name: 'cybersecurity-digest-mcp',
  version: '1.0.0',
};

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function loadJson(filePath, defaultValue = {}) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
  } catch (err) {
    console.error(`[MCP Storage Warning] Could not read ${filePath}: ${err.message}`);
  }
  return defaultValue;
}

function saveJson(filePath, data) {
  ensureDataDir();
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function pruneHistory(historyObj) {
  const maxAgeMs = 30 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  const pruned = {};
  for (const [key, entry] of Object.entries(historyObj)) {
    const ts = entry?.sentAt ? new Date(entry.sentAt).getTime() : 0;
    if (now - ts <= maxAgeMs) {
      pruned[key] = entry;
    }
  }
  return pruned;
}

const TOOLS = [
  {
    name: 'get_daily_security_digest',
    description:
      'Check configured production domains (MONITORED_DOMAINS), 7 hosting status pages (Cloudflare, Kinsta, WP Engine, Fly.io, Pantheon, Ploi.io, SiteGround), and cybersecurity/release feeds to generate the Daily Stack & Dev Digest. Returns ready-to-post Slack, Markdown, or JSON output.',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          enum: ['slack', 'markdown', 'json'],
          default: 'slack',
          description: 'Output format (default: "slack").',
        },
        lookbackHours: {
          type: 'number',
          default: 72,
          description: 'Lookback window in hours for security advisories and news (default: 72).',
        },
        maxItems: {
          type: 'number',
          default: 15,
          description: 'Maximum number of prioritized items to include in the digest (default: 15).',
        },
        platforms: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Optional list of platforms to filter by (e.g. ["WordPress", "PHP", "Next.js", "Nuxt.js", "Sanity CMS", "Statamic CMS", "JavaScript", "SecOps / Breach"]).',
        },
        deduplicate: {
          type: 'boolean',
          default: false,
          description:
            'If true, skips items already recorded in local sent_history.json and records the newly returned items.',
        },
        forceRefresh: {
          type: 'boolean',
          default: false,
          description: 'If true, bypasses the 60-second in-memory feed cache and re-fetches all feeds.',
        },
      },
    },
  },
  {
    name: 'get_urgent_security_alerts',
    description:
      'Check all 14 security feeds, GitHub Security Advisories (npm & composer), and CISA KEV for critical/emergency zero-days, unauthenticated RCEs, and official vendor security pre-notifications affecting PHP, WordPress, Sanity CMS, Statamic CMS, JavaScript/Node.js, Nuxt.js, and Next.js.',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          enum: ['slack', 'markdown', 'json'],
          default: 'slack',
          description: 'Output format (default: "slack").',
        },
        lookbackHours: {
          type: 'number',
          default: 72,
          description: 'Lookback window in hours for emergency alerts (default: 72).',
        },
        deduplicate: {
          type: 'boolean',
          default: false,
          description:
            'If true, skips alerts already recorded in urgent_history.json and saves newly returned alerts.',
        },
        forceRefresh: {
          type: 'boolean',
          default: false,
          description: 'If true, bypasses the 60-second in-memory feed cache.',
        },
      },
    },
  },
  {
    name: 'search_stack_advisories',
    description:
      'Search live cybersecurity feeds, GitHub Security Advisories (npm & composer), CISA KEV, and official platform release notes by keyword, CVE ID, package name, priority, or platform.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Keyword, CVE ID, GHSA ID, or package name to search for (e.g. "Next.js", "woocommerce", "RCE", "CVE-2026").',
        },
        platform: {
          type: 'string',
          description:
            'Optional platform filter (e.g. "WordPress", "PHP", "Next.js", "Nuxt.js", "Sanity CMS", "Statamic CMS", "JavaScript", "SecOps / Breach").',
        },
        priority: {
          type: 'string',
          enum: ['HIGH', 'MEDIUM', 'LOW'],
          description: 'Optional priority filter.',
        },
        lookbackHours: {
          type: 'number',
          default: 168,
          description: 'Lookback window in hours (default: 168 = 7 days).',
        },
        limit: {
          type: 'number',
          default: 15,
          description: 'Maximum number of matching advisories to return (default: 15).',
        },
      },
    },
  },
  {
    name: 'post_digest_to_slack',
    description:
      'Generate the prioritized daily digest or urgent security flash alert and post it directly to a Slack Incoming Webhook or Slack Workflow Builder URL.',
    inputSchema: {
      type: 'object',
      properties: {
        mode: {
          type: 'string',
          enum: ['daily', 'urgent'],
          default: 'daily',
          description: 'Whether to post the full daily digest ("daily") or only critical flash alerts ("urgent").',
        },
        webhookUrl: {
          type: 'string',
          description: 'Optional Slack Webhook URL (falls back to SLACK_WEBHOOK_URL environment variable).',
        },
        lookbackHours: {
          type: 'number',
          default: 72,
          description: 'Lookback window in hours (default: 72).',
        },
        platforms: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional platform filter list.',
        },
      },
    },
  },
];

const PROMPTS = [
  {
    name: 'slack-daily-digest',
    description: 'Generate today’s prioritized cybersecurity & stack breaking-changes digest formatted for Slack.',
    arguments: [
      {
        name: 'platforms',
        description: 'Optional comma-separated list of platforms to focus on (e.g. WordPress,PHP,Next.js)',
        required: false,
      },
    ],
  },
  {
    name: 'urgent-security-triage',
    description: 'Check for critical zero-days, unauthenticated RCEs, or emergency vendor security notices across our stack.',
    arguments: [],
  },
  {
    name: 'stack-vulnerability-audit',
    description: 'Search recent security advisories and breaking releases for a specific technology or package.',
    arguments: [
      {
        name: 'query',
        description: 'Package name, platform, or CVE keyword to audit (e.g. Next.js, WordPress, composer)',
        required: true,
      },
    ],
  },
];

async function handleToolCall(name, args = {}) {
  switch (name) {
    case 'get_daily_security_digest': {
      const format = args.format || 'slack';
      const lookbackHours = args.lookbackHours ?? CONFIG.lookbackHours;
      const maxItems = args.maxItems ?? CONFIG.maxItemsPerDigest;
      const platforms = args.platforms || null;
      const deduplicate = Boolean(args.deduplicate);

      const sentHistory = deduplicate ? pruneHistory(loadJson(HISTORY_FILE, {})) : {};
      const rawItems = await collectAllRawItems({ forceRefresh: Boolean(args.forceRefresh) });
      const analysis = await filterAndPrioritizeItems(rawItems, sentHistory, {
        lookbackHours,
        maxItems,
        platforms,
      });

      if (deduplicate && analysis.allSelected.length > 0) {
        const nowIso = new Date().toISOString();
        for (const item of analysis.allSelected) {
          const record = {
            title: item.title,
            url: item.url,
            platform: item.platform,
            priority: item.priority,
            sentAt: nowIso,
          };
          sentHistory[item.fingerprint] = record;
          sentHistory[item.titleFingerprint] = record;
        }
        saveJson(HISTORY_FILE, sentHistory);
      }

      if (format === 'json') {
        return JSON.stringify(
          {
            checkedRawItems: rawItems.length,
            totalStackCandidates: analysis.totalCandidates,
            selectedCount: analysis.allSelected.length,
            grouped: analysis.grouped,
          },
          null,
          2
        );
      }

      const formatted =
        format === 'markdown'
          ? formatMarkdownDigest(analysis)
          : formatSlackDigest(analysis);

      return formatted;
    }

    case 'get_urgent_security_alerts': {
      const format = args.format || 'slack';
      const lookbackHours = args.lookbackHours ?? CONFIG.urgentLookbackHours;
      const deduplicate = Boolean(args.deduplicate);

      const sentHistory = deduplicate ? pruneHistory(loadJson(HISTORY_FILE, {})) : {};
      const urgentHistory = deduplicate ? pruneHistory(loadJson(URGENT_HISTORY_FILE, {})) : {};

      const rawItems = await collectAllRawItems({ forceRefresh: Boolean(args.forceRefresh) });
      const { selectedUrgent, allMatchedUrgent } = filterUrgentEmergencyItems(
        rawItems,
        sentHistory,
        urgentHistory,
        { lookbackHours }
      );

      if (deduplicate && allMatchedUrgent.length > 0) {
        const nowIso = new Date().toISOString();
        for (const item of allMatchedUrgent) {
          const record = {
            title: item.title,
            url: item.url,
            platform: item.platform,
            priority: 'URGENT_HIGH',
            sentAt: nowIso,
          };
          sentHistory[item.fingerprint] = record;
          sentHistory[item.titleFingerprint] = record;
          urgentHistory[item.fingerprint] = record;
          urgentHistory[item.titleFingerprint] = record;
        }
        saveJson(HISTORY_FILE, sentHistory);
        saveJson(URGENT_HISTORY_FILE, urgentHistory);
      }

      if (format === 'json') {
        return JSON.stringify(
          {
            checkedRawItems: rawItems.length,
            urgentCount: selectedUrgent.length,
            totalMatchedUrgent: allMatchedUrgent.length,
            alerts: selectedUrgent,
          },
          null,
          2
        );
      }

      return formatUrgentFlashAlert(selectedUrgent, format);
    }

    case 'search_stack_advisories': {
      const rawItems = await collectAllRawItems();
      const results = searchStackAdvisories(rawItems, {
        query: args.query || '',
        platform: args.platform || '',
        priority: args.priority || '',
        lookbackHours: args.lookbackHours ?? 168,
        limit: args.limit ?? 15,
      });

      if (results.length === 0) {
        return `No matching security advisories or releases found in the last ${args.lookbackHours ?? 168} hours for query="${args.query || '*'}" platform="${args.platform || '*'}".`;
      }

      const lines = [
        `Found ${results.length} matching advisory/release item(s) across ${RSS_FEEDS.length} feeds + GitHub Advisories + CISA KEV:`,
        '',
      ];

      for (const item of results) {
        const pubStr = item.publishedAt instanceof Date ? item.publishedAt.toISOString().slice(0, 10) : '';
        lines.push(
          `• [${item.priority || 'INFO'} | ${item.platform}] *<${item.url}|${item.title.replace(/[<>]/g, '')}>* (${pubStr} — ${item.source})`
        );
        if (item.summary) {
          lines.push(`  _${item.summary.slice(0, 180).trim()}${item.summary.length > 180 ? '…' : ''}_`);
        }
        lines.push('');
      }

      return lines.join('\n').trim();
    }

    case 'post_digest_to_slack': {
      const mode = args.mode || 'daily';
      const lookbackHours = args.lookbackHours ?? CONFIG.lookbackHours;
      const rawItems = await collectAllRawItems({ forceRefresh: true });

      let textToPost = '';
      if (mode === 'urgent') {
        const { selectedUrgent } = filterUrgentEmergencyItems(rawItems, {}, {}, { lookbackHours });
        if (selectedUrgent.length === 0) {
          return 'No urgent security alerts detected in the lookback window. Nothing posted to Slack.';
        }
        textToPost = formatUrgentFlashAlert(selectedUrgent, 'slack');
      } else {
        const analysis = await filterAndPrioritizeItems(rawItems, {}, {
          lookbackHours,
          platforms: args.platforms || null,
        });
        textToPost = formatSlackDigest(analysis);
      }

      const delivery = await postToSlackWebhook(textToPost, args.webhookUrl);
      return `✅ Successfully posted ${mode} cybersecurity digest to Slack (HTTP ${delivery.status}).\n\n---\n${textToPost}`;
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

function handlePromptGet(name, args = {}) {
  switch (name) {
    case 'slack-daily-digest': {
      const platformNote = args.platforms ? ` focusing on platforms: ${args.platforms}` : '';
      return {
        description: 'Generate today’s prioritized cybersecurity & stack breaking-changes digest for Slack.',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Call the \`get_daily_security_digest\` tool with \`format: "slack"\`${platformNote} and output the formatted Slack digest so I can share it with the engineering team.`,
            },
          },
        ],
      };
    }
    case 'urgent-security-triage':
      return {
        description: 'Check for critical zero-days, unauthenticated RCEs, or emergency vendor security notices.',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: 'Call `get_urgent_security_alerts` with `format: "slack"`. If any urgent alerts are returned, highlight the affected stack components, CVE IDs, and immediate patching actions.',
            },
          },
        ],
      };
    case 'stack-vulnerability-audit':
      return {
        description: 'Search recent security advisories and breaking releases for a specific technology or package.',
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Call \`search_stack_advisories\` with \`query: "${args.query || ''}"\` and summarize any vulnerabilities, breaking changes, or required version upgrades.`,
            },
          },
        ],
      };
    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
}

let useContentLengthFraming = false;

function sendJsonRpc(message) {
  const json = JSON.stringify(message);
  if (useContentLengthFraming) {
    const byteLength = Buffer.byteLength(json, 'utf8');
    process.stdout.write(`Content-Length: ${byteLength}\r\n\r\n${json}`);
  } else {
    process.stdout.write(`${json}\n`);
  }
}

async function handleJsonRpcMessage(msg) {
  if (!msg || typeof msg !== 'object') return;

  const { id, method, params } = msg;

  // Notifications have no id and expect no response
  if (id === undefined || id === null) {
    return;
  }

  try {
    switch (method) {
      case 'initialize': {
        const clientVersion = params?.protocolVersion || '2024-11-05';
        sendJsonRpc({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: clientVersion,
            capabilities: {
              tools: {},
              prompts: {},
            },
            serverInfo: SERVER_INFO,
          },
        });
        break;
      }

      case 'ping': {
        sendJsonRpc({
          jsonrpc: '2.0',
          id,
          result: {},
        });
        break;
      }

      case 'tools/list': {
        sendJsonRpc({
          jsonrpc: '2.0',
          id,
          result: {
            tools: TOOLS,
          },
        });
        break;
      }

      case 'tools/call': {
        const toolName = params?.name;
        const toolArgs = params?.args || params?.arguments || {};
        try {
          const textOutput = await handleToolCall(toolName, toolArgs);
          sendJsonRpc({
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: textOutput,
                },
              ],
            },
          });
        } catch (toolErr) {
          sendJsonRpc({
            jsonrpc: '2.0',
            id,
            result: {
              isError: true,
              content: [
                {
                  type: 'text',
                  text: `Error executing ${toolName}: ${toolErr.message}`,
                },
              ],
            },
          });
        }
        break;
      }

      case 'prompts/list': {
        sendJsonRpc({
          jsonrpc: '2.0',
          id,
          result: {
            prompts: PROMPTS,
          },
        });
        break;
      }

      case 'prompts/get': {
        const promptResult = handlePromptGet(params?.name, params?.arguments || {});
        sendJsonRpc({
          jsonrpc: '2.0',
          id,
          result: promptResult,
        });
        break;
      }

      case 'resources/list': {
        sendJsonRpc({
          jsonrpc: '2.0',
          id,
          result: {
            resources: [],
          },
        });
        break;
      }

      default: {
        sendJsonRpc({
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: `Method not found: ${method}`,
          },
        });
      }
    }
  } catch (err) {
    sendJsonRpc({
      jsonrpc: '2.0',
      id,
      error: {
        code: -32603,
        message: err.message || 'Internal JSON-RPC error',
      },
    });
  }
}

function startStdioMcpServer() {
  let buffer = Buffer.alloc(0);

  process.stdin.on('data', chunk => {
    buffer = Buffer.concat([buffer, Buffer.from(chunk)]);

    while (buffer.length > 0) {
      const preview = buffer.toString('utf8', 0, Math.min(buffer.length, 64));

      // Support Content-Length framed stdio messages
      if (/^Content-Length:/i.test(preview)) {
        useContentLengthFraming = true;
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) break;

        const headerStr = buffer.toString('utf8', 0, headerEnd);
        const match = headerStr.match(/Content-Length:\s*(\d+)/i);
        if (!match) {
          buffer = buffer.subarray(headerEnd + 4);
          continue;
        }

        const contentLength = parseInt(match[1], 10);
        const bodyStart = headerEnd + 4;
        if (buffer.length < bodyStart + contentLength) break;

        const bodyStr = buffer.toString('utf8', bodyStart, bodyStart + contentLength);
        buffer = buffer.subarray(bodyStart + contentLength);

        try {
          const parsed = JSON.parse(bodyStr);
          handleJsonRpcMessage(parsed);
        } catch (err) {
          console.error('[MCP Parse Error]', err.message);
        }
        continue;
      }

      // Standard MCP newline-delimited JSON-RPC 2.0
      const newlineIdx = buffer.indexOf('\n');
      if (newlineIdx === -1) break;

      const line = buffer.toString('utf8', 0, newlineIdx).trim();
      buffer = buffer.subarray(newlineIdx + 1);

      if (!line) continue;
      try {
        const parsed = JSON.parse(line);
        handleJsonRpcMessage(parsed);
      } catch (err) {
        console.error('[MCP Parse Error]', err.message);
      }
    }
  });

  process.stdin.on('end', () => {
    process.exit(0);
  });
}

startStdioMcpServer();
