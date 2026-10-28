#!/usr/bin/env node
import fs from 'fs';
import { CONFIG } from './config.js';
import { collectAllRawItems } from './collectors.js';
import { filterAndPrioritizeItems, filterUrgentEmergencyItems } from './analyzer.js';
import { formatSlackDigest, formatUrgentFlashAlert } from './formatter.js';
import { postToSlackWebhook } from './slack.js';

function loadJson(filePath, fallback = {}) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
  } catch {
    // ignore
  }
  return fallback;
}

function saveJson(filePath, data) {
  fs.mkdirSync(CONFIG.dataDir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function isVancouverBusinessHours(now = new Date()) {
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: CONFIG.timezone || 'America/Vancouver',
    hour: 'numeric',
    hour12: false,
  });
  const hour = parseInt(formatter.format(now), 10);
  const start = CONFIG.businessHoursStart ?? 8;
  const end = CONFIG.businessHoursEnd ?? 18;
  return hour >= start && hour < end;
}

async function main() {
  const args = process.argv.slice(2);
  const isUrgent = args.includes('--urgent');
  const isSlackPost = args.includes('--slack');
  const forceSend = args.includes('--force') || args.includes('--dry-run');

  const state = loadJson(CONFIG.stateFile, {
    lastDailyDigestDate: null,
    lastRunAt: null,
    lastUrgentCheckAt: null,
  });
  const sentHistory = forceSend ? {} : loadJson(CONFIG.sentHistoryFile, {});
  const urgentHistory = forceSend ? {} : loadJson(CONFIG.urgentHistoryFile, {});
  const now = new Date();

  if (isUrgent && !forceSend && !isVancouverBusinessHours(now) && state.lastUrgentCheckAt) {
    const elapsedMinutes =
      (now.getTime() - new Date(state.lastUrgentCheckAt).getTime()) / (1000 * 60);
    if (elapsedMinutes < 55) {
      console.log(
        `[Off-Hours Throttle] Outside Vancouver business hours (${CONFIG.businessHoursStart}:00-${CONFIG.businessHoursEnd}:00 ${CONFIG.timezone}). Last check was ${Math.round(elapsedMinutes)}m ago (< 60m). Skipping.`
      );
      return;
    }
  }

  const rawItems = await collectAllRawItems({ forceRefresh: isUrgent || forceSend });

  if (isUrgent) {
    state.lastUrgentCheckAt = now.toISOString();
    saveJson(CONFIG.stateFile, state);

    const { selectedUrgent, allMatchedUrgent } = filterUrgentEmergencyItems(
      rawItems,
      sentHistory,
      urgentHistory
    );

    if (selectedUrgent.length === 0) {
      console.log(formatUrgentFlashAlert([], 'slack'));
      return;
    }

    const text = formatUrgentFlashAlert(selectedUrgent, 'slack');
    console.log(text);

    if (isSlackPost && CONFIG.slackWebhookUrl) {
      const res = await postToSlackWebhook(text);
      console.log(`\n[✓] Posted site/incident update to Slack (HTTP ${res.status})`);
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
      saveJson(CONFIG.sentHistoryFile, sentHistory);
      saveJson(CONFIG.urgentHistoryFile, urgentHistory);
    }
    return;
  }

  const analysis = await filterAndPrioritizeItems(rawItems, sentHistory);
  const text = formatSlackDigest(analysis);
  console.log(text);

  if (isSlackPost && CONFIG.slackWebhookUrl) {
    const res = await postToSlackWebhook(text);
    console.log(`\n[✓] Posted daily digest to Slack (HTTP ${res.status})`);
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
    saveJson(CONFIG.sentHistoryFile, sentHistory);
    state.lastDailyDigestDate = nowIso.slice(0, 10);
    state.lastRunAt = nowIso;
    saveJson(CONFIG.stateFile, state);
  }
}

main().catch(err => {
  console.error('[Fatal Error]', err);
  process.exit(1);
});
