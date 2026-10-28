import { CONFIG } from './config.js';

export async function postToSlackWebhook(text, webhookUrl = CONFIG.slackWebhookUrl) {
  const targetUrl = (webhookUrl || CONFIG.slackWebhookUrl || '').trim();
  if (!targetUrl) {
    throw new Error(
      'Missing Slack Webhook URL. Provide webhookUrl argument or set SLACK_WEBHOOK_URL in your environment.'
    );
  }

  const res = await fetch(targetUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text,
      message: text,
      digest: text,
      content: text,
      body: text,
      unfurl_links: false,
      unfurl_media: false,
    }),
    signal: AbortSignal.timeout(15000),
  });

  const responseText = await res.text().catch(() => '');
  if (!res.ok) {
    throw new Error(`Slack webhook returned HTTP ${res.status}: ${responseText}`);
  }

  return {
    ok: true,
    status: res.status,
    response: responseText || 'ok',
  };
}
