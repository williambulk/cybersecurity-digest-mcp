# Stack, Site Status & Dev News Digest (`cybersecurity-digest-mcp`)

A portable **Model Context Protocol (MCP)** server and **Slack / GitHub Actions automation** that monitors **configurable production domains**, **7 hosting/CDN status pages**, and **high-impact developer & security news** across your web stack:

- **Configurable Domain Monitoring (Two-Step Outage Verification):**
  - Supports listing your production domains in `.env` (or GitHub Secrets) via `MONITORED_DOMAINS`, grouped by hosting provider (e.g., **WP Engine**, **Kinsta**, **Pantheon**, **Ploi.io**, **Fly.io**, **SiteGround**).
  - Checks your configured domains **first** before flagging any upstream hosting incident, avoiding false-alarm alerts when a hosting provider posts a minor status notice that does not impact your sites.
- **7 Hosting & Infrastructure Status Monitors:**
  - **Cloudflare**, **Kinsta**, **WP Engine**, **Fly.io**, **Pantheon**, **Ploi.io**, and **SiteGround**
- **Stack & Dev News (`📰 DEV NEWS`):**
  - **PHP** (PHP Core releases, security notices, Composer/Packagist advisories)
  - **WordPress** (Core releases, Gutenberg/REST API updates, critical plugin/theme vulnerabilities via Wordfence & Patchstack)
  - **Sanity CMS** (`sanity-io/sanity` releases, Studio updates, breaking changes, advisories)
  - **Statamic CMS** (`statamic/cms` releases, Laravel/Livewire security advisories)
  - **JavaScript / Node.js** (Node.js security releases, npm supply-chain advisories, React/Vue/Vite updates)
  - **Nuxt.js** (`nuxt/nuxt` & Nitro/UnJS releases, breaking changes, security advisories)
  - **Next.js** (`vercel/next.js` releases, App Router / Server Actions / Middleware CVEs & breaking changes)

---

## Exposed MCP Tools

| Tool Name | Description |
| :--- | :--- |
| **`get_daily_security_digest`** | Checks configured production domains (`MONITORED_DOMAINS`), 7 hosting status pages, RSS/Atom feeds, GitHub Security Advisories (`npm` & `composer`), and CISA KEV; outputs the `🗞️ Daily Stack & Dev Digest` (`🌐 SITES & HOSTING STATUS` + `📰 DEV NEWS`). Supports `format: "slack" \| "markdown" \| "json"`. |
| **`get_urgent_security_alerts`** | Checks for verified site/hosting outages across your configured domains and high-impact stack advisories. |
| **`search_stack_advisories`** | Ad-hoc search across live security feeds, GitHub Advisories, CISA KEV, and official releases by keyword, CVE ID, package name, priority, or platform. |
| **`post_digest_to_slack`** | Generates the daily digest or site/incident update and posts it directly to a Slack Workflow Builder Webhook or Incoming Webhook (`SLACK_WEBHOOK_URL`). |

---

## Quick Start

```bash
git clone https://github.com/williambulk/cybersecurity-digest-mcp.git
cd cybersecurity-digest-mcp
npm install
cp .env.example .env
```

### Configuring Domains & Slack Locally (`.env`)

In `.env`, you can optionally list the domains you want monitored for uptime alongside your Slack webhook:

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/triggers/your_slack_webhook_here
MONITORED_DOMAINS="WP Engine=example1.com,example2.com|Kinsta=example3.com|Pantheon=example4.com|Ploi.io=example5.com"
```

*(Also supports a JSON array format: `MONITORED_DOMAINS='[{"domain":"example.com","provider":"Kinsta"}]'`)*

### Test via CLI

```bash
# Preview the Slack-formatted Daily Stack & Dev Digest in your terminal
npm run dry-run

# Preview the 15-minute Site & Hosting Status check in your terminal
npm run urgent:dry-run
```

---

## Running Automatically on GitHub Actions (Slack)

This repository includes [`.github/workflows/digest.yml`](.github/workflows/digest.yml) pre-configured for **Vancouver time (`America/Vancouver`)**:
- **Daily Digest:** Runs at **8:00 AM Vancouver time** (`🗞️ Daily Stack & Dev Digest`).
- **Site & Incident Monitor:** Runs **every 15 minutes during Vancouver business hours (8:00 AM – 6:00 PM)**, and automatically throttles to **once every 1 hour outside business hours (6:00 PM – 8:00 AM)**.

### Setup in Company GitHub
1. Import or push this repository into your organization's GitHub.
2. Go to **Settings → Secrets and variables → Actions → New repository secret**:
   - **`SLACK_WEBHOOK_URL`** *(Required)*: Your Slack Workflow Builder webhook URL (`https://hooks.slack.com/triggers/...`) or Incoming Webhook URL.
   - **`MONITORED_DOMAINS`** *(Optional)*: Domains to monitor grouped by provider (`"WP Engine=domain1.com,domain2.com|Kinsta=domain3.com|Pantheon=domain4.com|Ploi.io=domain5.com"`).
   - **`GEMINI_API_KEY`** *(Optional)*: Google Gemini API key for AI headline refinement (falls back to the built-in deterministic engine if omitted).

---

## Connecting to AI Clients (MCP Configuration)

### 1. Claude Desktop / Claude for Work (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "cybersecurity-digest": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/cybersecurity-digest-mcp/src/mcp-server.js"],
      "env": {
        "TIMEZONE": "America/Vancouver"
      }
    }
  }
}
```

### 2. Google Antigravity (`mcp_config.json`)

```json
{
  "mcpServers": {
    "cybersecurity-digest": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/cybersecurity-digest-mcp/src/mcp-server.js"]
    }
  }
}
```
