# BLT-Pool

> BLT-Pool is a mentor matching and GitHub automation platform for [OWASP BLT](https://owaspblt.org), running as a Python [Cloudflare Worker](https://workers.cloudflare.com/). Repository: [OWASP-BLT/BLT-Pool](https://github.com/OWASP-BLT/BLT-Pool).

---

## Table of Contents

- [Features](#features)
  - [Issue Management](#-issue-management)
  - [Pull Request Automation](#-pull-request-automation)
  - [Contribution Leaderboard](#-contribution-leaderboard)
  - [Bug Reporting](#-bug-reporting)
  - [Mentor Pool](#-mentor-pool)
  - [Landing Page & Status](#-landing-page--status)
- [Architecture](#architecture)
- [Setup](#setup)
  - [Prerequisites](#prerequisites)
  - [Environment Variables](#environment-variables)
  - [D1 Database](#d1-database)
  - [Running Locally](#running-locally)
  - [Deploying to Production](#deploying-to-production)
  - [Testing](#testing)
- [GitHub App Permissions](#github-app-permissions)
- [Endpoints](#endpoints)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Related Projects](#related-projects)

- [License](#license)

---

## Features

### 🗂 Issue Management

| Feature | Description |
|---|---|
| **`/assign` command** | Comment `/assign` on any issue to self-assign it. An 8-hour deadline is set — if no linked PR is submitted in time, you are automatically unassigned. |
| **`/unassign` command** | Comment `/unassign` to release your assignment so other contributors can pick it up. |
| **Stale assignment cleanup** | A cron job runs every 2 hours and automatically unassigns issues where the 8-hour window has expired with no linked PR. |
| **Welcome message** | New issues receive an onboarding comment with instructions on how to get assigned and contribute. |

### 🔀 Pull Request Automation

| Feature | Description |
|---|---|
| **Merge congratulations** | A celebratory comment is posted when a PR is merged, crediting the author. |
| **Auto-close excess PRs** | If an author already has **50 or more open PRs** in the repository, the new PR is automatically closed with an explanatory message. |
| **Peer review enforcement** | PRs are labeled `needs-peer-review` or `has-peer-review` based on whether a valid (non-bot, non-author) approval exists. A reminder comment is posted when a review is missing. |
| **Unresolved conversations label** | Every PR is labeled `unresolved-conversations: N` (🔴 red if any are open, 🟢 green if all resolved), updated automatically whenever the PR is opened or a review thread changes. |

### 🏆 Contribution Leaderboard

The leaderboard is **event-driven and backed by Cloudflare D1** — no per-request repo scanning, scalable to large orgs.

**How points are scored:**

| Event | Points |
|---|---|
| PR opened | +1 to open PR counter |
| PR merged | +10 merged PRs, −1 open PR counter |
| PR closed without merge | −2 closed PRs, −1 open PR counter |
| PR review submitted | +5 (first two unique reviewers per PR per month only) |
| Issue comment created | +2 (bots and CodeRabbit pings excluded) |

**Commands & automation:**

| Feature | Description |
|---|---|
| **`/leaderboard` command** | Comment `/leaderboard` on any issue or PR to see the current monthly ranking for your org. The triggering command comment is deleted to keep threads clean. |
| **Auto-posted leaderboard** | The leaderboard is automatically posted (or updated in-place) when a PR is opened or merged. |
| **D1 backfill** | Historical data from repos is incrementally backfilled into D1 on scheduled runs so rankings are accurate from day one. |

### 🐛 Bug Reporting

When an issue is labeled with `bug`, `vulnerability`, or `security` — either at creation time or by adding the label later — the app automatically:
1. Reports the issue to the [BLT platform](https://owaspblt.org) via the BLT API.
2. Posts a comment with the assigned BLT Bug ID for cross-referencing.

Duplicate reports are prevented: if a bug label is already present from a prior event, the report is skipped.

### 🌐 Landing Page & Status

The Worker serves a mentor directory at `/` and a GitHub App install/status page at `/github-app` where anyone can:
- View the app description and install it on their GitHub organization.
- See the live status of all required secret variables (`APP_ID`, `PRIVATE_KEY`, `WEBHOOK_SECRET`).

A post-installation success page is served at `/callback`.

### 🤝 Mentor Pool

BLT-Pool provides a full mentor matching and assignment system for OWASP BLT contributors.

**Slash commands (on issues only):**

| Command | Who | Description |
|---|---|---|
| `/mentor` | Contributor | Request mentorship on the current issue. Triggers capacity-aware mentor selection and posts an assignment comment. |
| `/rematch` | Contributor | Request a different mentor (replaces the current assignment while keeping the issue mentored). |
| `/handoff` | Assigned mentor | Transfer mentorship to another available mentor. Only the currently assigned mentor can use this. |
| `/mentor-pause` | Mentor | Acknowledge a pause request; prompts the mentor to open a PR setting `active: false` in `.github/mentors.yml`. |

**Label-based trigger:**

Adding the `needs-mentor` label to an issue triggers automatic mentor assignment (uses the issue's first assignee, or the issue author as the contributor).

**Mentor selection algorithm:**
1. Filter to active mentors with a GitHub username.
2. Prefer mentors whose specialties match the issue's labels.
3. Query open mentored-issue counts (load map) via GitHub Search API.
4. Reject mentors at or over their `max_mentees` capacity.
5. Return the mentor with the fewest active mentees — ties broken alphabetically.

**PR integration:**
- When a PR body references a mentored issue (`Closes/Fixes/Resolves #N`), the assigned mentor is automatically requested as a reviewer.
- Optionally, a round-robin mentor can be requested as a reviewer on every new PR regardless of linked issues (controlled by `MENTOR_AUTO_PR_REVIEWER_ENABLED`).

**Stale assignment cleanup:**
- A cron job runs every 2 hours and releases mentor assignments on issues idle for more than **14 days** (based on the last human comment, not bot comments).

**Security bypass:**
- Issues labeled `security`, `vulnerability`, `security-sensitive`, or `private-security` skip mentor auto-assignment entirely.

**Configuration:**
- Mentor roster is loaded from `.github/mentors.yml` in the target repository at runtime. Falls back to the built-in `MENTORS` list when the file is absent.
- Mentor records support optional `referred_by`, which powers the homepage referral leaderboard widget.
- Example `.github/mentors.yml` entry:
  ```yaml
  mentors:
    - github_username: alice
      name: Alice Smith
      specialties:
        - frontend
        - javascript
      max_mentees: 3
      active: true
      referred_by: bob
  ```

**Web directory:**

The mentor pool is also exposed as a public directory at `/` — a live grid of all mentors with availability status, specialties, capacity, and GitHub links.

**Referral leaderboard:**
- The homepage includes a live "Referral Leaderboard" generated from mentor entries that include `referred_by`.
- Rankings are calculated by counting how many mentor entries each referrer has in `.github/mentors.yml`.

**Mentor application automation:**
- The homepage "Become a Mentor" form and the GitHub issue template feed into an automated pipeline.
- `.github/workflows/add-mentor-from-issue.yml` listens to newly opened mentor application issues.
- `.github/scripts/add_mentor.py` parses and validates fields, appends the mentor entry to `.github/mentors.yml`, commits directly to the default branch, comments on the issue, and closes it.

---

## Architecture

```text
GitHub Webhook
      │
      ▼
Cloudflare Worker (src/worker.py)
      │
      ├── Webhook signature verification (HMAC-SHA256)
      ├── Event routing → handler functions
      │
      ├── Issue handlers
      │   ├── handle_issue_comment   (/assign, /unassign, /leaderboard, /mentor, /mentor-pause, /handoff, /rematch)
      │   ├── handle_issue_opened    (welcome message, bug report)
      │   └── handle_issue_labeled   (bug report on label add; needs-mentor → mentor assignment)
      │
      ├── PR handlers
      │   ├── handle_pull_request_opened   (leaderboard, excess-PR check, unresolved-conversations, mentor reviewer)
      │   ├── handle_pull_request_closed   (merge congrats, leaderboard, D1 tracking)
      │   ├── handle_pull_request_review_submitted  (D1 review tracking)
      │   ├── handle_pull_request_for_review         (peer review label + comment, pending-checks label)
      │   └── handle_pull_request_review             (peer review label update on dismiss)
      │
      ├── Mentor Pool engine
      │   ├── _select_mentor           (capacity-aware round-robin with specialty matching)
      │   ├── _assign_mentor_to_issue  (label + comment + reviewer request)
      │   ├── handle_mentor_command    (/mentor)
      │   ├── handle_mentor_handoff    (/handoff)
      │   ├── handle_mentor_rematch    (/rematch)
      │   └── handle_mentor_pause      (/mentor-pause)
      │
      ├── CI/Checks handlers
      │   ├── handle_workflow_run   (workflow_run events → pending-checks label)
      │   └── handle_check_run      (check_run created/completed → pending-checks label)
      │
      ├── Leaderboard engine
      │   ├── D1-backed event counters (open/merged/closed PRs, reviews, comments)
      │   ├── Incremental D1 backfill from GitHub REST API
      │   └── Formatted leaderboard comment builder
      │
      └── Cron scheduler (every 2 hours)
          ├── _check_stale_assignments       → auto-unassign expired issue contributors
          └── _check_stale_mentor_assignments → release mentor assignments idle > 14 days
```

### Leaderboard Scalability

The leaderboard uses an **event-driven D1 model**:
- Webhook events atomically increment counters in Cloudflare D1 (SQLite at the edge).
- `/leaderboard` reads precomputed counters — no repo scanning on demand.
- Scales to orgs with hundreds of repos and thousands of contributors.

---

## Setup

### Prerequisites

- A [Cloudflare Workers](https://workers.cloudflare.com/) account with Workers Paid plan (required for D1)
- A registered [GitHub App](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps)
- [Node.js](https://nodejs.org/) ≥ 18 (for Wrangler CLI)
- [Python](https://python.org/) ≥ 3.11 (for running tests locally)

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `APP_ID` | ✅ | GitHub App numeric ID |
| `PRIVATE_KEY` | ✅ | GitHub App RSA private key (full PEM, PKCS#1 or PKCS#8) |
| `WEBHOOK_SECRET` | ✅ | GitHub App webhook secret |
| `GITHUB_APP_SLUG` | ⬜ | App URL slug shown in GitHub App URLs (e.g. `blt-pool`). Defaults to empty string — install button falls back to a generic URL. |
| `BLT_API_URL` | ⬜ | BLT API base URL (`wrangler.toml` sets `https://github-app.owaspblt.org`; runtime fallback in code is `https://blt-api.owasp-blt.workers.dev`) |
| `GITHUB_TOKEN` | ⬜ | Optional GitHub token used by `GET /` to fetch `.github/mentors.yml` with higher API rate limits (avoids unauthenticated 60 req/h limits). |
| `GITHUB_CLIENT_ID` | ⬜ | OAuth client ID (optional, for OAuth flow) |
| `GITHUB_CLIENT_SECRET` | ⬜ | OAuth client secret (optional, for OAuth flow) |
| `ADMIN_SECRET` | ⬜ | Bearer token to authorize `POST /admin/reset-leaderboard-month` (optional) |
| `MENTOR_AUTO_PR_REVIEWER_ENABLED` | ⬜ | Set to `true` to automatically request a round-robin mentor as reviewer on every new PR regardless of linked issues (optional, default: `false`) |

Non-secret variables (`BLT_API_URL`, `GITHUB_APP_SLUG`) are committed to `wrangler.toml`. Secrets must be set via Wrangler.

### D1 Database

The leaderboard requires a Cloudflare D1 database.

**1. Create the database:**
```bash
npx wrangler d1 create blt-leaderboard
```

**2. Copy the returned `database_id` into `wrangler.toml`:**
```toml
[[d1_databases]]
binding = "LEADERBOARD_DB"
database_name = "blt-leaderboard"
database_id = "<your-database-id>"
```

The schema is auto-created on first webhook event — no manual migration needed.

### Running Locally

```bash
# 1. Copy the example env file and fill in your credentials
cp .dev.vars.example .dev.vars

# 2. Start the local dev server
npx wrangler dev
```
The local server listens at `http://localhost:8787`. Use a tool like [ngrok](https://ngrok.com/) to expose it for GitHub webhook delivery.

### Deploying to Production

**Note:** The `public/` directory contains static assets (for example, `logo-sm.png`) served by Cloudflare Workers via the `[assets]` binding in `wrangler.toml`. HTML source templates live in `templates/` and are compiled into `src/index_template.py` before deploying.

```bash
# Set required secrets (one-time setup)
npx wrangler secret put APP_ID
npx wrangler secret put PRIVATE_KEY
npx wrangler secret put WEBHOOK_SECRET

# Deploy the Worker
npx wrangler deploy
```

**Bulk secret upload** from an `.env.production` file (with pre-flight Worker name verification):
```bash
chmod +x scripts/upload-production-vars.sh
./scripts/upload-production-vars.sh
```

The script verifies that `CLOUDFLARE_WORKER_NAME` in `.env.production` matches `name` in `wrangler.toml` before uploading any secrets.

> **Static assets:** The `public/` directory is automatically served by the Worker via the `[assets]` binding configured in `wrangler.toml`.

### Testing

```bash
pip install pytest
pytest test_worker.py -v
```

---

## GitHub App Permissions

| Permission | Access | Why |
|---|---|---|
| Issues | Read & Write | Assignment, comments, bug reporting, mentor labels |
| Pull Requests | Read & Write | PR automation, leaderboard, peer review, mentor reviewer requests |
| Metadata | Read | Repository info |
| Checks | Read | Pending-checks label updates |
| Actions | Read | Workflow run pending-checks tracking |

**Subscribed webhook events:** `issue_comment`, `issues`, `pull_request`, `pull_request_review`, `pull_request_review_comment`, `pull_request_review_thread`, `check_run`, `workflow_run`

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | BLT-Pool mentor directory landing page |
| `GET` | `/github-app` | GitHub App landing page with install button and secret variable status |
| `GET` | `/health` | JSON health check (`{"status": "ok"}`) |
| `POST` | `/api/github/webhooks` | GitHub webhook receiver (HMAC-verified) |
| `GET` | `/callback` | Post-installation success page |
| `POST` | `/admin/reset-leaderboard-month` | Admin endpoint to reset monthly leaderboard data (requires `ADMIN_SECRET`) |

---

## Project Structure

```text
BLT-Pool/
├── .dev.vars.example            # Local development variables template
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── mentor-application.md      # Mentor application issue template
│   ├── scripts/
│   │   └── add_mentor.py              # Parser/validator used by mentor onboarding workflow
│   ├── workflows/
│   │   ├── add-mentor-from-issue.yml  # Auto-add mentors from application issues
│   │   ├── node-ci.yml                # Node.js CI workflow
│   │   └── python-ci.yml              # Python CI workflow
│   └── mentors.yml                    # Mentor pool source of truth (used at runtime)
├── src/
│   ├── worker.py              # Main Cloudflare Worker — all webhook handlers, leaderboard engine, landing page
│   └── index_template.py      # Landing page HTML template
├── public/
│   └── logo-sm.png            # Static asset served via [assets]
├── templates/
│   ├── index.html             # GitHub App page source template
│   └── callback.html          # Installation success page source template
├── scripts/
│   └── upload-production-vars.sh  # Bulk secret upload script
├── test_worker.py             # pytest unit tests
├── wrangler.toml              # Cloudflare Worker configuration
├── app.yml                    # GitHub App manifest
└── LICENSE
```

---

## Roadmap

Everything below is planned for future development. Items are ordered roughly by priority.

| Feature | Description |
|---|---|
| **PR automation labels** | Auto-label PRs by number of files changed (`files-changed: N`), detect Django migration files (`migrations`), validate that the PR body references a linked issue (`linked-issue`), and flag merge conflicts — with feature toggles for each check. |
| **GitHub Checks — console statement scanner** | Create a GitHub Check Run that scans changed JS/TS files for `console.*` calls and annotates the exact offending lines directly in the PR diff. |
| **PR summary comment** | Post a rich summary on every PR showing file-change stats, estimated contribution points, a pre-merge checklist, and the author's current leaderboard rank. |
| **Security scanning** | GitHub Checks API integration for Gitleaks (secrets), Semgrep (SAST), Checkov (IaC), and CodeQL — results surfaced as inline PR annotations with SARIF uploaded to GitHub Code Scanning. |
| **Python linting check** | Ruff linting and formatting check exposed as a GitHub Check Run with per-line PR annotations. |
| **Auto-fix commits** | Automatically commit Ruff / isort / djLint fixes to the PR branch when linting issues are found, with loop detection and rate limiting. |
| **Quality labels** | Mutual-exclusion labels (`quality: high`, `quality: medium`, `quality: low`) applied to PRs based on review feedback signals. |
| **Test result labels** | `tests: passing` / `tests: failing` labels and failure summary comments driven by CI status checks. |
| **Comment count label** | A label that tracks PR discussion activity and is updated on each new comment. |
| **Last-active label** | Automatically marks PRs that have been idle for a configurable time window to surface stale work. |
| **Bounty payout integration** | When a PR merges and closes an issue carrying a `$amount` label, trigger the BLT bounty payout API automatically. |
| **Reviewer suggestions** | Suggest relevant reviewers based on file ownership history and past contribution patterns. |

---

## Related Projects

| Project | Description |
|---|---|
| [OWASP BLT](https://github.com/OWASP-BLT/BLT) | Main bug logging and bounty platform |
| [BLT-Action](https://github.com/OWASP-BLT/BLT-Action) | GitHub Action for issue assignment (predecessor) |
| [BLT-API](https://github.com/OWASP-BLT/BLT-API) | REST API powering BLT services |

---

## License

[AGPL-3.0](LICENSE)
