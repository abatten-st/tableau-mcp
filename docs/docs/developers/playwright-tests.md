---
sidebar_position: 7
---

# Playwright Tests

Tableau authorization-server OAuth tests live in `tests/oauth/tableau-authz/` and run with
Playwright (`npm run test:oauth:tableau`). They are **not** part of `scripts/agent-check`.

## Chromium version guard

Playwright's bundled Chromium can lag Chrome stable. After Chrome 156.0.8078.73 (27 Oct 2026) fixed
critical sandbox-escape issues
([CVE-2026-118306](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html),
CVE-2026-118331, CVE-2026-118348, CVE-2026-118344), this repo refuses to launch an older browser on
a shared host.

`playwright.config.ts` plus `src/testing/playwrightGlobalSetup.ts` apply a fail-closed check:

| Host                                               | Browser used                                                                                                       | Sandbox                                                   |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Laptop / workstation                               | Installed Chrome stable (`channel: "chrome"`) **>= 156.0.8078.73**, or a patched Playwright bundle when one exists | Always **on**                                             |
| `CI=true`, a container, or a Cursor cloud agent VM | Bundled Chromium is allowed even if still unpatched                                                                | On, except inside containers where the sandbox cannot run |
| Any host with `PLAYWRIGHT_ALLOW_UNPATCHED=1`       | Bundled Chromium (unsafe). Logs a loud warning. Off by default.                                                    | Still **on** outside containers                           |

The Chromium sandbox is never disabled outside CI/containers. Do not pass `--no-sandbox`.

`@playwright/test@1.65.0` (2026-11-05) bundles Chromium 158.0.8127.18, which is above the
156.0.8078.73 floor (CVE-2026-118306 / 118331 / 118348 / 118344). Keep the guard as defense in
depth; laptops can use the bundled browser.
