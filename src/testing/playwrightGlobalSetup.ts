import { chromium, type FullConfig } from '@playwright/test';

import {
  applyPlaywrightChromiumGuard,
  assertLaunchedBrowserVersion,
} from './playwrightChromiumGuard.js';

/**
 * Fail-closed Playwright globalSetup: refuse to run when the actually launched
 * Chromium/Chrome build is below the patched minimum, unless the host is isolated
 * or PLAYWRIGHT_ALLOW_UNPATCHED=1 is set.
 */
export default async function playwrightGlobalSetup(config: FullConfig): Promise<void> {
  const { decision, use } = applyPlaywrightChromiumGuard();
  const projectUse = config.projects[0]?.use ?? {};

  const browser = await chromium.launch({
    channel: use.channel ?? projectUse.channel,
    chromiumSandbox: use.chromiumSandbox,
  });

  try {
    assertLaunchedBrowserVersion(browser.version(), decision);
  } finally {
    await browser.close();
  }
}
