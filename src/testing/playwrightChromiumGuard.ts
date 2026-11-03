import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

/**
 * Chrome 156 stable that includes the Oct 2026 critical sandbox-escape fixes.
 * https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html
 *
 * Critical CVEs: CVE-2026-118306, CVE-2026-118331, CVE-2026-118348, CVE-2026-118344.
 */
export const MIN_SAFE_CHROMIUM_VERSION = '156.0.8078.73';

export const PLAYWRIGHT_ALLOW_UNPATCHED_ENV = 'PLAYWRIGHT_ALLOW_UNPATCHED';

const CRITICAL_CVES = [
  'CVE-2026-118306',
  'CVE-2026-118331',
  'CVE-2026-118348',
  'CVE-2026-118344',
] as const;

const CHROME_RELEASE_NOTES =
  'https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html';

/** Partial env map so unit tests can pass only the flags under test. */
export type EnvLookup = NodeJS.Dict<string>;

export type ChromiumGuardHost = {
  env: EnvLookup;
  bundledChromiumVersion: string | undefined;
  systemChromeVersion: string | undefined;
  isContainer: boolean;
};

export type ChromiumGuardDecision = {
  allow: boolean;
  message: string;
  channel: 'chrome' | undefined;
  /** Playwright `chromiumSandbox`. True means the sandbox stays enabled. */
  chromiumSandbox: boolean;
  isolated: boolean;
  allowUnpatchedOverride: boolean;
  usingUnpatchedBrowser: boolean;
  selectedBrowser: 'chrome' | 'bundled-chromium';
  selectedVersion: string | undefined;
};

export type PlaywrightChromiumUseOptions = {
  channel?: 'chrome';
  chromiumSandbox: boolean;
};

type FileExists = (filePath: string) => boolean;
type ReadFile = (filePath: string) => string;
type SpawnVersion = (
  command: string,
  args: readonly string[],
  options: { encoding: 'utf8' },
) => { status: number | null; stdout?: string | null };

function envFlagEnabled(value: string | undefined): boolean {
  if (value === undefined) {
    return false;
  }
  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

export function parseBrowserVersion(version: string): number[] | undefined {
  const match = version.trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    return undefined;
  }
  return match.slice(1, 5).map((part) => Number.parseInt(part, 10));
}

export function compareBrowserVersions(left: string, right: string): number {
  const leftParts = parseBrowserVersion(left);
  const rightParts = parseBrowserVersion(right);
  if (!leftParts || !rightParts) {
    throw new Error(`Cannot compare browser versions "${left}" and "${right}"`);
  }
  for (let i = 0; i < 4; i++) {
    if (leftParts[i] !== rightParts[i]) {
      return leftParts[i] - rightParts[i];
    }
  }
  return 0;
}

export function isBrowserVersionAtLeast(version: string, minimum: string): boolean {
  const parsed = parseBrowserVersion(version);
  if (!parsed) {
    return false;
  }
  return compareBrowserVersions(version, minimum) >= 0;
}

export function isCiEnvironment(env: EnvLookup = process.env): boolean {
  return envFlagEnabled(env.CI) || envFlagEnabled(env.GITHUB_ACTIONS);
}

export function isCursorCloudAgent(env: EnvLookup = process.env): boolean {
  if (envFlagEnabled(env.CURSOR_AGENT)) {
    return true;
  }
  return Boolean(env.CURSOR_AGENT_SOCKET && env.CURSOR_AGENT_SOCKET.trim());
}

export function detectContainer(
  fileExists: FileExists = (filePath) => fs.existsSync(filePath),
  readFile: ReadFile = (filePath) => fs.readFileSync(filePath, 'utf8'),
): boolean {
  if (fileExists('/.dockerenv') || fileExists('/run/.containerenv')) {
    return true;
  }

  try {
    const cgroup = readFile('/proc/1/cgroup');
    if (/docker|containerd|kubepods|lxc|libpod|podman|actions_job|\/pod-[a-z0-9]/i.test(cgroup)) {
      return true;
    }
  } catch {
    // Not Linux, or cgroup is unreadable — treat as not a container.
  }

  return false;
}

export function isIsolatedEnvironment(
  env: EnvLookup = process.env,
  isContainer = detectContainer(),
): boolean {
  return isCiEnvironment(env) || isCursorCloudAgent(env) || isContainer;
}

export function isAllowUnpatchedOverride(env: EnvLookup = process.env): boolean {
  return envFlagEnabled(env[PLAYWRIGHT_ALLOW_UNPATCHED_ENV]);
}

export function readBundledChromiumVersion(
  resolveBrowsersJson: () => string = resolvePlaywrightBrowsersJson,
  readFile: ReadFile = (filePath) => fs.readFileSync(filePath, 'utf8'),
): string | undefined {
  try {
    const browsersJsonPath = resolveBrowsersJson();
    const parsed = JSON.parse(readFile(browsersJsonPath)) as {
      browsers?: Array<{ name?: string; browserVersion?: string }>;
    };
    const chromium = parsed.browsers?.find((browser) => browser.name === 'chromium');
    return chromium?.browserVersion;
  } catch {
    return undefined;
  }
}

export function readSystemChromeVersion(
  platform: NodeJS.Platform = process.platform,
  env: EnvLookup = process.env,
  run: SpawnVersion = spawnSync,
): string | undefined {
  for (const binary of systemChromeBinaries(platform, env)) {
    const result = run(binary, ['--version'], { encoding: 'utf8' });
    if (result.status !== 0 || !result.stdout) {
      continue;
    }
    const match = result.stdout.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (match) {
      return match[1];
    }
  }
  return undefined;
}

export function inspectChromiumHost(overrides: Partial<ChromiumGuardHost> = {}): ChromiumGuardHost {
  const env = overrides.env ?? process.env;
  const isContainer = overrides.isContainer ?? detectContainer();
  return {
    env,
    bundledChromiumVersion: overrides.bundledChromiumVersion ?? readBundledChromiumVersion(),
    systemChromeVersion:
      overrides.systemChromeVersion ?? readSystemChromeVersion(process.platform, env),
    isContainer,
  };
}

export function resolveChromiumGuard(host: ChromiumGuardHost): ChromiumGuardDecision {
  const isolated = isIsolatedEnvironment(host.env, host.isContainer);
  const allowUnpatchedOverride = isAllowUnpatchedOverride(host.env);
  // Never disable the Chromium sandbox on a bare (non-isolated) host.
  // Containers often lack the user namespaces the sandbox needs; CI VMs keep it on.
  const chromiumSandbox = !host.isContainer;

  const chromeIsSafe =
    Boolean(host.systemChromeVersion) &&
    isBrowserVersionAtLeast(host.systemChromeVersion as string, MIN_SAFE_CHROMIUM_VERSION);
  const bundledIsSafe =
    Boolean(host.bundledChromiumVersion) &&
    isBrowserVersionAtLeast(host.bundledChromiumVersion as string, MIN_SAFE_CHROMIUM_VERSION);

  if (!isolated && chromeIsSafe) {
    return {
      allow: true,
      message: `Using installed Chrome stable ${host.systemChromeVersion} (>= ${MIN_SAFE_CHROMIUM_VERSION}).`,
      channel: 'chrome',
      chromiumSandbox: true,
      isolated,
      allowUnpatchedOverride,
      usingUnpatchedBrowser: false,
      selectedBrowser: 'chrome',
      selectedVersion: host.systemChromeVersion,
    };
  }

  if (bundledIsSafe) {
    return {
      allow: true,
      message: `Using Playwright bundled Chromium ${host.bundledChromiumVersion} (>= ${MIN_SAFE_CHROMIUM_VERSION}).`,
      channel: undefined,
      chromiumSandbox,
      isolated,
      allowUnpatchedOverride,
      usingUnpatchedBrowser: false,
      selectedBrowser: 'bundled-chromium',
      selectedVersion: host.bundledChromiumVersion,
    };
  }

  const selectedVersion = host.bundledChromiumVersion;
  const usingUnpatchedBrowser = Boolean(selectedVersion) && !bundledIsSafe;
  const unpatchedSummary = formatUnpatchedSummary(selectedVersion);

  if (isolated) {
    return {
      allow: true,
      message:
        'Isolated environment detected (CI/container/Cursor cloud agent). ' +
        `Allowing ${unpatchedSummary} because the host is not a shared laptop. ` +
        `Follow-up: bump Playwright when a stable release bundles Chromium >= ${MIN_SAFE_CHROMIUM_VERSION}.`,
      channel: undefined,
      chromiumSandbox,
      isolated,
      allowUnpatchedOverride,
      usingUnpatchedBrowser,
      selectedBrowser: 'bundled-chromium',
      selectedVersion,
    };
  }

  if (allowUnpatchedOverride) {
    return {
      allow: true,
      message: formatAllowUnpatchedWarning(selectedVersion, host.systemChromeVersion),
      channel: undefined,
      chromiumSandbox: true,
      isolated,
      allowUnpatchedOverride,
      usingUnpatchedBrowser,
      selectedBrowser: 'bundled-chromium',
      selectedVersion,
    };
  }

  return {
    allow: false,
    message: formatRefusal(selectedVersion, host.systemChromeVersion),
    channel: undefined,
    chromiumSandbox: true,
    isolated,
    allowUnpatchedOverride,
    usingUnpatchedBrowser,
    selectedBrowser: 'bundled-chromium',
    selectedVersion,
  };
}

export function assertChromiumGuard(decision: ChromiumGuardDecision): void {
  if (decision.allowUnpatchedOverride && decision.usingUnpatchedBrowser) {
    console.error(decision.message);
  } else if (decision.isolated && decision.usingUnpatchedBrowser) {
    console.warn(decision.message);
  }

  if (!decision.allow) {
    throw new Error(decision.message);
  }

  if (!decision.chromiumSandbox && !decision.isolated) {
    throw new Error(
      'Refusing to disable the Chromium sandbox outside CI, a container, or a Cursor cloud agent VM.',
    );
  }
}

export function playwrightUseOptionsFromGuard(
  decision: ChromiumGuardDecision,
): PlaywrightChromiumUseOptions {
  const options: PlaywrightChromiumUseOptions = {
    chromiumSandbox: decision.chromiumSandbox,
  };
  if (decision.channel) {
    options.channel = decision.channel;
  }
  return options;
}

export function applyPlaywrightChromiumGuard(overrides: Partial<ChromiumGuardHost> = {}): {
  decision: ChromiumGuardDecision;
  use: PlaywrightChromiumUseOptions;
} {
  const decision = resolveChromiumGuard(inspectChromiumHost(overrides));
  assertChromiumGuard(decision);
  return { decision, use: playwrightUseOptionsFromGuard(decision) };
}

export function assertLaunchedBrowserVersion(
  launchedVersion: string,
  decision: ChromiumGuardDecision,
): void {
  if (isBrowserVersionAtLeast(launchedVersion, MIN_SAFE_CHROMIUM_VERSION)) {
    return;
  }

  if (decision.isolated || decision.allowUnpatchedOverride) {
    console.warn(
      `Launched Chromium ${launchedVersion} is below patched minimum ${MIN_SAFE_CHROMIUM_VERSION}. ` +
        (decision.allowUnpatchedOverride
          ? `${PLAYWRIGHT_ALLOW_UNPATCHED_ENV}=1 override is in effect.`
          : 'Continuing because this host is isolated (CI/container/Cursor cloud agent).'),
    );
    return;
  }

  throw new Error(
    `Launched Chromium ${launchedVersion} is below patched minimum ${MIN_SAFE_CHROMIUM_VERSION} ` +
      `(${CRITICAL_CVES.join(', ')}; ${CHROME_RELEASE_NOTES}). ` +
      `Install Chrome stable >= ${MIN_SAFE_CHROMIUM_VERSION} or set ${PLAYWRIGHT_ALLOW_UNPATCHED_ENV}=1.`,
  );
}

function resolvePlaywrightBrowsersJson(): string {
  const require = createRequire(path.join(process.cwd(), 'package.json'));
  // playwright-core does not export ./browsers.json; resolve the package root instead.
  const playwrightCoreEntry = require.resolve('playwright-core');
  return path.join(path.dirname(playwrightCoreEntry), 'browsers.json');
}

function systemChromeBinaries(platform: NodeJS.Platform, env: EnvLookup): string[] {
  if (platform === 'darwin') {
    return ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'];
  }
  if (platform === 'win32') {
    const prefixes = [
      env['PROGRAMFILES'] ?? 'C:\\Program Files',
      env['PROGRAMFILES(X86)'] ?? 'C:\\Program Files (x86)',
      env.LOCALAPPDATA ?? '',
    ];
    return prefixes
      .filter(Boolean)
      .map((prefix) => path.join(prefix, 'Google', 'Chrome', 'Application', 'chrome.exe'));
  }
  return [
    'google-chrome-stable',
    'google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome',
  ];
}

function formatUnpatchedSummary(bundledVersion: string | undefined): string {
  return bundledVersion
    ? `Playwright bundled Chromium ${bundledVersion} (below ${MIN_SAFE_CHROMIUM_VERSION})`
    : 'an unknown Playwright Chromium build (could not read playwright-core/browsers.json)';
}

function formatAllowUnpatchedWarning(
  bundledVersion: string | undefined,
  systemChromeVersion: string | undefined,
): string {
  return [
    `WARNING: ${PLAYWRIGHT_ALLOW_UNPATCHED_ENV}=1 is set.`,
    `Running Playwright with ${formatUnpatchedSummary(bundledVersion)}`,
    `which does not include the Chrome ${MIN_SAFE_CHROMIUM_VERSION} sandbox-escape fixes`,
    `(${CRITICAL_CVES.join(', ')}; ${CHROME_RELEASE_NOTES}).`,
    systemChromeVersion
      ? `Installed Chrome reported ${systemChromeVersion}.`
      : 'No patched Chrome stable was found on this host.',
    'This override is off by default and is unsafe on a shared laptop. Remove the env var after upgrading.',
  ].join(' ');
}

function formatRefusal(
  bundledVersion: string | undefined,
  systemChromeVersion: string | undefined,
): string {
  const chromeLine = systemChromeVersion
    ? `Installed Chrome ${systemChromeVersion} is also below ${MIN_SAFE_CHROMIUM_VERSION}.`
    : `No installed Chrome stable was found. On a laptop, install Chrome >= ${MIN_SAFE_CHROMIUM_VERSION} (Playwright channel "chrome").`;
  return [
    `Refusing to run Playwright with ${formatUnpatchedSummary(bundledVersion)}.`,
    chromeLine,
    `Chrome ${MIN_SAFE_CHROMIUM_VERSION} fixed critical sandbox-escape issues ${CRITICAL_CVES.join(', ')}.`,
    `See ${CHROME_RELEASE_NOTES}.`,
    `Workarounds: run in CI/container/Cursor cloud agent; or set ${PLAYWRIGHT_ALLOW_UNPATCHED_ENV}=1 (logs a loud warning).`,
  ].join(' ');
}
