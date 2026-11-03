import {
  applyPlaywrightChromiumGuard,
  assertChromiumGuard,
  assertLaunchedBrowserVersion,
  type ChromiumGuardDecision,
  type ChromiumGuardHost,
  compareBrowserVersions,
  detectContainer,
  inspectChromiumHost,
  isAllowUnpatchedOverride,
  isBrowserVersionAtLeast,
  isCiEnvironment,
  isCursorCloudAgent,
  isIsolatedEnvironment,
  MIN_SAFE_CHROMIUM_VERSION,
  parseBrowserVersion,
  PLAYWRIGHT_ALLOW_UNPATCHED_ENV,
  playwrightUseOptionsFromGuard,
  readBundledChromiumVersion,
  readSystemChromeVersion,
  resolveChromiumGuard,
} from './playwrightChromiumGuard.js';

function host(overrides: Partial<ChromiumGuardHost> = {}): ChromiumGuardHost {
  return {
    env: {},
    bundledChromiumVersion: '156.0.8078.4',
    systemChromeVersion: undefined,
    isContainer: false,
    ...overrides,
  };
}

describe('playwrightChromiumGuard', () => {
  describe('version comparison', () => {
    it('parses a four-part Chrome version', () => {
      expect(parseBrowserVersion('156.0.8078.73')).toEqual([156, 0, 8078, 73]);
    });

    it('ignores trailing channel labels after the build', () => {
      expect(parseBrowserVersion('156.0.8078.73 extra')).toEqual([156, 0, 8078, 73]);
    });

    it('rejects incomplete versions', () => {
      expect(parseBrowserVersion('156.0.8078')).toBeUndefined();
      expect(() => compareBrowserVersions('nope', MIN_SAFE_CHROMIUM_VERSION)).toThrow(
        /Cannot compare browser versions/,
      );
    });

    it('orders Playwright bundled 156.0.8078.4 below the patched stable', () => {
      expect(compareBrowserVersions('156.0.8078.4', MIN_SAFE_CHROMIUM_VERSION)).toBeLessThan(0);
      expect(isBrowserVersionAtLeast('156.0.8078.4', MIN_SAFE_CHROMIUM_VERSION)).toBe(false);
    });

    it('treats 156.0.8078.73 as the minimum patched build', () => {
      expect(isBrowserVersionAtLeast('156.0.8078.73', MIN_SAFE_CHROMIUM_VERSION)).toBe(true);
      expect(isBrowserVersionAtLeast('156.0.8078.74', MIN_SAFE_CHROMIUM_VERSION)).toBe(true);
      expect(isBrowserVersionAtLeast('157.0.0.0', MIN_SAFE_CHROMIUM_VERSION)).toBe(true);
    });
  });

  describe('isolation detection', () => {
    it('treats CI=true as CI', () => {
      expect(isCiEnvironment({ CI: 'true' })).toBe(true);
      expect(isCiEnvironment({ GITHUB_ACTIONS: 'true' })).toBe(true);
      expect(isCiEnvironment({})).toBe(false);
      expect(isCiEnvironment({ CI: '0' })).toBe(false);
    });

    it('treats CURSOR_AGENT=1 as a Cursor cloud agent VM', () => {
      expect(isCursorCloudAgent({ CURSOR_AGENT: '1' })).toBe(true);
      expect(isCursorCloudAgent({ CURSOR_AGENT_SOCKET: '/run/cursor/api.sock' })).toBe(true);
      expect(isCursorCloudAgent({})).toBe(false);
    });

    it('detects docker, podman, and pod cgroup containers', () => {
      expect(
        detectContainer(
          (filePath) => filePath === '/.dockerenv',
          () => '',
        ),
      ).toBe(true);
      expect(
        detectContainer(
          (filePath) => filePath === '/run/.containerenv',
          () => '',
        ),
      ).toBe(true);
      expect(
        detectContainer(
          () => false,
          (filePath) => (filePath === '/proc/1/cgroup' ? '0::/system.slice/pod-abc123/init' : ''),
        ),
      ).toBe(true);
      expect(
        detectContainer(
          () => false,
          () => '0::/',
        ),
      ).toBe(false);
    });

    it('treats CI, containers, and Cursor agents as isolated', () => {
      expect(isIsolatedEnvironment({ CI: 'true' }, false)).toBe(true);
      expect(isIsolatedEnvironment({ CURSOR_AGENT: '1' }, false)).toBe(true);
      expect(isIsolatedEnvironment({}, true)).toBe(true);
      expect(isIsolatedEnvironment({}, false)).toBe(false);
    });
  });

  describe('laptop (non-isolated) policy', () => {
    it('prefers installed Chrome stable when it is patched', () => {
      const decision = resolveChromiumGuard(host({ systemChromeVersion: '156.0.8078.73' }));
      expect(decision.allow).toBe(true);
      expect(decision.channel).toBe('chrome');
      expect(decision.chromiumSandbox).toBe(true);
      expect(decision.selectedBrowser).toBe('chrome');
      expect(playwrightUseOptionsFromGuard(decision)).toEqual({
        channel: 'chrome',
        chromiumSandbox: true,
      });
    });

    it('refuses unpatched bundled Chromium when Chrome is missing', () => {
      const decision = resolveChromiumGuard(host());
      expect(decision.allow).toBe(false);
      expect(decision.chromiumSandbox).toBe(true);
      expect(decision.message).toContain('Refusing to run Playwright');
      expect(decision.message).toContain(MIN_SAFE_CHROMIUM_VERSION);
      expect(decision.message).toContain('CVE-2026-118306');
      expect(() => assertChromiumGuard(decision)).toThrow(/Refusing to run Playwright/);
    });

    it('refuses when installed Chrome is also unpatched', () => {
      const decision = resolveChromiumGuard(host({ systemChromeVersion: '156.0.8078.4' }));
      expect(decision.allow).toBe(false);
      expect(decision.message).toContain('Installed Chrome 156.0.8078.4');
    });

    it('allows patched bundled Chromium without switching to Chrome', () => {
      const decision = resolveChromiumGuard(host({ bundledChromiumVersion: '156.0.8078.73' }));
      expect(decision.allow).toBe(true);
      expect(decision.channel).toBeUndefined();
      expect(decision.chromiumSandbox).toBe(true);
      expect(decision.usingUnpatchedBrowser).toBe(false);
    });

    it('never disables the Chromium sandbox on a laptop', () => {
      const unpatched = resolveChromiumGuard(host());
      const overridden = resolveChromiumGuard(
        host({ env: { [PLAYWRIGHT_ALLOW_UNPATCHED_ENV]: '1' } }),
      );
      expect(unpatched.chromiumSandbox).toBe(true);
      expect(overridden.chromiumSandbox).toBe(true);
    });

    it('refuses a sandbox-off decision on a non-isolated host', () => {
      const unsafe: ChromiumGuardDecision = {
        ...resolveChromiumGuard(host({ systemChromeVersion: '156.0.8078.73' })),
        chromiumSandbox: false,
        isolated: false,
      };
      expect(() => assertChromiumGuard(unsafe)).toThrow(/sandbox/);
    });
  });

  describe('isolated environment policy', () => {
    it('allows unpatched bundled Chromium in CI', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      const decision = resolveChromiumGuard(host({ env: { CI: 'true' } }));
      expect(decision.allow).toBe(true);
      expect(decision.isolated).toBe(true);
      expect(decision.channel).toBeUndefined();
      expect(decision.usingUnpatchedBrowser).toBe(true);
      expect(decision.chromiumSandbox).toBe(true);
      expect(() => assertChromiumGuard(decision)).not.toThrow();
      expect(warnSpy).toHaveBeenCalledOnce();
      warnSpy.mockRestore();
    });

    it('allows unpatched bundled Chromium on a Cursor cloud agent', () => {
      const decision = resolveChromiumGuard(host({ env: { CURSOR_AGENT: '1' } }));
      expect(decision.allow).toBe(true);
      expect(decision.isolated).toBe(true);
    });

    it('disables the Chromium sandbox only inside a container', () => {
      const container = resolveChromiumGuard(host({ isContainer: true }));
      expect(container.allow).toBe(true);
      expect(container.isolated).toBe(true);
      expect(container.chromiumSandbox).toBe(false);

      const ciVm = resolveChromiumGuard(host({ env: { CI: 'true' }, isContainer: false }));
      expect(ciVm.chromiumSandbox).toBe(true);
    });
  });

  describe('PLAYWRIGHT_ALLOW_UNPATCHED escape hatch', () => {
    it('is off by default', () => {
      expect(isAllowUnpatchedOverride({})).toBe(false);
    });

    it('allows an unpatched browser on a laptop and logs loudly', () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      const decision = resolveChromiumGuard(
        host({ env: { [PLAYWRIGHT_ALLOW_UNPATCHED_ENV]: '1' } }),
      );
      expect(decision.allow).toBe(true);
      expect(decision.allowUnpatchedOverride).toBe(true);
      expect(decision.usingUnpatchedBrowser).toBe(true);
      expect(decision.chromiumSandbox).toBe(true);
      expect(decision.message).toContain('WARNING');
      expect(decision.message).toContain(PLAYWRIGHT_ALLOW_UNPATCHED_ENV);
      assertChromiumGuard(decision);
      expect(errorSpy).toHaveBeenCalledOnce();
      expect(String(errorSpy.mock.calls[0]?.[0])).toContain('WARNING');
      errorSpy.mockRestore();
    });
  });

  describe('launched-browser fail-closed check', () => {
    it('accepts a patched launched version', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      expect(() =>
        assertLaunchedBrowserVersion('156.0.8078.73', resolveChromiumGuard(host())),
      ).not.toThrow();
      expect(warnSpy).not.toHaveBeenCalled();
      warnSpy.mockRestore();
    });

    it('refuses an unpatched launched browser on a laptop', () => {
      expect(() =>
        assertLaunchedBrowserVersion('156.0.8078.4', resolveChromiumGuard(host())),
      ).toThrow(/Launched Chromium 156\.0\.8078\.4/);
    });

    it('warns but allows an unpatched launched browser in CI', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      expect(() =>
        assertLaunchedBrowserVersion(
          '156.0.8078.4',
          resolveChromiumGuard(host({ env: { CI: 'true' } })),
        ),
      ).not.toThrow();
      expect(warnSpy).toHaveBeenCalledOnce();
      warnSpy.mockRestore();
    });
  });

  describe('applyPlaywrightChromiumGuard', () => {
    it('returns Playwright use options for a patched Chrome host', () => {
      const { use, decision } = applyPlaywrightChromiumGuard({
        env: {},
        bundledChromiumVersion: '156.0.8078.4',
        systemChromeVersion: '156.0.8078.73',
        isContainer: false,
      });
      expect(decision.channel).toBe('chrome');
      expect(use).toEqual({ channel: 'chrome', chromiumSandbox: true });
    });

    it('throws fail-closed on a laptop with only unpatched bundled Chromium', () => {
      expect(() =>
        applyPlaywrightChromiumGuard({
          env: {},
          bundledChromiumVersion: '156.0.8078.4',
          systemChromeVersion: undefined,
          isContainer: false,
        }),
      ).toThrow(/Refusing to run Playwright/);
    });
  });

  describe('inspectChromiumHost', () => {
    it('honors explicit overrides without spawning Chrome', () => {
      const inspected = inspectChromiumHost({
        env: { CI: 'true' },
        bundledChromiumVersion: '1.0.0.0',
        systemChromeVersion: '2.0.0.0',
        isContainer: true,
      });
      expect(inspected).toEqual({
        env: { CI: 'true' },
        bundledChromiumVersion: '1.0.0.0',
        systemChromeVersion: '2.0.0.0',
        isContainer: true,
      });
    });
  });

  describe('host inspectors', () => {
    it('confirms Playwright 1.64.1 still bundles Chromium 156.0.8078.4 (unpatched)', () => {
      const bundled = readBundledChromiumVersion();
      expect(bundled).toBe('156.0.8078.4');
      expect(isBrowserVersionAtLeast(bundled ?? '', MIN_SAFE_CHROMIUM_VERSION)).toBe(false);
    });

    it('reads the bundled Chromium version from browsers.json', () => {
      expect(
        readBundledChromiumVersion(
          () => '/fake/browsers.json',
          () =>
            JSON.stringify({
              browsers: [{ name: 'chromium', browserVersion: '156.0.8078.4' }],
            }),
        ),
      ).toBe('156.0.8078.4');
    });

    it('returns undefined when browsers.json cannot be read', () => {
      expect(
        readBundledChromiumVersion(
          () => {
            throw new Error('missing');
          },
          () => '',
        ),
      ).toBeUndefined();
    });

    it('parses google-chrome --version output', () => {
      const run = vi.fn().mockReturnValue({
        status: 0,
        stdout: 'Google Chrome 156.0.8078.73\n',
      });
      expect(readSystemChromeVersion('linux', {}, run)).toBe('156.0.8078.73');
      expect(run).toHaveBeenCalled();
    });

    it('returns undefined when Chrome is not installed', () => {
      const run = vi.fn().mockReturnValue({ status: 1, stdout: '' });
      expect(readSystemChromeVersion('linux', {}, run)).toBeUndefined();
    });
  });
});
