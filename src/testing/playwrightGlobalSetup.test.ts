const { closeMock, launchMock } = vi.hoisted(() => {
  const closeMock = vi.fn().mockResolvedValue(undefined);
  const versionMock = vi.fn().mockReturnValue('156.0.8078.4');
  const launchMock = vi.fn().mockResolvedValue({
    version: versionMock,
    close: closeMock,
  });
  return { closeMock, launchMock };
});

vi.mock('@playwright/test', () => ({
  chromium: {
    launch: launchMock,
  },
}));

const { applyMock, assertLaunchedMock } = vi.hoisted(() => ({
  applyMock: vi.fn(),
  assertLaunchedMock: vi.fn(),
}));

vi.mock('./playwrightChromiumGuard.js', () => ({
  applyPlaywrightChromiumGuard: applyMock,
  assertLaunchedBrowserVersion: assertLaunchedMock,
}));

import playwrightGlobalSetup from './playwrightGlobalSetup.js';

describe('playwrightGlobalSetup', () => {
  beforeEach(() => {
    applyMock.mockReturnValue({
      decision: { isolated: true, allowUnpatchedOverride: false },
      use: { chromiumSandbox: true },
    });
    assertLaunchedMock.mockReset();
  });

  it('launches Chromium with the guard policy and checks the actual version', async () => {
    await playwrightGlobalSetup({ projects: [{ use: {} }] } as never);

    expect(launchMock).toHaveBeenCalledWith({
      channel: undefined,
      chromiumSandbox: true,
    });
    expect(assertLaunchedMock).toHaveBeenCalledWith('156.0.8078.4', {
      isolated: true,
      allowUnpatchedOverride: false,
    });
    expect(closeMock).toHaveBeenCalledOnce();
  });

  it('closes the browser when the version check fails', async () => {
    assertLaunchedMock.mockImplementation(() => {
      throw new Error('unpatched');
    });

    await expect(playwrightGlobalSetup({ projects: [{ use: {} }] } as never)).rejects.toThrow(
      'unpatched',
    );
    expect(closeMock).toHaveBeenCalledOnce();
  });
});
