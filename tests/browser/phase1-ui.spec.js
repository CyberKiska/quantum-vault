import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { getBrowserFixtureSet } from './support/fixture-factory.mjs';
import { buildQsigFixture } from '../../src/core/crypto/selftest.js';
import { lastToast, openProTab } from './support/ui-helpers.mjs';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

let fixtures;

test.beforeAll(async () => {
  fixtures = await getBrowserFixtureSet();
});

function mimeTypeForFilename(name) {
  if (/\.json$/i.test(name)) return 'application/json';
  return 'application/octet-stream';
}

async function payloadFromDownload(download, overrideName = '') {
  const path = await download.path();
  const name = overrideName || download.suggestedFilename();
  return {
    name,
    mimeType: mimeTypeForFilename(name),
    buffer: await readFile(path),
  };
}

async function openProMode(page) {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  const modeToggle = page.getByTestId('mode-toggle');
  if (!(await modeToggle.isChecked())) {
    await page.getByTestId('mode-toggle-control').click();
    await expect(modeToggle).toBeChecked();
  }
}

test('advanced entropy collection shows heuristic progress and success copy without bit estimates', async ({ page }) => {
  await openProMode(page);
  await page.getByTestId('tab-create').click();

  await page.getByTestId('advanced-entropy-btn').click();

  const entropyPanel = page.getByTestId('entropy-status');
  await expect(entropyPanel).toBeVisible();

  const heuristicNote = page.getByTestId('entropy-heuristic-note');
  await expect(heuristicNote).toBeVisible();
  await expect(heuristicNote).toContainText('This is not a measured cryptographic guarantee.');

  const entropyText = page.getByTestId('entropy-text');
  await expect(entropyText).not.toContainText('bits');

  for (let i = 0; i < 130; i += 1) {
    await page.mouse.move(90 + (i % 50), 70 + (i % 30));
  }

  await expect(entropyText).toContainText('Supplemental entropy collected and mixed into next key generation.', { timeout: 35000 });
  await expect(entropyText).not.toContainText('64-byte');
  await expect(entropyText).not.toContainText('Est.');
});

test('scoped workflow busy leaves sidebar navigation and log toggle enabled', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  await page.evaluate(() => {
    const root = document.getElementById('liteViewProtect');
    if (!root) return;
    root.setAttribute('aria-busy', 'true');
    root.querySelectorAll('button, input:not([type="hidden"]), select, textarea').forEach((el) => {
      el.disabled = true;
    });
  });

  await expect(page.locator('#liteCreateShardsBtn')).toBeDisabled();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeDisabled();
  await expect(page.locator('#liteTabRestore')).not.toBeDisabled();
  await expect(page.locator('#liteTabProtect')).not.toBeDisabled();
  await expect(page.getByTestId('mode-toggle')).toBeEnabled();
  await expect(page.locator('#logToggleBtn')).toBeEnabled();
  await expect(page.locator('#sidebar-selftest')).toBeEnabled();
});

function shortenHashForUi(hash) {
  return `${hash.slice(0, 6)}...${hash.slice(-6)}`;
}

async function evaluateAndReleaseRestore(page, expectedPreflightText) {
  await page.getByTestId('restore-button').click();
  const preflight = page.getByTestId('restore-preflight');
  await expect(preflight).toBeVisible();
  if (expectedPreflightText) {
    await expect(preflight).toContainText(expectedPreflightText);
  }
  const releaseButton = page.getByTestId('release-button');
  await expect(releaseButton).toBeVisible();
  await expect(releaseButton).toBeEnabled();
  await releaseButton.click();
}

async function expectNoHorizontalOverflow(page) {
  const overflow = await page.evaluate(() => {
    const root = document.documentElement;
    const viewportWidth = root.clientWidth;
    const documentOverflow = root.scrollWidth - viewportWidth;
    const offenders = [...document.body.querySelectorAll('*')]
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          tag: element.tagName.toLowerCase(),
          id: element.id,
          className: typeof element.className === 'string' ? element.className : '',
          rightOverflow: rect.right - viewportWidth,
          leftOverflow: -rect.left,
          width: rect.width,
        };
      })
      .filter((entry) => entry.rightOverflow > 1 || entry.leftOverflow > 1)
      .sort((a, b) => Math.max(b.rightOverflow, b.leftOverflow) - Math.max(a.rightOverflow, a.leftOverflow))
      .slice(0, 5);
    return { viewportWidth, scrollWidth: root.scrollWidth, documentOverflow, offenders };
  });

  expect(overflow, JSON.stringify(overflow, null, 2)).toMatchObject({
    documentOverflow: expect.any(Number),
  });
  expect(overflow.documentOverflow, JSON.stringify(overflow, null, 2)).toBeLessThanOrEqual(1);
  expect(overflow.offenders, JSON.stringify(overflow, null, 2)).toHaveLength(0);
}

test('lite tablist supports roving keyboard navigation', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  await page.locator('#liteTabProtect').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#liteTabRestore')).toBeFocused();
  await expect(page.locator('#liteTabRestore')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#liteShardsInput')).toBeVisible();
  await expect(page.locator('#liteTabProtect')).toHaveAttribute('tabindex', '-1');

  await page.keyboard.press('Home');
  await expect(page.locator('#liteTabProtect')).toBeFocused();
  await expect(page.locator('#liteTabProtect')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#liteFilesInput')).toBeVisible();
});

test('pro tablist supports arrow home end and explicit activation keys', async ({ page }) => {
  await openProMode(page);

  await page.getByTestId('tab-create').focus();
  await page.keyboard.press('End');
  await expect(page.getByTestId('tab-restore')).toBeFocused();
  await expect(page.getByTestId('tab-restore')).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByTestId('restore-input')).toBeVisible();
  await expect(page.getByTestId('pro-workflow-active')).toContainText('Restore');

  await page.keyboard.press('ArrowLeft');
  await expect(page.getByTestId('tab-reshare')).toBeFocused();
  await expect(page.getByTestId('tab-reshare')).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByTestId('reshare-input')).toBeVisible();

  await page.getByTestId('tab-restore').focus();
  await page.keyboard.press('Enter');
  await expect(page.getByTestId('tab-restore')).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByTestId('restore-input')).toBeVisible();

  await page.keyboard.press('Home');
  await expect(page.getByTestId('tab-create')).toBeFocused();
  await expect(page.getByTestId('tab-create')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#proViewIdentity')).toBeVisible();
  await expect(page.locator('#proViewEncryption')).toBeVisible();
  await expect(page.locator('#proViewDistribution')).toBeVisible();
  await expect(page.getByTestId('pro-workflow-active')).toContainText('Create');
});

test('dropzone file inputs expose a visible focus hook on the drop target', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').focus();

  const focusStyle = await page.locator('#liteShardsDropzone').evaluate((element) => {
    const style = window.getComputedStyle(element);
    return {
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
      boxShadow: style.boxShadow,
    };
  });

  expect(focusStyle.outlineStyle).toBe('solid');
  expect(focusStyle.outlineWidth).toBeGreaterThanOrEqual(2);
  expect(focusStyle.boxShadow).not.toBe('none');
});

test('policy consequence previews update in Lite Create and Pro Split', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  const litePreview = page.getByTestId('lite-policy-consequence');
  await expect(litePreview).toContainText('Restore may release plaintext without archive-approval signature.');
  await expect(litePreview).toContainText('Integrity is checked; archive approval is not claimed.');
  await expect(litePreview).toHaveClass(/warning/);

  await page.locator('#liteAuthPolicy').selectOption('any-signature');
  await expect(litePreview).toContainText('Restore requires at least one valid archive-approval signature.');
  await expect(litePreview).toContainText('Maintenance, source-evidence, and timestamp evidence do not satisfy this policy.');
  await expect(litePreview).toHaveClass(/informational/);
  await expect.poll(async () => litePreview.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return { display: style.display, width: Math.round(rect.width), height: Math.round(rect.height) };
  })).toMatchObject({ display: 'block', width: expect.any(Number), height: expect.any(Number) });
  await expect.poll(async () => litePreview.evaluate((element) => element.getBoundingClientRect().width)).toBeGreaterThan(200);

  await page.locator('#liteAuthPolicy').selectOption('strong-pq-signature');
  await expect(litePreview).toContainText('Restore requires a strong PQ archive-approval signature over the archive-state descriptor.');
  await expect(litePreview).toContainText('Self-verified signatures are ignored for policy.');
  await expect(litePreview).toHaveClass(/strict/);

  await openProMode(page);
  await page.locator('#proTabDistribution').click();
  const proPreview = page.getByTestId('pro-policy-consequence');
  await expect(proPreview).toContainText('Restore requires a strong PQ archive-approval signature over the archive-state descriptor.');
  await expect(proPreview).toHaveClass(/strict/);

  await page.locator('#proAuthPolicy').selectOption('integrity-only');
  await expect(proPreview).toContainText('Restore may release plaintext without archive-approval signature.');
  await expect(proPreview).toHaveClass(/warning/);

  await page.locator('#proAuthPolicy').selectOption('any-signature');
  await expect(proPreview).toContainText('Restore requires at least one valid archive-approval signature.');
  await expect(proPreview).toHaveClass(/informational/);
  await expect.poll(async () => proPreview.evaluate((element) => element.getBoundingClientRect().width)).toBeGreaterThan(200);
});

test('lite custody guidance appears when ready and export checklist updates after create and optional key backup', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  await expect(page.locator('#keyStatus .status-text')).toContainText('Keys ready', { timeout: 30000 });

  const custody = page.getByTestId('lite-custody-guidance');
  await expect(custody).toBeVisible();
  await expect(custody).toContainText('independent shard custody');
  await expect(custody).toContainText('Retain the archive-state descriptor');
  await expect(custody).toContainText('Pro Attach');
  await expect(custody).toContainText('Backup Keys');
  await expect(custody).toContainText('optional');

  const createBtn = page.locator('#liteCreateShardsBtn');
  await expect(createBtn).toBeDisabled();

  await page.locator('#liteFilesInput').setInputFiles({
    name: 'custody-export-check.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('custody-export-check'),
  });

  await expect(createBtn).toBeEnabled();

  const shardDownloads = 5;
  const bundleDownloads = 2;
  const downloadWaiters = [];
  for (let i = 0; i < shardDownloads + bundleDownloads; i++) {
    downloadWaiters.push(page.waitForEvent('download'));
  }

  await createBtn.click();
  await Promise.all(downloadWaiters);

  const checklist = page.getByTestId('lite-export-checklist');
  await expect(checklist).toBeVisible();
  await expect(checklist).toContainText('QVqcont-7 shards exported');
  await expect(checklist).toContainText('Archive-state descriptor exported');
  await expect(checklist).toContainText('Lifecycle bundle exported');
  await expect(checklist).toContainText('Optional key backup not exported');

  const keyBackupWaiters = [page.waitForEvent('download'), page.waitForEvent('download')];
  await page.locator('#liteDownloadKeysBtn').click();
  await Promise.all(keyBackupWaiters);

  await expect(checklist).toContainText('Optional key backup exported');
});

test('narrow layouts do not horizontally overflow with long filenames and digest details', async ({ page }) => {
  const viewportWidths = [320, 375, 768, 1280];
  const longName = `${'quarterly-custody-rotation-restore-artifact-'.repeat(5)}.plaintext`;

  for (const width of viewportWidths) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/');
    await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

    await page.locator('#liteFilesInput').setInputFiles({
      name: longName,
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('responsive-layout-check'),
    });
    await expect(page.locator('#liteFilesList .file-name')).toContainText(longName);
    await expectNoHorizontalOverflow(page);

    await openProMode(page);
    await page.getByTestId('tab-restore').click();
    await page.getByTestId('restore-input').setInputFiles(fixtures.mixedBundleFiles);
    const digestDetails = page.getByTestId('restore-digest-details');
    await expect(digestDetails).toBeVisible();
    await digestDetails.locator('summary').click();
    await expect(digestDetails).toContainText(fixtures.mixedBundleDigestHex);
    await expectNoHorizontalOverflow(page);
  }
});

test('artifact intake table explains accepted ignored unsupported and wrong-target artifacts', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedCompleteOtsFiles);

  const restoreIntake = page.getByTestId('restore-artifact-intake');
  await expect(restoreIntake).toBeVisible();
  await expect(restoreIntake).toContainText('QVqcont-7 shard');
  await expect(restoreIntake).toContainText('archive-approval signature');
  await expect(restoreIntake).toContainText('PQ signer key');
  await expect(restoreIntake).toContainText('OTS proof');
  await expect(restoreIntake.locator('[data-artifact-status="accepted"]').first()).toBeVisible();
  await expect(restoreIntake.locator('[data-artifact-status="pending"]').first()).toBeVisible();
  await restoreIntake.locator('.artifact-row-details').first().locator('summary').click();
  const expandedDigestValue = restoreIntake.locator('.artifact-detail-value').first();
  await expect(expandedDigestValue).toBeVisible();
  await expect.poll(async () => expandedDigestValue.evaluate((element) => element.getBoundingClientRect().width)).toBeGreaterThan(300);

  await page.getByTestId('restore-input').setInputFiles(fixtures.legacyManifestFiles);
  await expect(restoreIntake).toContainText('unsupported');
  await expect(restoreIntake.locator('[data-artifact-status="ignored"]').first()).toBeVisible();

  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-input').setInputFiles(fixtures.legacyManifestFiles);
  const attachIntake = page.getByTestId('attach-artifact-intake');
  await expect(attachIntake).toBeVisible();
  await expect(attachIntake.locator('[data-artifact-status="unsupported"]').first()).toBeVisible();
  await expect(attachIntake).toContainText('Remove legacy manifest-side files');

  await page.getByTestId('attach-input').setInputFiles(fixtures.attachWrongOtsFiles);
  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();
  await attachButton.click();
  await expect(attachIntake.locator('[data-artifact-kind="ots-proof"][data-artifact-status="wrong target"]')).toBeVisible();
  await expect(attachIntake).toContainText('Load the detached signature this OTS proof stamps');

  await openProTab(page, 'tab-review');
  await page.getByTestId('review-input').setInputFiles(fixtures.strongPolicySatisfiedCompleteOtsFiles);
  const reviewIntake = page.getByTestId('review-artifact-intake');
  await expect(reviewIntake).toBeVisible();
  await expect(reviewIntake).toContainText('QVqcont-7 shard');
  await expect(reviewIntake).toContainText('archive-approval signature');
  const reviewInspector = page.getByTestId('review-archive-inspector');
  await expect(reviewInspector).toBeVisible();
  await expect(reviewInspector).toContainText('Lifecycle timeline');
  await expect(reviewInspector).toContainText('Evidence present in bundle (counts)');
  await expect(page.getByTestId('pro-workflow-active')).toContainText('Review');
  await expect(page.getByTestId('pro-workflow-evidence')).toContainText('review artifacts selected');
});

test('distribution build exports successor shards and the generated shards restore under integrity-only policy', async ({ page }) => {
  await openProMode(page);
  await page.locator('#proTabDistribution').click();

  await page.locator('#qencForQcontInput').setInputFiles(fixtures.buildFlowFiles[0]);
  await page.locator('#privKeyForQcontInput').setInputFiles(fixtures.buildFlowFiles[1]);
  await page.locator('#proAuthPolicy').selectOption('integrity-only');

  const buildButton = page.locator('#buildQcontBtn');
  await expect(buildButton).toBeEnabled();
  await expect(page.getByTestId('split-readiness-text')).toContainText('Ready to build successor shards');
  await expect(page.getByTestId('split-prerequisites')).toContainText('Encrypted .qenc selected');
  await expect(page.getByTestId('split-prerequisites')).toContainText('Private .qkey artifact selected');

  const downloads = [];
  page.on('download', (download) => {
    downloads.push(download);
  });

  await Promise.all([
    page.waitForEvent('download'),
    buildButton.click(),
  ]);
  await expect(page.getByTestId('operations-log')).toContainText('.qcont shards built');
  await expect.poll(() => downloads.length, { timeout: 10_000 }).toBe(8);

  const exported = await Promise.all(downloads.map((download) => payloadFromDownload(download)));
  const exportedNames = exported.map((item) => item.name).sort();
  expect(exportedNames.filter((name) => /\.qcont$/i.test(name))).toHaveLength(5);
  expect(exportedNames.some((name) => /\.archive-state\.json$/i.test(name))).toBe(true);
  expect(exportedNames.some((name) => /\.cohort-binding\.json$/i.test(name))).toBe(true);
  expect(exportedNames.some((name) => /\.lifecycle-bundle\.json$/i.test(name))).toBe(true);

  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(exported.filter((item) => /\.qcont$/i.test(item.name)));

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await expect(page.getByTestId('restore-preflight')).toContainText('Plaintext release: allowed by integrity-only policy');
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by integrity-only policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toHaveClass(/warn/);
  await expect(restoreResult).toContainText('Plaintext released under integrity-only policy');
  await expect(restoreResult).toContainText('Allowed by integrity-only policy');
  await expect(restoreResult).toContainText('Archive policy satisfied');
  await expect(restoreResult).toContainText('No verified archive-approval signature over archive-state');
});

test('pro split readiness blocks missing qenc and missing private key', async ({ page }) => {
  await openProMode(page);
  await page.locator('#proTabDistribution').click();

  await expect(page.locator('#buildQcontBtn')).toBeDisabled();
  await expect(page.getByTestId('split-readiness-text')).toContainText('Split is blocked');
  await expect(page.getByTestId('split-prerequisites')).toContainText('Select the encrypted .qenc container to split');
  await expect(page.getByTestId('split-prerequisites')).toContainText('Select a private .qkey artifact (3168 B)');

  await page.locator('#buildQcontBtn').evaluate((button) => { button.disabled = false; });
  await page.locator('#buildQcontBtn').click();
  await expect(page.getByTestId('split-inline-error')).toBeVisible();
  await expect(page.getByTestId('split-inline-error')).toContainText('Split blocked');
  await expect(page.getByTestId('split-inline-error')).toContainText('Select the encrypted .qenc container to split');
});

test('pro split readiness blocks invalid private key size', async ({ page }) => {
  await openProMode(page);
  await page.locator('#proTabDistribution').click();

  await page.locator('#qencForQcontInput').setInputFiles(fixtures.buildFlowFiles[0]);
  await page.locator('#privKeyForQcontInput').setInputFiles({
    name: 'wrong-size.private.qkey',
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(32),
  });

  await expect(page.locator('#buildQcontBtn')).toBeDisabled();
  await expect(page.getByTestId('split-prerequisites')).toContainText('Private .qkey artifact must be exactly 3168 bytes');
});

test('pro split readiness blocks invalid shard geometry', async ({ page }) => {
  await openProMode(page);
  await page.locator('#proTabDistribution').click();

  await page.locator('#qencForQcontInput').setInputFiles(fixtures.buildFlowFiles[0]);
  await page.locator('#privKeyForQcontInput').setInputFiles(fixtures.buildFlowFiles[1]);
  await page.locator('#rsN').fill('4');

  await expect(page.locator('#buildQcontBtn')).toBeDisabled();
  await expect(page.getByTestId('split-prerequisites')).toContainText('Shard geometry invalid');
  await expect(page.getByTestId('split-prerequisites')).toContainText('n must be at least 5');
});

test('strong-PQ restore fails closed without detached archive approval', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicyFailFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  await restoreButton.click();

  await expect(page.getByTestId('restore-preflight')).toContainText('Plaintext release: blocked');
  await expect(page.getByTestId('restore-preflight')).toContainText('before reconstruction');
  await expect(lastToast(page)).toContainText('strong PQ archive-approval signature');
  await expect(page.getByTestId('restore-inline-error')).toBeVisible();
  await expect(page.getByTestId('restore-inline-error')).toContainText('Cause');
  await expect(page.getByTestId('restore-inline-error')).toContainText('Affected artifact');
  await expect(page.getByTestId('restore-inline-error')).toContainText('Next recovery action');
  await expect(page.getByTestId('restore-inline-error')).toContainText('policy-satisfying archive-approval');
  await expect(page.getByTestId('restore-result')).toBeHidden();
});

test('lite restore policy failure is shown as a persistent inline error', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicyFailFiles);

  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeEnabled();
  await restoreButton.click();

  const inlineError = page.getByTestId('lite-restore-inline-error');
  await expect(inlineError).toBeVisible();
  await expect(inlineError).toContainText('Lite restore blocked');
  await expect(inlineError).toContainText('Cause');
  await expect(inlineError).toContainText('Affected artifact');
  await expect(inlineError).toContainText('Next recovery action');
  await expect(inlineError).toContainText('policy-satisfying archive-approval');
});

test('strong-PQ restore succeeds with valid qsig and matching pqpk pin', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  await expect(page.getByTestId('restore-preflight')).toContainText('Plaintext release: blocked');
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by strong PQ archive-approval policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Plaintext released under strong PQ archive-approval policy');
  await expect(restoreResult).toContainText('Strong PQ archive-approval signature verified');
  await expect(restoreResult).toContainText('Archive-approval signer pin');
  await expect(restoreResult).toContainText('Signer pinned by user input');
  await expect(restoreResult).toContainText('User-entered signer pin matched');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('restore reports unpinned embedded-key qsig as self-verified when another signature is pinned', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicyPinnedPlusSelfSignedFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by strong PQ archive-approval policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Plaintext released under strong PQ archive-approval policy');
  await expect(restoreResult).toContainText('Signer pinned by user input');
  await expect(restoreResult).toContainText('Self-verified signature');
  await expect(restoreResult).toContainText('Cryptographically self-verified, ignored for archive policy');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('restore reports complete-looking OTS evidence as heuristic and non-policy-satisfying', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedCompleteOtsFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await restoreButton.click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('OTS evidence linked to 1 signature');
  await expect(restoreResult).toContainText('OTS proof appears complete (heuristic): 1');
  await expect(restoreResult).toContainText('Timestamp evidence does not satisfy archive policy');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('restore reports incomplete OTS evidence separately from archive policy', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedIncompleteOtsFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await restoreButton.click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('OTS evidence linked to 1 signature');
  await expect(restoreResult).toContainText('OTS proof incomplete or pending: 1');
  await expect(restoreResult).toContainText('Timestamp evidence does not satisfy archive policy');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('ambiguous same-state cohorts stay blocked until explicit operator choice', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.ambiguousCohortFiles);

  await expect(page.getByTestId('restore-selection')).toBeVisible();
  await expect(page.getByTestId('restore-cohort-selection-group')).toBeVisible();
  await expect(page.getByTestId('restore-selection-help')).toContainText('will not auto-select an ambiguous successor path');
  await expect(page.getByTestId('restore-button')).toBeDisabled();

  const restoreInspector = page.getByTestId('restore-archive-inspector');
  await expect(restoreInspector).toBeVisible();
  await expect(restoreInspector).toContainText('Multiple archive states, same-state cohorts, or embedded lifecycle bundle variants are present');
  await expect(restoreInspector).toContainText('Maintenance signatures and source-evidence objects are separate from archive approval');
});

test('self-signed qsig warning is visible and does not satisfy any-signature policy', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.selfSignedFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  await restoreButton.click();

  await expect(page.getByTestId('operations-log')).toContainText('self-signed');
  await expect(page.getByTestId('operations-log')).toContainText('ignored for trust/policy');
  await expect(lastToast(page)).toContainText('archive-approval signature');
  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toContainText('Plaintext not released: archive policy not satisfied');
  await expect(restoreResult).toContainText('Self-verified signature');
  await expect(restoreResult).toContainText('Cryptographically self-verified, ignored for archive policy');
  await expect(restoreResult).toContainText('No verified archive-approval signer to pin');
});

test('mixed lifecycle bundle digests require explicit selection and surface a warning after restore', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.mixedBundleFiles);

  await expect(page.getByTestId('restore-bundle-selection-group')).toBeVisible();
  await expect(page.getByTestId('restore-button')).toBeDisabled();
  const mixedInspector = page.getByTestId('restore-archive-inspector');
  await expect(mixedInspector).toBeVisible();
  await expect(mixedInspector).toContainText('This cohort carries multiple embedded lifecycle bundle digests');
  await expect(mixedInspector).toContainText('Timestamp (.ots) proofs');
  await expect(page.getByTestId('restore-bundle-selection').locator('option', {
    hasText: `Lifecycle bundle ${shortenHashForUi(fixtures.mixedBundleDigestHex)}`,
  })).toHaveCount(1);

  const digestDetails = page.getByTestId('restore-digest-details');
  await expect(digestDetails).toBeVisible();
  await expect(digestDetails.locator('summary')).toContainText('Digest details and copy');
  await expect(digestDetails.getByText(fixtures.mixedBundleDigestHex).first()).toBeHidden();
  await digestDetails.locator('summary').click();
  await expect(digestDetails).toContainText('Source filenames');
  await expect(digestDetails).toContainText('Artifact type');
  await expect(digestDetails).toContainText('Policy');
  await expect(digestDetails).toContainText('Cohort parameters');
  await expect(digestDetails).toContainText('Lifecycle-bundle digest (SHA3-512)');
  await expect(digestDetails).toContainText(fixtures.mixedBundleDigestHex);
  const copyBundleDigest = digestDetails.locator(`button[data-copy-value="${fixtures.mixedBundleDigestHex}"]`).first();
  await expect(copyBundleDigest).toHaveText('Copy bundle digest');
  await copyBundleDigest.click();
  await expect(copyBundleDigest).toHaveText('Copied');

  await page.getByTestId('restore-bundle-selection').selectOption(fixtures.mixedBundleDigestHex);
  await expect(page.getByTestId('restore-button')).toBeEnabled();

  await page.getByTestId('restore-button').click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Mixed embedded lifecycle bundle variants were present in the selected cohort');
});

test('attach rejects legacy manifest-side files with the explicit unsupported label', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-input').setInputFiles(fixtures.legacyManifestFiles);

  await expect(page.getByTestId('attach-status-text')).toHaveText('Unsupported attach input');
  await expect(page.getByTestId('attach-inline-error')).toBeVisible();
  await expect(page.getByTestId('attach-inline-error')).toContainText('Remove legacy manifest-side files');
  await expect(page.getByTestId('attach-button')).toBeDisabled();
});

test('attach fails closed when OTS does not match any loaded detached signature', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-input').setInputFiles(fixtures.attachWrongOtsFiles);

  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();

  let downloadCount = 0;
  page.on('download', () => {
    downloadCount += 1;
  });

  await attachButton.click();

  await expect(lastToast(page)).toContainText('does not match any detached signature');
  await expect(page.getByTestId('attach-inline-error')).toBeVisible();
  await expect(page.getByTestId('attach-inline-error')).toContainText('Check that each OTS proof targets a loaded detached signature');
  await expect(page.getByTestId('attach-result')).toBeHidden();
  expect(downloadCount).toBe(0);
});

test('archive-approval attach imports qsig plus pqpk and restore satisfies strong-PQ policy with the updated bundle', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('archive-approval');
  await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalAttachBaseFiles);

  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();
  await expect(page.getByTestId('attach-partial-ack-panel')).toBeHidden();

  const [bundleDownload] = await Promise.all([
    page.waitForEvent('download'),
    attachButton.click(),
  ]);
  const updatedBundle = await payloadFromDownload(bundleDownload);

  await expect(page.getByTestId('attach-result')).toBeVisible();
  await expect(page.getByTestId('attach-result')).toContainText('Archive-approval signatures merged');
  await expect(page.getByTestId('attach-result')).toContainText('OTS evidence targets detached signature bytes by SHA-256(signatureBytes), not archive-state or lifecycle-bundle bytes');
  await expect(page.getByTestId('attach-result')).toContainText('Timestamp evidence does not satisfy archive policy');

  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles([
    ...fixtures.archiveApprovalAttachRestoreShardFiles,
    updatedBundle,
  ]);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by strong PQ archive-approval policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Plaintext released under strong PQ archive-approval policy');
  await expect(restoreResult).toContainText('Strong PQ archive-approval signature verified');
  await expect(restoreResult).toContainText('Archive-approval signer pin');
  await expect(restoreResult).toContainText('Signer pinned by bundle');
  await expect(restoreResult).toContainText('Bundle signer pin matched');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('partial shard attach requires explicit acknowledgement before rewriting selected shards', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('archive-approval');
  await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalPartialShardAttachFiles);

  const attachButton = page.getByTestId('attach-button');
  const partialAckPanel = page.getByTestId('attach-partial-ack-panel');
  const partialAck = page.getByTestId('attach-partial-ack');

  await expect(partialAckPanel).toBeVisible();
  await expect(partialAckPanel).toContainText('only the selected shard files will be rewritten');
  await expect(page.getByTestId('attach-status-text')).toContainText('Ready to update selected shards only');
  await expect(attachButton).toBeDisabled();

  await partialAck.check();
  await expect(attachButton).toBeEnabled();

  const downloads = [];
  page.on('download', (download) => {
    downloads.push(download);
  });
  await Promise.all([
    page.waitForEvent('download'),
    attachButton.click(),
  ]);
  await expect(page.getByTestId('attach-result')).toBeVisible();
  await expect(page.getByTestId('attach-result')).toContainText('Only 2/5 selected shard files were rewritten');
  await expect(page.getByTestId('attach-result')).toContainText('other shards may still carry older embedded lifecycle-bundle bytes');
  await expect.poll(() => downloads.length, { timeout: 10_000 }).toBe(3);
});

test('reshare exposes the transition-record export for external maintenance signing', async ({ page }) => {
  await openProTab(page, 'tab-reshare');
  await page.getByTestId('reshare-input').setInputFiles(fixtures.reshareExportFiles);

  const reshareButton = page.getByTestId('reshare-button');
  await expect(reshareButton).toBeEnabled();
  await reshareButton.click();

  const reshareResult = page.getByTestId('reshare-result');
  await expect(reshareResult).toBeVisible();
  await expect(reshareResult).toContainText('Transition record emitted');
  await expect(page.getByTestId('reshare-export-transition-record')).toBeVisible();

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('reshare-export-transition-record').click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/\.transition-record\.json$/i);
});

test('maintenance attach imports detached qsig evidence and restore reports it separately from archive approval', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('maintenance');
  await page.getByTestId('attach-input').setInputFiles([
    ...fixtures.maintenanceAttachBaseFiles,
    ...fixtures.maintenanceAttachSignatureFiles,
  ]);

  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();

  const [bundleDownload] = await Promise.all([
    page.waitForEvent('download'),
    attachButton.click(),
  ]);
  const updatedBundle = await payloadFromDownload(bundleDownload);

  await expect(page.getByTestId('attach-result')).toBeVisible();
  await expect(page.getByTestId('attach-result')).toContainText('Maintenance signatures merged');

  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles([
    ...fixtures.maintenanceRestoreShardFiles,
    updatedBundle,
  ]);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by integrity-only policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Plaintext released under integrity-only policy');
  await expect(restoreResult).toContainText('Maintenance signature verified');
  await expect(restoreResult).toContainText('No verified archive-approval signature over archive-state');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('maintenance attach rejects a qsig signed over archive-state bytes instead of the transition record', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('maintenance');
  await page.getByTestId('attach-input').setInputFiles(fixtures.maintenanceWrongTargetFiles);

  const bindingPreview = page.getByTestId('attach-target-binding-preview');
  await expect(bindingPreview).toBeVisible();
  await expect(bindingPreview).toContainText('transition:sha3-512:');

  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();

  let downloadCount = 0;
  page.on('download', () => {
    downloadCount += 1;
  });

  await attachButton.click();

  await expect(lastToast(page)).toContainText('no provided .pqpk file matches this detached PQ signature');
  await expect(page.getByTestId('attach-result')).toBeHidden();
  expect(downloadCount).toBe(0);
});

test('source-evidence builder preview states archive policy and blocks export until digests are valid', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('source-evidence');

  const preview = page.getByTestId('source-evidence-export-preview');
  await expect(preview).toBeVisible();
  await expect(preview).toContainText('never satisfies archive restore policy');

  const exportBtn = page.getByTestId('source-evidence-export');
  await expect(exportBtn).toBeDisabled();

  await page.locator('#sourceEvidenceDigestRows .source-evidence-digest-value').first().fill('gg'.repeat(64));
  await expect(exportBtn).toBeDisabled();
  await expect(preview).toContainText('invalid');

  await page.locator('#sourceEvidenceDigestRows .source-evidence-digest-value').first().fill('aa'.repeat(63));
  await expect(exportBtn).toBeDisabled();

  await page.locator('#sourceEvidenceDigestRows .source-evidence-digest-value').first().fill('ab'.repeat(64));
  await expect(exportBtn).toBeEnabled();
});

test('attach target-binding preview reflects channel, archive binding, and shard rewrite mode', async ({ page }) => {
  await openProTab(page, 'tab-attach');

  await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalAttachBaseFiles);
  let preview = page.getByTestId('attach-target-binding-preview');
  await expect(preview).toBeVisible();
  await expect(preview).toContainText('Archive approval');
  await expect(preview).toContainText('state:');
  await expect(preview).toContainText('bundle-only');
  await expect(preview).toContainText('Archive policy binding: verified signatures on this channel can satisfy archive restore policy');

  await page.getByTestId('attach-channel').selectOption('maintenance');
  await page.getByTestId('attach-input').setInputFiles(fixtures.maintenanceWrongTargetFiles);
  preview = page.getByTestId('attach-target-binding-preview');
  await expect(preview).toContainText('Maintenance');
  await expect(preview).toContainText('transition:sha3-512:');
  await expect(preview).toContainText('does not satisfy archive restore policy by itself');

  await page.getByTestId('attach-channel').selectOption('source-evidence');
  await page.getByTestId('attach-input').setInputFiles(fixtures.sourceEvidenceWrongTargetFiles);
  preview = page.getByTestId('attach-target-binding-preview');
  await expect(preview).toContainText('Source evidence');
  await expect(preview).toContainText('source-evidence:sha3-512:');

  await page.getByTestId('attach-channel').selectOption('archive-approval');
  await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalPartialShardAttachFiles);
  preview = page.getByTestId('attach-target-binding-preview');
  await expect(preview).toContainText('partial cohort');
});

test('source-evidence builder exports canonical JSON for external signing, re-imports the matching qsig, and restore reports it separately', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('source-evidence');
  await page.getByTestId('source-evidence-object-type').fill('archive-state-descriptor');
  await page.locator('#sourceEvidenceDigestRows .source-evidence-digest-value').first().fill('ab'.repeat(64));
  await page.getByTestId('source-evidence-external-refs').fill('sig:browser-review-1');

  const [sourceEvidenceDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId('source-evidence-export').click(),
  ]);
  const sourceEvidencePayload = await payloadFromDownload(sourceEvidenceDownload);
  const qsig = buildQsigFixture(new Uint8Array(sourceEvidencePayload.buffer));
  const sourceEvidenceSignaturePayload = {
    name: 'source-evidence.qsig',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from(qsig.qsigBytes),
  };
  const sourceEvidencePinPayload = {
    name: 'source-evidence.pqpk',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from(qsig.pqpkBytes),
  };

  await page.getByTestId('attach-input').setInputFiles([
    ...fixtures.sourceEvidenceAttachBaseFiles,
    sourceEvidencePayload,
    sourceEvidenceSignaturePayload,
    sourceEvidencePinPayload,
  ]);

  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();

  const [bundleDownload] = await Promise.all([
    page.waitForEvent('download'),
    attachButton.click(),
  ]);
  const updatedBundle = await payloadFromDownload(bundleDownload);

  await expect(page.getByTestId('attach-result')).toBeVisible();
  await expect(page.getByTestId('attach-result')).toContainText('Source-evidence signatures merged');

  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles([
    ...fixtures.sourceEvidenceRestoreShardFiles,
    updatedBundle,
  ]);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by integrity-only policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Plaintext released under integrity-only policy');
  await expect(restoreResult).toContainText('Source-evidence signature verified');
  await expect(restoreResult).toContainText('No verified archive-approval signature over archive-state');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('source-evidence attach rejects a qsig signed over archive-state bytes instead of source-evidence JSON', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('source-evidence');
  await page.getByTestId('attach-input').setInputFiles(fixtures.sourceEvidenceWrongTargetFiles);

  const bindingPreview = page.getByTestId('attach-target-binding-preview');
  await expect(bindingPreview).toBeVisible();
  await expect(bindingPreview).toContainText('source-evidence:sha3-512:');

  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();

  let downloadCount = 0;
  page.on('download', () => {
    downloadCount += 1;
  });

  await attachButton.click();

  await expect(lastToast(page)).toContainText('no provided .pqpk file matches this detached PQ signature');
  await expect(page.getByTestId('attach-result')).toBeHidden();
  expect(downloadCount).toBe(0);
});

test('restore rejects an uploaded lifecycle bundle that belongs to a different archive cohort', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.lifecycleBundleMismatchFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  let downloadCount = 0;
  page.on('download', () => {
    downloadCount += 1;
  });

  await restoreButton.click();

  await expect(lastToast(page)).toContainText('Provided lifecycle bundle does not match');
  await expect(page.getByTestId('restore-result')).toBeHidden();
  expect(downloadCount).toBe(0);
});
