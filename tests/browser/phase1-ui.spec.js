import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { getBrowserFixtureSet } from './support/fixture-factory.mjs';
import { buildQsigFixture } from '../../src/core/crypto/selftest.js';
import { lastToast, openProTab } from './support/ui-helpers.mjs';

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

test('distribution build exports successor shards and the generated shards restore under integrity-only policy', async ({ page }) => {
  await openProMode(page);
  await page.locator('#proTabDistribution').click();

  await page.locator('#qencForQcontInput').setInputFiles(fixtures.buildFlowFiles[0]);
  await page.locator('#privKeyForQcontInput').setInputFiles(fixtures.buildFlowFiles[1]);
  await page.locator('#proAuthPolicy').selectOption('integrity-only');

  const buildButton = page.locator('#buildQcontBtn');
  await expect(buildButton).toBeEnabled();

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
  await restoreButton.click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Archive policy satisfied');
  await expect(restoreResult).toContainText('No verified archive-approval signature over archive-state');
});

test('strong-PQ restore fails closed without detached archive approval', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicyFailFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  await restoreButton.click();

  await expect(lastToast(page)).toContainText('strong PQ archive-approval signature');
});

test('strong-PQ restore succeeds with valid qsig and matching pqpk pin', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  await restoreButton.click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Strong PQ archive-approval signature verified');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('ambiguous same-state cohorts stay blocked until explicit operator choice', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.ambiguousCohortFiles);

  await expect(page.getByTestId('restore-selection')).toBeVisible();
  await expect(page.getByTestId('restore-cohort-selection-group')).toBeVisible();
  await expect(page.getByTestId('restore-selection-help')).toContainText('will not auto-select an ambiguous successor path');
  await expect(page.getByTestId('restore-button')).toBeDisabled();
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
});

test('mixed lifecycle bundle digests require explicit selection and surface a warning after restore', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.mixedBundleFiles);

  await expect(page.getByTestId('restore-bundle-selection-group')).toBeVisible();
  await expect(page.getByTestId('restore-button')).toBeDisabled();

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
  await expect(page.getByTestId('attach-result')).toBeHidden();
  expect(downloadCount).toBe(0);
});

test('archive-approval attach imports qsig plus pqpk and restore satisfies strong-PQ policy with the updated bundle', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('archive-approval');
  await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalAttachBaseFiles);

  const attachButton = page.getByTestId('attach-button');
  await expect(attachButton).toBeEnabled();

  const [bundleDownload] = await Promise.all([
    page.waitForEvent('download'),
    attachButton.click(),
  ]);
  const updatedBundle = await payloadFromDownload(bundleDownload);

  await expect(page.getByTestId('attach-result')).toBeVisible();
  await expect(page.getByTestId('attach-result')).toContainText('Archive-approval signatures merged');

  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles([
    ...fixtures.archiveApprovalAttachRestoreShardFiles,
    updatedBundle,
  ]);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await restoreButton.click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Strong PQ archive-approval signature verified');
  await expect(restoreResult).toContainText('Archive policy satisfied');
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
  await restoreButton.click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Maintenance signature verified');
  await expect(restoreResult).toContainText('No verified archive-approval signature over archive-state');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('maintenance attach rejects a qsig signed over archive-state bytes instead of the transition record', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('maintenance');
  await page.getByTestId('attach-input').setInputFiles(fixtures.maintenanceWrongTargetFiles);

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
  await restoreButton.click();

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Source-evidence signature verified');
  await expect(restoreResult).toContainText('No verified archive-approval signature over archive-state');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('source-evidence attach rejects a qsig signed over archive-state bytes instead of source-evidence JSON', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('source-evidence');
  await page.getByTestId('attach-input').setInputFiles(fixtures.sourceEvidenceWrongTargetFiles);

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
