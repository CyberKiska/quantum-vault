import { expect, test } from '@playwright/test';
import { getBrowserFixtureSet } from './support/fixture-factory.mjs';
import { lastToast, openProTab } from './support/ui-helpers.mjs';

let fixtures;

test.beforeAll(async () => {
  fixtures = await getBrowserFixtureSet();
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
