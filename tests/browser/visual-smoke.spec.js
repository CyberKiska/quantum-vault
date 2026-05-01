import { expect, test } from '@playwright/test';
import { getBrowserFixtureSet } from './support/fixture-factory.mjs';
import {
  evaluateAndReleaseRestore,
  openProMode,
  openProTab,
} from './support/ui-helpers.mjs';
import {
  expectCriticalPanelsNotClipped,
  expectFocusRingVisible,
  expectNoHorizontalOverflow,
  waitForUiAnimations,
} from './support/visual-assertions.mjs';

let fixtures;

test.beforeAll(async () => {
  fixtures = await getBrowserFixtureSet();
});

async function captureSmoke(page, testInfo, slug) {
  const buffer = await page.screenshot({ fullPage: true, type: 'png' });
  await testInfo.attach(`visual-smoke-${slug}.png`, {
    body: buffer,
    contentType: 'image/png',
  });
}

test.describe('Visual smoke (layout + screenshots after UI motion)', () => {
  test('Lite Create default', async ({ page }, testInfo) => {
    await page.goto('/');
    await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);
    await expect(page.locator('#liteViewProtect')).toHaveClass(/active/);
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await page.locator('#liteFilesInput').focus();
    await expectFocusRingVisible(page, page.locator('#liteDropzone'));
    await waitForUiAnimations(page);
    await captureSmoke(page, testInfo, 'lite-create-default');
  });

  test('Lite Restore policy failure', async ({ page }, testInfo) => {
    await page.goto('/');
    await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);
    await page.locator('#liteTabRestore').click();
    await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicyFailFiles);
    await page.locator('#liteRestoreBtn').click();
    await expect(page.getByTestId('lite-restore-inline-error')).toBeVisible();
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await captureSmoke(page, testInfo, 'lite-restore-policy-failure');
  });

  test('Pro Split blocked (invalid geometry)', async ({ page }, testInfo) => {
    await openProMode(page);
    await page.getByTestId('tab-create').click();
    await page.locator('#qencForQcontInput').setInputFiles(fixtures.buildFlowFiles[0]);
    await page.locator('#privKeyForQcontInput').setInputFiles(fixtures.buildFlowFiles[1]);
    await page.locator('#rsN').fill('4');
    await expect(page.getByTestId('split-prerequisites')).toContainText('Shard geometry invalid');
    await expect(page.getByTestId('split-readiness-text')).toContainText('blocked');
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await captureSmoke(page, testInfo, 'pro-split-blocked');
  });

  test('Pro Attach partial shard rewrite (ack panel visible)', async ({ page }, testInfo) => {
    await openProTab(page, 'tab-attach');
    await page.getByTestId('attach-channel').selectOption('archive-approval');
    await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalPartialShardAttachFiles);
    await expect(page.getByTestId('attach-partial-ack-panel')).toBeVisible();
    await expect(page.getByTestId('attach-status-text')).toContainText('Ready to update selected shards only');
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await captureSmoke(page, testInfo, 'pro-attach-partial-rewrite');
  });

  test('Pro Restore strong-PQ success (post-release)', async ({ page }, testInfo) => {
    await openProTab(page, 'tab-restore');
    await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedFiles);
    await expect(page.getByTestId('restore-button')).toBeEnabled();
    await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by strong PQ archive-approval policy');
    await expect(page.getByTestId('restore-result')).toBeVisible();
    await expect(page.getByTestId('restore-result')).toContainText('Plaintext released under strong PQ archive-approval policy');
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await captureSmoke(page, testInfo, 'pro-restore-strong-pq-success');
  });

  test('Pro Restore integrity-only warning (post-release)', async ({ page }, testInfo) => {
    await openProTab(page, 'tab-restore');
    await page.getByTestId('restore-input').setInputFiles(fixtures.reshareExportFiles);
    await expect(page.getByTestId('restore-button')).toBeEnabled();
    await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by integrity-only policy');
    await expect(page.getByTestId('restore-result')).toBeVisible();
    await expect(page.getByTestId('restore-result')).toContainText('Plaintext released under integrity-only policy');
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await captureSmoke(page, testInfo, 'pro-restore-integrity-only-warning');
  });

  test('Mobile Lite Create default', async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 375, height: 780 });
    await page.goto('/');
    await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);
    await expect(page.locator('#liteViewProtect')).toHaveClass(/active/);
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await captureSmoke(page, testInfo, 'mobile-lite-create');
  });

  test('Mobile Pro Restore digest details expanded', async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 375, height: 900 });
    await openProTab(page, 'tab-restore');
    await page.getByTestId('restore-input').setInputFiles(fixtures.mixedBundleFiles);
    await expect(page.getByTestId('restore-bundle-selection-group')).toBeVisible();
    const digestDetails = page.getByTestId('restore-digest-details');
    await expect(digestDetails).toBeVisible();
    await digestDetails.locator('summary').click();
    await expect(digestDetails.getByText(fixtures.mixedBundleDigestHex).first()).toBeVisible();
    await waitForUiAnimations(page);
    await expectNoHorizontalOverflow(page);
    await expectCriticalPanelsNotClipped(page);
    await captureSmoke(page, testInfo, 'mobile-pro-restore-digest-details');
  });
});
