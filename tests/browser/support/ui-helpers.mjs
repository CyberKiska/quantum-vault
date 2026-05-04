import { expect } from '@playwright/test';

export async function openProMode(page) {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  const modeToggle = page.getByTestId('mode-toggle');
  if (!(await modeToggle.isChecked())) {
    await page.getByTestId('mode-toggle-control').click();
    await expect(modeToggle).toBeChecked();
  }
}

export async function openProTab(page, tabTestId) {
  await openProMode(page);

  await page.getByTestId(tabTestId).click();

  if (tabTestId === 'tab-create') {
    await expect(page.locator('#proViewIdentity')).toBeVisible();
  }
  if (tabTestId === 'tab-restore') {
    await expect(page.getByTestId('restore-input')).toBeVisible();
  }
  if (tabTestId === 'tab-attach') {
    await expect(page.getByTestId('attach-input')).toBeVisible();
  }
  if (tabTestId === 'tab-reshare') {
    await expect(page.getByTestId('reshare-input')).toBeVisible();
  }
  if (tabTestId === 'tab-review') {
    await expect(page.getByTestId('review-input')).toBeVisible();
  }
}

export async function evaluateAndReleaseRestore(page, expectedPreflightText) {
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

export function lastToast(page) {
  return page.getByTestId('toast').last();
}

const ARCHIVE_REVIEW_HUB_ROOT_BY_PREFIX = Object.freeze({
  restore: 'restoreArchiveReviewRoot',
  liteRestore: 'liteRestoreArchiveReviewRoot',
  attach: 'attachArchiveReviewRoot',
  reshare: 'reshareArchiveReviewRoot',
  review: 'reviewArchiveReviewRoot',
});

/**
 * Expands the shared Archive review disclosure so nested intake / inspector / technical panels
 * satisfy Playwright visibility checks (content in a closed `details` element is not visible).
 *
 * @param {import('@playwright/test').Page} page
 * @param {'restore'|'liteRestore'|'attach'|'reshare'|'review'} prefix
 */
export async function openArchiveReviewHub(page, prefix) {
  const id = ARCHIVE_REVIEW_HUB_ROOT_BY_PREFIX[prefix];
  if (!id) throw new Error(`openArchiveReviewHub: unknown prefix "${prefix}"`);
  const root = page.locator(`#${id}`);
  await expect(root).toBeAttached();
  if (prefix === 'attach') {
    await expect(page.getByTestId('attach-status-text')).not.toContainText('Analyzing attach', { timeout: 15_000 });
  }
  await page.evaluate((hid) => {
    const el = document.getElementById(hid);
    if (el instanceof HTMLDetailsElement) el.open = true;
  }, id);
  await expect.poll(async () => root.evaluate((el) => el instanceof HTMLDetailsElement && el.open)).toBe(true);
}
