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
