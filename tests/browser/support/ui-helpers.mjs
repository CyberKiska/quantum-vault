import { expect } from '@playwright/test';

export async function openProTab(page, tabTestId) {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  const modeToggle = page.getByTestId('mode-toggle');
  if (!(await modeToggle.isChecked())) {
    await page.getByTestId('mode-toggle-control').click();
    await expect(modeToggle).toBeChecked();
  }

  await page.getByTestId(tabTestId).click();

  if (tabTestId === 'tab-restore') {
    await expect(page.getByTestId('restore-input')).toBeVisible();
  }
  if (tabTestId === 'tab-attach') {
    await expect(page.getByTestId('attach-input')).toBeVisible();
  }
}

export function lastToast(page) {
  return page.getByTestId('toast').last();
}
