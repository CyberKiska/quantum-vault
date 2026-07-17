import { expect, test } from '@playwright/test';

import { parseLifecycleShard, zeroizeParsedLifecycleShard } from '../../src/app/crypto-service.js';
import { getBrowserFixtureSet } from './support/fixture-factory.mjs';
import { openProTab } from './support/ui-helpers.mjs';

let fixtures;

test.beforeAll(async () => {
  fixtures = await getBrowserFixtureSet();
});

test('restore never renders or logs the legacy QCONT private-key fingerprint', async ({ page }) => {
  const shardFile = fixtures.strongPolicySatisfiedFiles.find((file) => /\.qcont$/i.test(file.name));
  const parsed = await parseLifecycleShard(new Uint8Array(shardFile.buffer), { strict: true });
  const privateFingerprintCanary = parsed.metaJSON.privateKeyHash;
  expect(privateFingerprintCanary).toMatch(/^[0-9a-f]{128}$/);

  const consoleMessages = [];
  page.on('console', (message) => consoleMessages.push(message.text()));
  await page.addInitScript(() => {
    window.__qvSuccessorSelectionEvents = [];
    document.addEventListener('qv:successor-selection-change', (event) => {
      window.__qvSuccessorSelectionEvents.push(JSON.stringify(event.detail));
    });
  });

  try {
    await openProTab(page, 'tab-restore');
    await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedFiles);
    const restoreButton = page.getByTestId('restore-button');
    await expect(restoreButton).toBeEnabled();
    await restoreButton.click();
    await expect(page.getByTestId('release-button')).toBeVisible();
    await expect(page.getByTestId('release-button')).toBeEnabled();

    const rendered = await page.locator('body').innerText();
    const html = await page.locator('html').evaluate((element) => element.outerHTML);
    const selectionEvents = await page.evaluate(() => window.__qvSuccessorSelectionEvents.join('\n'));

    expect(rendered).not.toContain(privateFingerprintCanary);
    expect(html).not.toContain(privateFingerprintCanary);
    expect(consoleMessages.join('\n')).not.toContain(privateFingerprintCanary);
    expect(selectionEvents).not.toContain(privateFingerprintCanary);
    await expect(page.getByTestId('operations-log')).toContainText(
      'Recovered ML-KEM private key satisfied the authenticated QENC key commitment.',
    );
  } finally {
    zeroizeParsedLifecycleShard(parsed);
  }
});
