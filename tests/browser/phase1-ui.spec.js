import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { getBrowserFixtureSet } from './support/fixture-factory.mjs';
import { buildQsigFixture } from '../../src/core/crypto/selftest.js';
import {
  decryptFile,
  hashBytes,
  parseLifecycleShard,
  restoreFromShards,
  zeroizeParsedLifecycleShard,
} from '../../src/app/crypto-service.js';
import { wipeRestoreResult } from '../../src/core/crypto/zeroize.js';
import { lastToast, openArchiveReviewHub, openProMode, openProTab, evaluateAndReleaseRestore } from './support/ui-helpers.mjs';
import { expectNoHorizontalOverflow } from './support/visual-assertions.mjs';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const ARCHIVE_EXTERNAL_COPY_HAZARD = 'One or more archive downloads were requested and may remain outside page control; retain them under the archive custody policy or securely delete them. A threshold set is a complete recovery root.';
const PRIVATE_KEY_EXTERNAL_COPY_HAZARD = 'A raw private-key download was requested and may remain outside page control; the browser cannot delete it. Securely delete every unneeded copy under the key-custody policy.';
const RESTORE_PLAINTEXT_EXTERNAL_COPY_HAZARD = 'A restored plaintext download was requested and may remain outside page control; cancellation, page cleanup, and object-URL revocation cannot delete a browser-managed copy.';

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

async function beginLiteArchiveWithoutAutomaticDownloads(
  page,
  name,
  plaintext,
  { retainRawKeyBackup = false } = {},
) {
  await page.locator('#liteFilesInput').setInputFiles({
    name,
    mimeType: 'text/plain',
    buffer: Buffer.from(plaintext),
  });
  const backupAcknowledgement = page.getByTestId('lite-raw-key-backup-ack');
  await expect(backupAcknowledgement).not.toBeChecked();
  if (retainRawKeyBackup) {
    await backupAcknowledgement.check();
  }
  const createButton = page.locator('#liteCreateShardsBtn');
  await expect(createButton).toBeEnabled();

  const unexpectedDownloads = [];
  const onDownload = (download) => unexpectedDownloads.push(download);
  page.on('download', onDownload);
  try {
    await createButton.click();
    await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(7, {
      timeout: 60_000,
    });
    await page.waitForTimeout(250);
    expect(unexpectedDownloads).toHaveLength(0);
  } finally {
    page.off('download', onDownload);
  }

  await expect(backupAcknowledgement).toBeDisabled();
  await expect(backupAcknowledgement).not.toBeChecked();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Archive incomplete');
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(createButton).toBeDisabled();
}

async function downloadEveryLiteExportRow(page, expectedCount) {
  const observedDownloads = [];
  const onDownload = (download) => observedDownloads.push(download);
  page.on('download', onDownload);
  try {
    for (let index = 0; index < expectedCount; index += 1) {
      const action = page.getByTestId(`lite-export-row-action-${index}`);
      await expect(action).toHaveText('Download');
      await action.click();
      await expect.poll(() => observedDownloads.length, { timeout: 30_000 }).toBe(index + 1);
      await expect(page.getByTestId(`lite-export-row-${index}`)).toContainText(
        'Download requested; re-import not verified',
      );
    }
    await page.waitForTimeout(100);
    expect(observedDownloads).toHaveLength(expectedCount);
    return await Promise.all(observedDownloads.map((download) => payloadFromDownload(download)));
  } finally {
    page.off('download', onDownload);
  }
}

async function reimportLiteArtifacts(page, payloads) {
  const button = page.locator('#liteExportReimportBtn');
  await expect(button).toBeEnabled();
  await button.focus();
  await expect(button).toBeFocused();
  const [chooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    button.press('Enter'),
  ]);
  await chooser.setFiles(payloads);
}

async function downloadLiteExportRow(page, index) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByTestId(`lite-export-row-action-${index}`).click(),
  ]);
  await expect(page.getByTestId(`lite-export-row-${index}`)).toContainText(
    'Download requested; re-import not verified',
  );
  return payloadFromDownload(download);
}

async function expectVerifiedLiteRows(page, count) {
  // A completed session is synchronously scrubbed from the export surface.
  // Assert the post-settlement checklist instead of racing the terminal row
  // render; partial sessions continue to expose their verified row states.
  if (count === 7) {
    await expect(page.getByTestId('lite-export-session')).toBeHidden({ timeout: 30_000 });
    await expect(page.getByTestId('lite-export-checklist')).toBeVisible();
    await expect(page.getByTestId('lite-export-checklist')).toContainText(
      'QVqcont-7 shard artifacts re-import verified',
      { timeout: 30_000 },
    );
    return;
  }
  if (count === 2) {
    await expect.poll(async () => {
      const states = await page.locator('.lite-export-session-state').allTextContents();
      const verifiedRows = states.filter(
        (state) => state.includes('Exact name, size, and SHA3-512 digest verified'),
      ).length;
      if (verifiedRows === 2) return true;
      return (await page.getByTestId('lite-export-checklist').innerText())
        .includes('Authorized 1-of-1 key backup re-import verified');
    }, { timeout: 30_000 }).toBe(true);
    return;
  }
  await expect.poll(async () => {
    const states = await page.locator('.lite-export-session-state').allTextContents();
    return states.filter((state) => state.includes('Exact name, size, and SHA3-512 digest verified')).length;
  }, { timeout: 30_000 }).toBe(count);
}

async function parseDownloadedLiteShards(payloads) {
  const shardPayloads = payloads.filter((payload) => /\.qcont$/i.test(payload.name));
  expect(shardPayloads).toHaveLength(5);
  return Promise.all(shardPayloads.map((payload) => (
    parseLifecycleShard(new Uint8Array(payload.buffer), { strict: true })
  )));
}

async function detachExactNode(page, id, slot) {
  await page.evaluate(({ nodeId, storageSlot }) => {
    const node = document.getElementById(nodeId);
    if (!node?.parentNode) throw new Error('test fixture node is unavailable');
    const marker = document.createComment(`qv-test-detached-${storageSlot}`);
    node.parentNode.insertBefore(marker, node);
    node.remove();
    window[storageSlot] = { marker, node };
  }, { nodeId: id, storageSlot: slot });
}

async function detachExactNodeAfterExportMutation(page, id, slot) {
  await page.evaluate(({ nodeId, storageSlot }) => {
    const panel = document.getElementById('liteExportSessionPanel');
    if (!panel) throw new Error('test fixture export panel is unavailable');
    const observer = new MutationObserver(() => {
      const node = document.getElementById(nodeId);
      if (!node?.parentNode) return;
      observer.disconnect();
      const marker = document.createComment(`qv-test-detached-${storageSlot}`);
      node.parentNode.insertBefore(marker, node);
      node.remove();
      window[storageSlot] = { marker, node };
    });
    observer.observe(panel, {
      attributes: true,
      childList: true,
      characterData: true,
      subtree: true,
    });
  }, { nodeId: id, storageSlot: slot });
}

async function restoreExactNode(page, slot) {
  await page.evaluate((storageSlot) => {
    const detached = window[storageSlot];
    if (!detached?.marker?.isConnected || detached.node?.isConnected) {
      throw new Error('test fixture detached node state is invalid');
    }
    detached.marker.replaceWith(detached.node);
    delete window[storageSlot];
  }, slot);
}

async function dispatchPersistedPageTransition(page, type) {
  await page.evaluate((eventType) => {
    window.dispatchEvent(new PageTransitionEvent(eventType, { persisted: true }));
  }, type);
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

test('browser cryptographic self-test runs only browser-compatible cases and passes', async ({ page }) => {
  test.setTimeout(180000);
  const failedCliModuleRequests = [];
  page.on('requestfailed', (request) => {
    if (/\/cli\/qv\.js(?:$|\?)/.test(request.url())) failedCliModuleRequests.push(request.url());
  });

  await page.goto('/');
  await page.getByTestId('operations-log').waitFor({ state: 'attached' });
  await page.locator('#sidebar-selftest').click();
  await expect(page.getByTestId('operations-log')).toContainText(/Self-test PASS \(\d+\/\d+\)/, {
    timeout: 170000,
  });
  expect(failedCliModuleRequests).toEqual([]);
});

function shortenHashForUi(hash) {
  return `${hash.slice(0, 6)}...${hash.slice(-6)}`;
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
  await expect(litePreview).toContainText('Restore requires at least one valid archive-approval signature matched by an external signer pin.');
  await expect(litePreview).toContainText('Maintenance, source-evidence, and timestamp evidence do not satisfy this policy.');
  await expect(litePreview).toHaveClass(/informational/);
  await expect.poll(async () => litePreview.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return { display: style.display, width: Math.round(rect.width), height: Math.round(rect.height) };
  })).toMatchObject({ display: 'block', width: expect.any(Number), height: expect.any(Number) });
  await expect.poll(async () => litePreview.evaluate((element) => element.getBoundingClientRect().width)).toBeGreaterThan(200);

  await page.locator('#liteAuthPolicy').selectOption('strong-pq-signature');
  await expect(litePreview).toContainText('Restore requires a strong PQ archive-approval signature over the archive-state descriptor matched by an external signer pin.');
  await expect(litePreview).toContainText('Embedded or bundled signer material alone is ignored for policy.');
  await expect(litePreview).toHaveClass(/strict/);

  await openProMode(page);
  await page.locator('#proTabDistribution').click();
  const proPreview = page.getByTestId('pro-policy-consequence');
  await expect(proPreview).toContainText('Restore requires a strong PQ archive-approval signature over the archive-state descriptor matched by an external signer pin.');
  await expect(proPreview).toHaveClass(/strict/);

  await page.locator('#proAuthPolicy').selectOption('integrity-only');
  await expect(proPreview).toContainText('Restore may release plaintext without archive-approval signature.');
  await expect(proPreview).toHaveClass(/warning/);

  await page.locator('#proAuthPolicy').selectOption('any-signature');
  await expect(proPreview).toContainText('Restore requires at least one valid archive-approval signature matched by an external signer pin.');
  await expect(proPreview).toHaveClass(/informational/);
  await expect.poll(async () => proPreview.evaluate((element) => element.getBoundingClientRect().width)).toBeGreaterThan(200);
});

test('Lite create rejects noninteger configuration and oversized plaintext before key ownership', async ({ page }) => {
  await page.goto('/');
  await page.locator('#liteFilesInput').setInputFiles({
    name: 'bounded-preflight-private-name.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('x'),
  });

  const createButton = page.locator('#liteCreateShardsBtn');
  const nInput = page.locator('#liteN');
  const thresholdInput = page.locator('#liteThreshold');
  const setNumberValue = async (locator, value) => {
    await locator.evaluate((element, nextValue) => {
      element.value = nextValue;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
  };

  for (const value of ['4', '26', '5.5']) {
    await setNumberValue(nInput, value);
    await expect(createButton).toBeDisabled();
  }
  await setNumberValue(nInput, '5');
  for (const value of ['49', '91', '60.5']) {
    await setNumberValue(thresholdInput, value);
    await expect(createButton).toBeDisabled();
  }

  await setNumberValue(thresholdInput, '90');
  await expect(page.locator('#thresholdText')).toHaveText('Configuration Error');
  await expect(createButton).toBeDisabled();

  await setNumberValue(thresholdInput, '60');
  await expect(createButton).toBeEnabled();

  await page.locator('#liteAuthPolicy').evaluate((element) => {
    element.value = '';
    element.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await expect(createButton).toBeDisabled();
  await page.locator('#liteAuthPolicy').selectOption('integrity-only');
  await expect(createButton).toBeEnabled();

  const rejectedName = 'oversized-selection-secret-name.bin';
  await page.locator('#liteFilesInput').setInputFiles({
    name: rejectedName,
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc((8 * 1024 * 1024) + 1, 0x5a),
  });
  await expect(createButton).toBeDisabled();
  await expect(page.locator('#liteFilesList')).toContainText('exceeds the fixed Lite browser input profile');
  await expect(page.locator('#liteFilesInput')).toHaveValue('');

  // Install a FileList without dispatching the normal change event so the
  // click handler's independent profile check is exercised directly.
  const handlerRejectedName = 'handler-preflight-secret-name.bin';
  await page.locator('#liteFilesInput').evaluate((element, name) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File(
      [new Uint8Array((8 * 1024 * 1024) + 1)],
      name,
      { type: 'application/octet-stream' },
    ));
    element.files = transfer.files;
  }, handlerRejectedName);
  await createButton.evaluate((element) => { element.disabled = false; });
  await createButton.click();
  await expect(page.locator('#liteFilesInput')).toHaveValue('');
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  const bodyText = await page.locator('body').innerText();
  expect(bodyText).not.toContain(rejectedName);
  expect(bodyText).not.toContain(handlerRejectedName);
  await expect(page.getByTestId('operations-log')).not.toContainText(rejectedName);
  await expect(page.getByTestId('operations-log')).not.toContainText(handlerRejectedName);
});

test('Lite raw-key backup is default-off and requires a fresh threshold-bypass acknowledgement', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();

  const backupWarning = page.getByTestId('lite-raw-key-backup-warning');
  const backupAcknowledgement = page.getByTestId('lite-raw-key-backup-ack');
  await expect(backupWarning).toContainText('raw ML-KEM private key');
  await expect(backupWarning).toContainText('unilateral 1-of-1 recovery root');
  await expect(backupWarning).toContainText('bypasses the shard threshold');
  await expect(backupAcknowledgement).not.toBeChecked();

  const custody = page.getByTestId('lite-custody-guidance');
  await expect(custody).toBeVisible();
  await expect(custody).toContainText('independent shard custody');
  await expect(custody).toContainText('Retain the archive-state descriptor');
  await expect(custody).toContainText('Pro Attach');
  await expect(custody).toContainText('Optional 1-of-1 Key Backup');
  await expect(custody).toContainText('bypasses the shard threshold');
  await expect(custody).toContainText(/optional/i);
  await expect(custody).toContainText('not storage confirmation');

  const createBtn = page.locator('#liteCreateShardsBtn');
  await expect(createBtn).toBeDisabled();

  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'cancelled-export-private-name.txt',
    'cancelled export payload',
  );
  const exportPanel = page.getByTestId('lite-export-session');
  await expect(exportPanel).toContainText('temporarily holds the operation key and a complete recovery set');
  await expect(exportPanel).toContainText('does not prove durable storage');
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(7);
  await expect(page.getByTestId('lite-export-checklist')).toBeHidden();

  await page.getByTestId('lite-export-cancel').click();
  await expect(exportPanel).toBeHidden();
  await expect(createBtn).toBeDisabled();
  await expect(page.locator('#liteFilesInput')).toHaveValue('');
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(backupAcknowledgement).not.toBeChecked();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.getByTestId('operations-log')).not.toContainText('cancelled-export-private-name.txt');

  await page.locator('#liteFilesInput').setInputFiles({
    name: 'fresh-selection-after-cancel.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('fresh'),
  });
  await expect(createBtn).toBeEnabled();
});

test('a pending acknowledged key blocks supersession until explicit export or discard', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'pending-key-decision-private-name.txt',
    'pending key custody decision',
    { retainRawKeyBackup: true },
  );
  const payloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, payloads);
  await expectVerifiedLiteRows(page, 7);

  const createButton = page.locator('#liteCreateShardsBtn');
  const plaintextInput = page.locator('#liteFilesInput');
  const acknowledgement = page.getByTestId('lite-raw-key-backup-ack');
  const exportButton = page.locator('#liteDownloadKeysBtn');
  const discardButton = page.locator('#liteDiscardKeysBtn');
  await expect(page.locator('#keyStatus .status-text')).toContainText(
    'Pending 1-of-1 key decision blocks the next archive',
  );
  await expect(exportButton).toBeVisible();
  await expect(discardButton).toBeVisible();
  await expect(createButton).toBeDisabled();
  await expect(plaintextInput).toBeDisabled();
  await expect(acknowledgement).toBeDisabled();

  // Disabled controls are only a presentation boundary. Force the handler to
  // run and prove the controller itself refuses to supersede pending material.
  await createButton.evaluate((button) => { button.disabled = false; });
  await createButton.click();
  await expect(exportButton).toBeVisible();
  await expect(discardButton).toBeVisible();
  await expect(lastToast(page)).toContainText('before creating another archive');

  await page.getByTestId('mode-toggle-control').click();
  await expect(page.getByTestId('mode-toggle')).not.toBeChecked();
  await expect(exportButton).toBeVisible();
  await expect(lastToast(page)).toContainText('before switching modes');

  await discardButton.click();
  await expect(exportButton).toBeHidden();
  await expect(discardButton).toBeHidden();
  await expect(plaintextInput).toBeEnabled();
  await expect(acknowledgement).toBeEnabled();
  await expect(page.getByTestId('lite-export-checklist')).toContainText(
    'Authorized 1-of-1 key export cancelled',
  );
  await expect(page.getByTestId('operations-log')).toContainText(
    'Pending optional 1-of-1 key material was explicitly discarded',
  );

  await plaintextInput.setInputFiles({
    name: 'after-explicit-key-discard.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('next archive may start'),
  });
  await expect(createButton).toBeEnabled();
  expect(await page.locator('body').innerText()).not.toContain('pending-key-decision-private-name.txt');
});

test('missing exact key-decision controls suppress optional retention without stranding Lite custody', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'key-decision-control-private-name.txt',
    'key decision control replacement',
    { retainRawKeyBackup: true },
  );

  await page.evaluate(() => {
    for (const id of ['liteDownloadKeysBtn', 'liteDiscardKeysBtn']) {
      const original = document.getElementById(id);
      const replacement = original.cloneNode(true);
      original.replaceWith(replacement);
    }
  });

  const payloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, payloads);
  await expectVerifiedLiteRows(page, 7);
  await expect(page.getByTestId('lite-export-checklist')).toContainText(
    'Authorized 1-of-1 key export cancelled',
  );
  await expect(page.locator('#keyStatus .status-text')).toContainText(
    'Fresh keys are generated per archive',
  );
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeHidden();
  await expect(page.getByTestId('operations-log')).toContainText(
    'Authorized optional key retention was suppressed because its exact bound decision controls were unavailable',
  );

  await page.locator('#liteFilesInput').setInputFiles({
    name: 'after-key-control-fail-closed.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('next threshold-only archive may start'),
  });
  await expect(page.locator('#liteCreateShardsBtn')).toBeEnabled();
  expect(await page.locator('body').innerText()).not.toContain('key-decision-control-private-name.txt');
});

test('active archive and retained-key custody block Lite Restore until explicit resolution', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('/');

  const restoreTab = page.locator('#liteTabRestore');
  const protectTab = page.locator('#liteTabProtect');
  const forceRestoreHandler = async () => {
    await restoreTab.evaluate((tab) => {
      tab.disabled = false;
      tab.setAttribute('aria-disabled', 'false');
      tab.click();
    });
    await expect(restoreTab).toHaveAttribute('aria-selected', 'true');
    await page.locator('#liteRestoreBtn').evaluate((button) => {
      button.disabled = false;
      button.click();
    });
    await expect(page.getByTestId('operations-log')).toContainText(
      'Lite Restore was blocked because another workflow remains unresolved',
    );
  };

  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'active-custody-input.txt',
    'active archive custody',
  );
  await expect(restoreTab).toBeDisabled();
  await expect(restoreTab).toHaveAttribute('aria-disabled', 'true');
  await expect(protectTab).toHaveAttribute('aria-selected', 'true');

  await forceRestoreHandler();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(7);
  await protectTab.click();
  await page.getByTestId('lite-export-cancel').click();
  await expect(restoreTab).toBeEnabled();
  await expect(restoreTab).toHaveAttribute('aria-disabled', 'false');

  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'retained-custody-input.txt',
    'retained key custody',
    { retainRawKeyBackup: true },
  );
  const payloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, payloads);
  await expectVerifiedLiteRows(page, 7);
  await expect(page.locator('#liteDownloadKeysBtn')).toBeVisible();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeVisible();
  await expect(restoreTab).toBeDisabled();
  await expect(restoreTab).toHaveAttribute('aria-disabled', 'true');

  await forceRestoreHandler();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeVisible();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeVisible();
  await protectTab.click();
  await page.locator('#liteDiscardKeysBtn').click();
  await expect(restoreTab).toBeEnabled();
  await expect(restoreTab).toHaveAttribute('aria-disabled', 'false');
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeHidden();
});

test('partial archive cancellation warns about external copies and retries failed URL revocation', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'partial-archive-cancel-private-name.txt',
    'partial archive cancellation',
  );

  await page.evaluate(() => {
    const originalRevoke = URL.revokeObjectURL.bind(URL);
    let failuresRemaining = 2;
    window.__qvRevokeAttempts = 0;
    URL.revokeObjectURL = (objectUrl) => {
      window.__qvRevokeAttempts += 1;
      if (failuresRemaining > 0) {
        failuresRemaining -= 1;
        throw new Error('fault-injected URL revocation failure');
      }
      originalRevoke(objectUrl);
    };
  });

  const requestedArtifact = await downloadLiteExportRow(page, 0);
  await expect.poll(() => page.evaluate(() => window.__qvRevokeAttempts)).toBe(1);
  const unexpectedRetryDownloads = [];
  const onRetryDownload = (download) => unexpectedRetryDownloads.push(download);
  page.on('download', onRetryDownload);
  try {
    await page.getByTestId('lite-export-row-action-0').click();
    await page.waitForTimeout(150);
    expect(unexpectedRetryDownloads).toHaveLength(0);
  } finally {
    page.off('download', onRetryDownload);
  }
  await expect.poll(() => page.evaluate(() => window.__qvRevokeAttempts)).toBe(2);
  await expect(page.getByTestId('operations-log')).toContainText(
    'Artifact download request failed; retry the affected row',
  );
  await page.getByTestId('mode-toggle-control').click();
  await expect(page.getByTestId('mode-toggle')).not.toBeChecked();
  await expect(page.getByTestId('lite-export-session')).toBeVisible();
  await expect(page.getByTestId('lite-export-row-0')).toContainText(
    'Download requested; re-import not verified',
  );
  await expect(lastToast(page)).toContainText('before switching modes');
  await page.getByTestId('lite-export-cancel').click();
  await expect.poll(() => page.evaluate(() => window.__qvRevokeAttempts)).toBeGreaterThanOrEqual(3);
  await expect(page.getByTestId('operations-log')).toContainText(
    'requested downloads and any reported pending URL capabilities remain outside that proof',
  );
  await expect(page.getByTestId('operations-log')).toContainText(
    'a threshold set is a complete recovery root',
  );
  await expect(lastToast(page)).toContainText('outside page control');
  expect(await page.locator('body').innerText()).not.toContain(requestedArtifact.name);
  await expect(page.locator('#liteFilesInput')).toHaveValue('');
});

test('a Lite archive DOM handoff fault releases key ownership and permits a clean retry', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await page.locator('#liteFilesInput').setInputFiles({
    name: 'handoff-fault-private-name.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('handoff fault'),
  });
  await page.evaluate(() => {
    const originalCreateElement = document.createElement.bind(document);
    let failListItemOnce = true;
    window.__qvRestoreCreateElement = () => {
      document.createElement = originalCreateElement;
    };
    document.createElement = (tagName, options) => {
      if (failListItemOnce && String(tagName).toLowerCase() === 'li') {
        failListItemOnce = false;
        throw new Error('fault-injected export renderer failure');
      }
      return originalCreateElement(tagName, options);
    };
  });

  await page.locator('#liteCreateShardsBtn').click();
  await expect(page.getByTestId('operations-log')).toContainText(
    'Lite archive preparation failed; no artifact was published',
    { timeout: 60_000 },
  );
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteFilesInput')).toHaveValue('');

  await page.evaluate(() => window.__qvRestoreCreateElement());
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'handoff-retry-private-name.txt',
    'clean retry',
  );
  await page.getByTestId('lite-export-cancel').click();
  expect(await page.locator('body').innerText()).not.toContain('handoff-fault-private-name.txt');
});

test('missing bound export controls fail closed and exact-node restoration permits retry or discard', async ({ page }) => {
  test.setTimeout(300_000);
  await page.goto('/');

  const createButton = page.locator('#liteCreateShardsBtn');
  await page.locator('#liteFilesInput').setInputFiles({
    name: 'control-preflight-input.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('control preflight'),
  });
  await detachExactNode(page, 'liteExportSessionPanel', '__qvDetachedExportPanel');
  await createButton.click();
  await expect(page.getByTestId('operations-log')).toContainText(
    'Lite archive creation could not start because required export controls are unavailable',
  );
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(createButton).toBeEnabled();
  await restoreExactNode(page, '__qvDetachedExportPanel');

  // The complete surface exists at preflight, then the exact bound file input
  // disappears while preparation is yielding. Handoff must discard ownership.
  await detachExactNodeAfterExportMutation(
    page,
    'liteExportReimportInput',
    '__qvDetachedReimportInput',
  );
  await createButton.click();
  await expect(page.getByTestId('operations-log')).toContainText(
    'Lite archive preparation failed; no artifact was published',
    { timeout: 60_000 },
  );
  await expect.poll(
    () => page.evaluate(() => Boolean(window.__qvDetachedReimportInput)),
  ).toBe(true);
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteFilesInput')).toHaveValue('');
  await restoreExactNode(page, '__qvDetachedReimportInput');

  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'control-handoff-retry.txt',
    'control handoff retry',
    { retainRawKeyBackup: true },
  );
  const payloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, payloads);
  await expectVerifiedLiteRows(page, 7);
  await expect(page.locator('#liteDownloadKeysBtn')).toBeVisible();

  // A missing exact cancel control during key-session setup must return the
  // retained pair to lifecycle custody, never silently discard or supersede it.
  await detachExactNodeAfterExportMutation(
    page,
    'liteExportCancelBtn',
    '__qvDetachedExportCancel',
  );
  await page.locator('#liteDownloadKeysBtn').click();
  await expect(page.getByTestId('operations-log')).toContainText(
    'Optional key export setup failed; pending key material remains available',
  );
  await expect.poll(
    () => page.evaluate(() => Boolean(window.__qvDetachedExportCancel)),
  ).toBe(true);
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeVisible();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeVisible();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Pending 1-of-1 key decision');
  await restoreExactNode(page, '__qvDetachedExportCancel');

  await page.locator('#liteDownloadKeysBtn').click();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(2);
  await page.getByTestId('lite-export-cancel').click();
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeHidden();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
});

test('switching modes clears an idle Lite plaintext FileList from the DOM', async ({ page }) => {
  await page.goto('/');
  const privateName = 'idle-mode-switch-private-name.txt';
  const input = page.locator('#liteFilesInput');
  await input.setInputFiles({
    name: privateName,
    mimeType: 'text/plain',
    buffer: Buffer.from('idle mode switch'),
  });
  await expect(input).not.toHaveValue('');
  await page.getByTestId('mode-toggle-control').click();
  await expect(page.getByTestId('mode-toggle')).toBeChecked();
  await expect(input).toHaveValue('');
  await expect(page.locator('#liteFilesList')).toBeHidden();
  expect(await page.locator('body').innerText()).not.toContain(privateName);
});

test('Lite export requires exact name length and digest and makes every failed row retryable', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'verification-dimensions-private-name.txt',
    'verify exact browser export evidence',
  );
  const payloads = await downloadEveryLiteExportRow(page, 7);
  const row = page.getByTestId('lite-export-row-0');
  let current = payloads[0];

  const floodingFiles = Array.from({ length: 65 }, (_, index) => ({
    name: `reimport-flood-${String(index).padStart(2, '0')}.bin`,
    mimeType: 'application/octet-stream',
    buffer: Buffer.from([index]),
  }));
  await reimportLiteArtifacts(page, floodingFiles);
  await expectVerifiedLiteRows(page, 0);
  await expect(page.getByTestId('operations-log')).toContainText(
    'Artifact re-import selection exceeded the fixed verification profile',
  );

  await reimportLiteArtifacts(page, [{
    ...current,
    name: `wrong-${current.name}`,
  }]);
  await expect(row).toContainText('Download requested; re-import not verified');
  await expect(page.getByTestId('lite-export-row-action-0')).toHaveText('Retry');
  current = await downloadLiteExportRow(page, 0);

  await reimportLiteArtifacts(page, [{
    ...current,
    buffer: Buffer.concat([current.buffer, Buffer.from([0])]),
  }]);
  await expect(row).toContainText('Verification failed; retry required');
  current = await downloadLiteExportRow(page, 0);

  const corrupted = Buffer.from(current.buffer);
  corrupted[0] ^= 1;
  await reimportLiteArtifacts(page, [{ ...current, buffer: corrupted }]);
  await expect(row).toContainText('Verification failed; retry required');
  current = await downloadLiteExportRow(page, 0);

  await reimportLiteArtifacts(page, [current]);
  await expect(row).toContainText('Exact name, size, and SHA3-512 digest verified');
  await reimportLiteArtifacts(page, payloads.slice(1));
  await expectVerifiedLiteRows(page, 7);
  await expect(page.getByTestId('lite-export-checklist')).toBeVisible();
  await expect(page.getByTestId('operations-log')).toContainText('Artifact re-import verification failed');

  const bodyText = await page.locator('body').innerText();
  for (const payload of payloads) {
    expect(bodyText).not.toContain(payload.name);
  }
  expect(bodyText).not.toContain('verification-dimensions-private-name.txt');
});

test('Lite re-import hashing is single-flight and cancellation aborts before new work', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'reimport-concurrency-private-name.txt',
    'single flight re-import hashing',
  );
  const payload = await downloadLiteExportRow(page, 0);

  await page.evaluate(() => {
    const originalStream = Blob.prototype.stream;
    Blob.prototype.stream = function delayedBlobStream() {
      const upstream = originalStream.call(this).getReader();
      let delayed = false;
      let cancelled = false;
      return new ReadableStream({
        async pull(controller) {
          if (!delayed) {
            delayed = true;
            await new Promise((resolve) => setTimeout(resolve, 1_000));
          }
          if (cancelled) return;
          const result = await upstream.read();
          if (cancelled) return;
          if (result.done) controller.close();
          else controller.enqueue(result.value);
        },
        cancel(reason) {
          cancelled = true;
          return upstream.cancel(reason);
        },
      });
    };
  });

  await reimportLiteArtifacts(page, [payload]);
  await expect(page.locator('#liteExportReimportBtn')).toBeDisabled();
  await page.locator('#liteExportReimportInput').evaluate((input, file) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([Uint8Array.from(file.bytes)], file.name, {
      type: file.mimeType,
    }));
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, {
    name: payload.name,
    mimeType: payload.mimeType,
    bytes: [...payload.buffer],
  });
  await expect(page.getByTestId('operations-log')).toContainText(
    'Artifact re-import verification is already active',
  );
  await expect(lastToast(page)).toContainText('active artifact verification');

  await page.getByTestId('lite-export-cancel').click();
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteFilesInput')).toBeEnabled();
  await expect(page.getByTestId('operations-log')).toContainText(
    'requested downloads and any reported pending URL capabilities remain outside that proof',
  );
  expect(await page.locator('body').innerText()).not.toContain(payload.name);
  expect(await page.locator('body').innerText()).not.toContain('reimport-concurrency-private-name.txt');
});

test('cancelling after a private-key request preserves an external-copy warning', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'private-key-cancel-warning-source.txt',
    'private key cancellation warning',
    { retainRawKeyBackup: true },
  );
  const archivePayloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, archivePayloads);
  await expectVerifiedLiteRows(page, 7);

  const acknowledgement = page.getByTestId('lite-raw-key-backup-ack');
  await expect(acknowledgement).toBeDisabled();
  await expect(acknowledgement).not.toBeChecked();
  await page.locator('#liteDownloadKeysBtn').click();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(2);
  await expect(acknowledgement).toBeDisabled();
  await expect(page.getByTestId('lite-export-row-0')).toContainText('Private-key artifact');
  await expect(page.getByTestId('lite-export-cancel')).toHaveText(
    'Cancel & discard pending 1-of-1 key',
  );

  const privateKeyPayload = await downloadLiteExportRow(page, 0);
  await page.getByTestId('mode-toggle-control').click();
  await expect(page.getByTestId('mode-toggle')).not.toBeChecked();
  await expect(page.getByTestId('lite-export-session')).toBeVisible();
  await expect(page.getByTestId('lite-export-row-0')).toContainText(
    'Download requested; re-import not verified',
  );
  await expect(lastToast(page)).toContainText('before switching modes');
  await page.getByTestId('lite-export-cancel').click();
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(acknowledgement).toBeEnabled();
  await expect(acknowledgement).not.toBeChecked();

  const checklist = page.getByTestId('lite-export-checklist');
  await expect(checklist).toContainText('external private-key copy may exist');
  await expect(checklist).toContainText('browser cannot delete requested downloads');
  await expect(checklist).toContainText('securely delete');
  await expect(checklist).not.toContainText('Threshold-only recovery preserved');
  await expect(page.getByTestId('operations-log')).toContainText('requires operator-controlled secure deletion');
  const bodyText = await page.locator('body').innerText();
  expect(bodyText).not.toContain(privateKeyPayload.name);
  expect(bodyText).not.toContain('private-key-cancel-warning-source.txt');
});

test('persisted pagehide ends archive export capability but preserves the generic download hazard', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'pagehide-archive-input.txt',
    'pagehide archive input',
  );
  const payload = await downloadLiteExportRow(page, 0);
  const warning = page.getByTestId('lite-external-copy-warning');
  await expect(warning).toBeVisible();
  await expect(page.locator('#liteExternalCopyWarningSummary')).toHaveText(
    ARCHIVE_EXTERNAL_COPY_HAZARD,
  );

  await dispatchPersistedPageTransition(page, 'pagehide');
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(0);
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.locator('#liteTabRestore')).toBeEnabled();

  await dispatchPersistedPageTransition(page, 'pageshow');
  await expect(warning).toBeVisible();
  await expect(page.locator('#liteExternalCopyWarningSummary')).toHaveText(
    ARCHIVE_EXTERNAL_COPY_HAZARD,
  );
  await expect(page.getByTestId('lite-export-session')).toBeHidden();

  // Re-importing a former download after the wipe cannot resurrect the ended
  // controller or its operation-key capability.
  await page.locator('#liteExportReimportInput').setInputFiles(payload);
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(0);
  await expect(page.locator('#liteExternalCopyWarningSummary')).toHaveText(
    ARCHIVE_EXTERNAL_COPY_HAZARD,
  );
});

test('persisted pagehide ends private-key export capability without clearing either hazard fact', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'pagehide-key-input.txt',
    'pagehide private key input',
    { retainRawKeyBackup: true },
  );
  const archivePayloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, archivePayloads);
  await expectVerifiedLiteRows(page, 7);
  await page.locator('#liteDownloadKeysBtn').click();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(2);
  await downloadLiteExportRow(page, 0);

  const expectedWarning = `${ARCHIVE_EXTERNAL_COPY_HAZARD} ${PRIVATE_KEY_EXTERNAL_COPY_HAZARD}`;
  const warning = page.getByTestId('lite-external-copy-warning');
  await expect(warning).toBeVisible();
  await expect(page.locator('#liteExternalCopyWarningSummary')).toHaveText(expectedWarning);

  await dispatchPersistedPageTransition(page, 'pagehide');
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(0);
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeHidden();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.locator('#liteTabRestore')).toBeEnabled();

  await dispatchPersistedPageTransition(page, 'pageshow');
  await expect(warning).toBeVisible();
  await expect(page.locator('#liteExternalCopyWarningSummary')).toHaveText(expectedWarning);
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeHidden();
});

test('DOM faults cannot prevent archive settlement or strand optional key-export ownership', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'settlement-fault-private-name.txt',
    'settlement and key handoff fault',
    { retainRawKeyBackup: true },
  );
  const payloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, payloads.slice(0, -1));
  await expectVerifiedLiteRows(page, 6);

  const injectOneListItemFailure = async () => {
    await page.evaluate(() => {
      const originalCreateElement = document.createElement.bind(document);
      let failOnce = true;
      window.__qvRestoreCreateElementAfterFault = () => {
        document.createElement = originalCreateElement;
      };
      document.createElement = (tagName, options) => {
        if (failOnce && String(tagName).toLowerCase() === 'li') {
          failOnce = false;
          throw new Error('fault-injected completion renderer failure');
        }
        return originalCreateElement(tagName, options);
      };
    });
  };

  // The first fault occurs while rendering the completion checklist. Security
  // settlement must already have happened, so the acknowledged key is offered.
  await injectOneListItemFailure();
  await reimportLiteArtifacts(page, payloads.slice(-1));
  await expect(page.locator('#liteDownloadKeysBtn')).toBeVisible();
  await expect(page.getByTestId('lite-raw-key-backup-ack')).toBeDisabled();
  await page.evaluate(() => window.__qvRestoreCreateElementAfterFault());

  // The second fault occurs while rendering the two-row key session. Starting
  // export is not a discard decision, so setup failure must return ownership.
  await injectOneListItemFailure();
  await page.locator('#liteDownloadKeysBtn').click();
  await expect(page.getByTestId('operations-log')).toContainText(
    'Optional key export setup failed; pending key material remains available',
  );
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeVisible();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeVisible();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Pending 1-of-1 key decision');
  await expect(lastToast(page)).toContainText('pending key was preserved');
  await page.evaluate(() => window.__qvRestoreCreateElementAfterFault());

  // A clean retry still owns the same pending decision; explicit cancellation
  // then performs the destructive transition named by the button.
  await page.locator('#liteDownloadKeysBtn').click();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(2);
  await page.getByTestId('lite-export-cancel').click();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeHidden();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  expect(await page.locator('body').innerText()).not.toContain('settlement-fault-private-name.txt');
});

test('Lite publication requires the exact visible warning surface and detached anchors never enter the DOM', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'warning-surface-private-name.txt',
    'warning surface publication gate',
  );

  await page.evaluate(() => {
    window.__qvConnectedDownloadAnchors = [];
    window.__qvDownloadAnchorObserver = new MutationObserver((records) => {
      for (const record of records) {
        for (const added of record.addedNodes) {
          if (!(added instanceof Element)) continue;
          const anchors = added.matches('a')
            ? [added]
            : [...added.querySelectorAll('a')];
          for (const anchor of anchors) {
            if (anchor.hasAttribute('download') || String(anchor.href || '').startsWith('blob:')) {
              window.__qvConnectedDownloadAnchors.push({
                download: anchor.getAttribute('download'),
                href: anchor.getAttribute('href'),
              });
            }
          }
        }
      }
    });
    window.__qvDownloadAnchorObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });

    const summary = document.getElementById('liteExternalCopyWarningSummary');
    const marker = document.createComment('qv-test-warning-summary');
    summary.parentNode.insertBefore(marker, summary);
    summary.remove();
    const replacement = document.createElement('p');
    replacement.id = 'liteExternalCopyWarningSummary';
    marker.parentNode.insertBefore(replacement, marker.nextSibling);
    window.__qvWarningSummaryFixture = { marker, summary, replacement };
  });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    const action = page.getByTestId('lite-export-row-action-0');
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Download');
    await expect(page.getByTestId('operations-log')).toContainText(
      'Artifact download request failed; retry the affected row',
    );

    await page.evaluate(() => {
      const { marker, summary, replacement } = window.__qvWarningSummaryFixture;
      replacement.remove();
      marker.replaceWith(summary);
      summary.hidden = true;
    });
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Download');

    await page.evaluate(() => {
      window.__qvWarningSummaryFixture.summary.hidden = false;
      window.__qvWarningSummaryFixture.summary.style.visibility = 'hidden';
    });
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Download');

    await page.evaluate(() => {
      const summary = window.__qvWarningSummaryFixture.summary;
      summary.style.visibility = '';
      summary.parentElement.style.opacity = '0';
    });
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Download');

    await page.evaluate(() => {
      window.__qvWarningSummaryFixture.summary.parentElement.style.opacity = '';
      document.getElementById('liteExportCancelBtn').style.display = 'none';
    });
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Download');

    await page.evaluate(() => {
      document.getElementById('liteExportCancelBtn').style.display = '';
      document.getElementById('liteExportReimportBtn').style.display = 'none';
    });
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Download');

    await page.evaluate(() => {
      document.getElementById('liteExportReimportBtn').style.display = '';
    });
    const payload = await downloadLiteExportRow(page, 0);
    expect(payload.name).toMatch(/\.qcont$/i);
    await expect.poll(() => page.evaluate(
      () => window.__qvConnectedDownloadAnchors.length,
    )).toBe(0);
    expect(await page.locator('body').innerText()).not.toContain(payload.name);
  } finally {
    page.off('download', onDownload);
    await page.evaluate(() => window.__qvDownloadAnchorObserver?.disconnect());
  }
});

test('composed object-URL registration and revocation faults poison Lite publication retry', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'object-url-accounting-private-name.txt',
    'object URL accounting fail closed',
  );

  await page.evaluate(() => {
    const originalSet = Map.prototype.set;
    const originalRevoke = URL.revokeObjectURL;
    window.__qvRestoreObjectUrlFaults = () => {
      Map.prototype.set = originalSet;
      URL.revokeObjectURL = originalRevoke;
    };
    Map.prototype.set = function faultObjectUrlRegistration(key, value) {
      if (typeof key === 'string' && key.startsWith('blob:') && typeof value === 'number') {
        throw new Error('fault-injected object URL registration failure');
      }
      return originalSet.call(this, key, value);
    };
    URL.revokeObjectURL = () => {
      throw new Error('fault-injected object URL revocation failure');
    };
  });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    const action = page.getByTestId('lite-export-row-action-0');
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Retry');
    await page.evaluate(() => window.__qvRestoreObjectUrlFaults());
    await expect(page.locator('#liteExternalCopyWarningSummary')).toContainText(
      'Browser object-URL cleanup or per-row capability accounting failed closed',
    );

    // Restoring the faulted adapters does not restore trust in an unaccounted
    // capability. The document remains poisoned until it is closed.
    await action.click();
    await page.waitForTimeout(150);
    expect(downloads).toHaveLength(0);
    await expect(action).toHaveText('Retry');
    await expect(page.getByTestId('operations-log')).toContainText(
      'Artifact download request failed; retry the affected row',
    );
  } finally {
    page.off('download', onDownload);
    await page.evaluate(() => window.__qvRestoreObjectUrlFaults?.());
  }
});

test('synchronous pagehide during final archive and key renders cannot resurrect export authority', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('/');

  const installFinalRenderBoundary = async () => {
    await page.evaluate(() => {
      const originalAppendChild = Node.prototype.appendChild;
      Node.prototype.appendChild = function dispatchPagehideOnFinalExportRow(child) {
        if (
          this instanceof HTMLElement &&
          this.id === 'liteExportSessionRows' &&
          child instanceof HTMLLIElement
        ) {
          Node.prototype.appendChild = originalAppendChild;
          window.__qvFinalRenderPagehideCount =
            Number(window.__qvFinalRenderPagehideCount || 0) + 1;
          window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
        }
        return originalAppendChild.call(this, child);
      };
    });
  };

  await page.locator('#liteFilesInput').setInputFiles({
    name: 'archive-final-render-private-name.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('archive final render boundary'),
  });
  await installFinalRenderBoundary();
  await page.locator('#liteCreateShardsBtn').click();
  await expect.poll(() => page.evaluate(
    () => Number(window.__qvFinalRenderPagehideCount || 0),
  ), { timeout: 60_000 }).toBe(1);
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(0);
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.locator('#liteTabRestore')).toBeEnabled();

  await dispatchPersistedPageTransition(page, 'pageshow');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'key-final-render-private-name.txt',
    'key final render boundary',
    { retainRawKeyBackup: true },
  );
  const archivePayloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, archivePayloads);
  await expectVerifiedLiteRows(page, 7);
  await installFinalRenderBoundary();
  await page.locator('#liteDownloadKeysBtn').click();
  await expect.poll(() => page.evaluate(
    () => Number(window.__qvFinalRenderPagehideCount || 0),
  ), { timeout: 60_000 }).toBe(2);
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(0);
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeHidden();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');
  await expect(page.locator('#liteTabRestore')).toBeEnabled();
});

test('session wipe clears exact and same-ID Lite file inputs through captured native accessors', async ({ page }) => {
  await page.goto('/');
  await page.locator('#liteFilesInput').setInputFiles({
    name: 'native-plaintext-clear-private-name.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('native plaintext clear'),
  });
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicySatisfiedFiles);

  await page.evaluate(() => {
    const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    const filesDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'files');
    if (!valueDescriptor?.get || !filesDescriptor?.get) {
      throw new Error('native input descriptors unavailable');
    }
    const installOwnValueFault = (input, mode) => {
      Object.defineProperty(input, 'value', {
        configurable: true,
        get() { return valueDescriptor.get.call(this); },
        set() {
          if (mode === 'throw') throw new Error('fault-injected input value setter');
          // Deliberate no-op.
        },
      });
    };
    const detachWithReplacement = (id, mode) => {
      const exact = document.getElementById(id);
      const marker = document.createComment(`qv-test-${id}`);
      exact.parentNode.insertBefore(marker, exact);
      exact.remove();
      installOwnValueFault(exact, mode);

      const replacement = document.createElement('input');
      replacement.type = 'file';
      replacement.id = id;
      replacement.multiple = true;
      const transfer = new DataTransfer();
      transfer.items.add(new File([new Uint8Array([1, 2, 3])], `${id}-replacement.bin`));
      replacement.files = transfer.files;
      installOwnValueFault(replacement, mode === 'throw' ? 'noop' : 'throw');
      marker.parentNode.insertBefore(replacement, marker.nextSibling);
      return { exact, replacement };
    };
    window.__qvNativeClearInputs = {
      plaintext: detachWithReplacement('liteFilesInput', 'throw'),
      restore: detachWithReplacement('liteShardsInput', 'noop'),
      filesGetter: filesDescriptor.get,
    };
  });

  await dispatchPersistedPageTransition(page, 'pagehide');
  const inputState = await page.evaluate(() => {
    const { plaintext, restore, filesGetter } = window.__qvNativeClearInputs;
    const length = (input) => Number(filesGetter.call(input)?.length || 0);
    return {
      plaintextExact: length(plaintext.exact),
      plaintextReplacement: length(plaintext.replacement),
      restoreExact: length(restore.exact),
      restoreReplacement: length(restore.replacement),
      plaintextExactConnected: plaintext.exact.isConnected,
      restoreExactConnected: restore.exact.isConnected,
    };
  });
  expect(inputState).toEqual({
    plaintextExact: 0,
    plaintextReplacement: 0,
    restoreExact: 0,
    restoreReplacement: 0,
    plaintextExactConnected: false,
    restoreExactConnected: false,
  });
  await expect(page.locator('#shardsStatusText')).toHaveText('No restore inputs selected');
});

test('stale outer Lite Restore refresh cannot repopulate cleared session presentation', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await page.locator('#liteTabRestore').click();
  await page.evaluate(() => {
    const originalArrayBuffer = Blob.prototype.arrayBuffer;
    let releaseRead;
    const gate = new Promise((resolve) => { releaseRead = resolve; });
    let delayed = false;
    window.__qvStaleRefreshReadStarted = false;
    window.__qvReleaseStaleRefreshRead = () => releaseRead();
    Blob.prototype.arrayBuffer = async function delayedOuterRestoreRefresh() {
      if (!delayed) {
        delayed = true;
        window.__qvStaleRefreshReadStarted = true;
        await gate;
      }
      return originalArrayBuffer.call(this);
    };
  });

  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicySatisfiedFiles);
  await expect.poll(
    () => page.evaluate(() => window.__qvStaleRefreshReadStarted),
  ).toBe(true);
  await dispatchPersistedPageTransition(page, 'pagehide');
  await page.evaluate(() => window.__qvReleaseStaleRefreshRead());
  await page.waitForTimeout(300);

  await expect(page.locator('#liteShardsInput')).toHaveValue('');
  await expect(page.locator('#shardsStatus')).toBeHidden();
  await expect(page.locator('#shardsStatusText')).toHaveText('No restore inputs selected');
  for (const selector of [
    '#liteRestoreArtifactIntake',
    '#liteRestorePreflightDecision',
    '#liteRestoreArchiveInspector',
  ]) {
    await expect(page.locator(selector)).toBeHidden();
    await expect(page.locator(selector)).toBeEmpty();
  }
  await expect(page.locator('#liteRestoreSuccessorSelection')).toBeHidden();
  await expect(page.locator('#liteRestoreSuccessorSelectionSummary')).toBeEmpty();
  await expect(page.locator('#liteRestoreSuccessorSelectionHelp')).toBeEmpty();
  await expect(page.locator('#liteRestoreStateSelection option')).toHaveCount(0);
  await expect(page.locator('#liteRestoreCohortSelection option')).toHaveCount(0);
  await expect(page.locator('#liteRestoreBundleSelection option')).toHaveCount(0);
  await expect(page.locator('#liteRestoreArchiveReviewRoot')).not.toHaveAttribute('open', '');
});

test('re-import control faults release verification ownership and selected File references', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'reimport-setter-fault-private-name.txt',
    'reimport setter fault release',
  );
  const first = await downloadLiteExportRow(page, 0);
  const second = await downloadLiteExportRow(page, 1);

  await page.evaluate((expectedNames) => {
    const disabledDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'disabled');
    const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (!disabledDescriptor?.get || !valueDescriptor?.get) {
      throw new Error('native input accessors unavailable');
    }
    const input = document.getElementById('liteExportReimportInput');
    Object.defineProperty(input, 'disabled', {
      configurable: true,
      get() { return disabledDescriptor.get.call(this); },
      set() { throw new Error('fault-injected re-import disabled setter'); },
    });
    Object.defineProperty(input, 'value', {
      configurable: true,
      get() { return valueDescriptor.get.call(this); },
      set() { throw new Error('fault-injected re-import value setter'); },
    });

    const names = new Set(expectedNames);
    const originalPush = Array.prototype.push;
    window.__qvCapturedReimportArrays = [];
    window.__qvRestoreReimportArrayPush = () => { Array.prototype.push = originalPush; };
    Array.prototype.push = function captureReimportFiles(...items) {
      if (items.some((item) => item instanceof File && names.has(item.name))) {
        window.__qvCapturedReimportArrays.push(this);
      }
      return originalPush.apply(this, items);
    };
  }, [first.name, second.name]);

  await reimportLiteArtifacts(page, [first]);
  await expectVerifiedLiteRows(page, 1);
  await page.locator('#liteExportReimportInput').evaluate((input) => {
    delete input.disabled;
  });
  await reimportLiteArtifacts(page, [second]);
  await expectVerifiedLiteRows(page, 2);
  const capturedLengths = await page.evaluate(() => {
    window.__qvRestoreReimportArrayPush();
    const input = document.getElementById('liteExportReimportInput');
    const filesGetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'files')?.get;
    const inputFileCount = filesGetter ? Number(filesGetter.call(input)?.length || 0) : -1;
    delete input.disabled;
    delete input.value;
    return {
      capturedLengths: window.__qvCapturedReimportArrays.map((files) => files.length),
      inputFileCount,
    };
  });
  expect(capturedLengths.capturedLengths.length).toBeGreaterThanOrEqual(2);
  expect(capturedLengths.capturedLengths.every((length) => length === 0)).toBe(true);
  expect(capturedLengths.inputFileCount).toBe(0);
  await expect(page.getByTestId('operations-log')).not.toContainText(
    'Artifact re-import verification is already active',
  );
});

test('explicit cancel and pagehide settle Lite custody despite raw-ack and input setter faults', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');

  const installSetterFaults = async () => {
    await page.evaluate(() => {
      const checkedDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked');
      const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
      const acknowledgement = document.getElementById('liteRetainRawKeyAck');
      const input = document.getElementById('liteFilesInput');
      Object.defineProperty(acknowledgement, 'checked', {
        configurable: true,
        get() { return checkedDescriptor.get.call(this); },
        set() { throw new Error('fault-injected acknowledgement setter'); },
      });
      Object.defineProperty(input, 'value', {
        configurable: true,
        get() { return valueDescriptor.get.call(this); },
        set() { throw new Error('fault-injected plaintext input setter'); },
      });
    });
  };
  const removeSetterFaults = async () => {
    await page.evaluate(() => {
      delete document.getElementById('liteRetainRawKeyAck').checked;
      delete document.getElementById('liteFilesInput').value;
    });
  };

  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'explicit-cancel-setter-fault.txt',
    'explicit cancellation survives setters',
  );
  await installSetterFaults();
  await page.getByTestId('lite-export-cancel').click();
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.locator('#liteTabRestore')).toBeEnabled();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');

  await removeSetterFaults();
  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'pagehide-setter-fault.txt',
    'pagehide cancellation survives setters',
  );
  await installSetterFaults();
  await dispatchPersistedPageTransition(page, 'pagehide');
  await expect(page.getByTestId('lite-export-session')).toBeHidden();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(0);
  await expect(page.locator('#liteTabRestore')).toBeEnabled();
  await expect(page.locator('#keyStatus .status-text')).toContainText('Fresh keys are generated per archive');

  await removeSetterFaults();
  await page.locator('#liteFilesInput').setInputFiles({
    name: 'post-fault-clean-selection.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('post fault clean selection'),
  });
  await expect(page.locator('#liteCreateShardsBtn')).toBeEnabled();
});

test('Lite Restore blocks the native click when pagehide fires from the output anchor setter', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicySatisfiedFiles);
  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeEnabled({ timeout: 30_000 });

  await page.evaluate(() => {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'download');
    const originalClick = HTMLAnchorElement.prototype.click;
    window.__qvRestoreDownloadSetter = () => {
      Object.defineProperty(HTMLAnchorElement.prototype, 'download', descriptor);
      HTMLAnchorElement.prototype.click = originalClick;
    };
    window.__qvRestoreAnchorClickCount = 0;
    let fired = false;
    Object.defineProperty(HTMLAnchorElement.prototype, 'download', {
      configurable: descriptor.configurable,
      enumerable: descriptor.enumerable,
      get: descriptor.get,
      set(value) {
        descriptor.set.call(this, value);
        if (!fired) {
          fired = true;
          window.__qvRestoreSetterPagehideFired = true;
          window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
        }
      },
    });
    HTMLAnchorElement.prototype.click = function countGuardedRestoreClick() {
      window.__qvRestoreAnchorClickCount += 1;
      return originalClick.call(this);
    };
  });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    await restoreButton.click();
    await expect.poll(
      () => page.evaluate(() => window.__qvRestoreSetterPagehideFired === true),
      { timeout: 60_000 },
    ).toBe(true);
    await expect(page.getByTestId('operations-log')).toContainText(
      'Lite Restore was cancelled; no new plaintext output was released after cancellation',
    );
    expect(downloads).toHaveLength(0);
    expect(await page.evaluate(() => window.__qvRestoreAnchorClickCount)).toBe(0);
    await expect(page.locator('#liteRestoreResult')).toBeHidden();
    await expect(page.locator('#liteTabProtect')).toBeEnabled();
  } finally {
    page.off('download', onDownload);
    await page.evaluate(() => window.__qvRestoreDownloadSetter?.());
  }
});

test('pagehide after the native Restore click cannot resurrect stale success presentation', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicySatisfiedFiles);
  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeEnabled({ timeout: 30_000 });

  await page.evaluate(() => {
    const originalClick = HTMLAnchorElement.prototype.click;
    window.__qvRestoreClickAfterPagehide = () => {
      HTMLAnchorElement.prototype.click = originalClick;
    };
    let fired = false;
    HTMLAnchorElement.prototype.click = function pagehideAfterNativeRestoreClick() {
      const result = originalClick.call(this);
      if (!fired) {
        fired = true;
        window.__qvRestorePostClickPagehideFired = true;
        window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
      }
      return result;
    };
  });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    await restoreButton.click();
    await expect.poll(
      () => page.evaluate(() => window.__qvRestorePostClickPagehideFired === true),
      { timeout: 60_000 },
    ).toBe(true);
    await expect(page.getByTestId('operations-log')).toContainText(
      'Lite Restore was cancelled; no new plaintext output was released after cancellation',
    );
    await page.waitForTimeout(250);
    expect(downloads.length).toBeLessThanOrEqual(1);
    await expect(page.locator('#liteRestoreResult')).toBeHidden();
    await expect(page.getByTestId('operations-log')).not.toContainText(
      'Container restored successfully from a policy-satisfying archive cohort',
    );
    await expect(page.locator('#liteExternalCopyWarningSummary')).toContainText(
      RESTORE_PLAINTEXT_EXTERNAL_COPY_HAZARD,
    );
  } finally {
    page.off('download', onDownload);
    await page.evaluate(() => window.__qvRestoreClickAfterPagehide?.());
  }
});

test('pagehide from Restore logging prevents later plaintext decryption work', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicySatisfiedFiles);
  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeEnabled({ timeout: 30_000 });

  await page.evaluate(() => {
    const originalArrayBuffer = Blob.prototype.arrayBuffer;
    const logElement = document.getElementById('log');
    const originalAppendChild = logElement.appendChild;
    window.__qvRestoreLoggingFault = () => {
      Blob.prototype.arrayBuffer = originalArrayBuffer;
      logElement.appendChild = originalAppendChild;
    };
    window.__qvReadsAfterRestoreLogPagehide = 0;
    window.__qvRestoreLogPagehideFired = false;
    Blob.prototype.arrayBuffer = async function countReadsAfterRestoreCancellation() {
      if (window.__qvRestoreLogPagehideFired) {
        window.__qvReadsAfterRestoreLogPagehide += 1;
      }
      return originalArrayBuffer.call(this);
    };
    logElement.appendChild = function pagehideFromRestoreSelectionLog(node) {
      const result = originalAppendChild.call(this, node);
      if (
        !window.__qvRestoreLogPagehideFired &&
        String(node?.textContent || '').includes('Selected archiveId:')
      ) {
        window.__qvRestoreLogPagehideFired = true;
        window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
      }
      return result;
    };
  });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    await restoreButton.click();
    await expect.poll(
      () => page.evaluate(() => window.__qvRestoreLogPagehideFired),
      { timeout: 60_000 },
    ).toBe(true);
    await expect(page.getByTestId('operations-log')).toContainText(
      'Lite Restore was cancelled; no new plaintext output was released after cancellation',
    );
    expect(await page.evaluate(() => window.__qvReadsAfterRestoreLogPagehide)).toBe(0);
    expect(downloads).toHaveLength(0);
    await expect(page.locator('#liteRestoreResult')).toBeHidden();
  } finally {
    page.off('download', onDownload);
    await page.evaluate(() => window.__qvRestoreLoggingFault?.());
  }
});

test('pagehide inside a Lite Restore failure renderer cannot leave stale error DOM', async ({ page }) => {
  await page.goto('/');
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicyFailFiles);
  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeDisabled();

  await page.evaluate(() => {
    const panel = document.getElementById('liteRestoreInlineError');
    const originalReplaceChildren = panel.replaceChildren;
    window.__qvRestoreFailureRenderer = () => { panel.replaceChildren = originalReplaceChildren; };
    let fired = false;
    panel.replaceChildren = function pagehideFromFailureRenderer(...children) {
      const result = originalReplaceChildren.apply(this, children);
      if (!fired) {
        fired = true;
        window.__qvRestoreFailurePagehideFired = true;
        window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
      }
      return result;
    };
  });

  try {
    await restoreButton.evaluate((button) => {
      button.disabled = false;
      button.click();
    });
    await expect.poll(
      () => page.evaluate(() => window.__qvRestoreFailurePagehideFired === true),
      { timeout: 60_000 },
    ).toBe(true);
    await expect(page.locator('#liteTabProtect')).toBeEnabled();
    await expect(page.getByTestId('lite-restore-inline-error')).toBeHidden();
    await expect(page.getByTestId('lite-restore-inline-error')).toBeEmpty();
    await expect(page.locator('#liteRestoreResult')).toBeHidden();
  } finally {
    await page.evaluate(() => window.__qvRestoreFailureRenderer?.());
  }
});

test('failed Restore URL revocation remains accounted and poisons later Lite publication', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicySatisfiedFiles);
  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeEnabled({ timeout: 30_000 });

  await page.evaluate(() => {
    const originalRevoke = URL.revokeObjectURL;
    window.__qvRestoreUrlRevocation = () => { URL.revokeObjectURL = originalRevoke; };
    window.__qvRestoreRevokeAttempts = 0;
    URL.revokeObjectURL = () => {
      window.__qvRestoreRevokeAttempts += 1;
      throw new Error('fault-injected Restore URL revocation failure');
    };
  });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    await restoreButton.click();
    await expect(page.getByTestId('operations-log')).toContainText(
      'Lite restore output publication failed.',
      { timeout: 60_000 },
    );
    await page.waitForTimeout(250);
    const firstDownloadCount = downloads.length;
    expect(firstDownloadCount).toBeLessThanOrEqual(1);
    await expect(page.getByTestId('operations-log')).not.toContainText(
      'Container restored successfully from a policy-satisfying archive cohort',
    );
    const warning = page.locator('#liteExternalCopyWarningSummary');
    await expect(warning).toContainText(RESTORE_PLAINTEXT_EXTERNAL_COPY_HAZARD);
    await expect(warning).toContainText('Best-effort cleanup remains pending for 1 bounded in-page object-URL capability');
    await expect(warning).toContainText('No further Lite publication is allowed in this page');

    await restoreButton.evaluate((button) => {
      button.disabled = false;
      button.click();
    });
    await expect(lastToast(page)).toContainText('Lite publication is unavailable in this page');
    await page.waitForTimeout(250);
    expect(downloads).toHaveLength(firstDownloadCount);
  } finally {
    page.off('download', onDownload);
    await page.evaluate(() => {
      window.__qvRestoreUrlRevocation?.();
      window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
    });
  }
});

test('Lite Restore preserves valid zero-byte QVPACK entries under the publication profile', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.locator('#liteFilesInput').setInputFiles([
    {
      name: 'empty-preservation-entry.bin',
      mimeType: 'application/octet-stream',
      buffer: Buffer.alloc(0),
    },
    {
      name: 'nonempty-preservation-entry.txt',
      mimeType: 'text/plain',
      buffer: Buffer.from('preserved companion entry'),
    },
  ]);
  await expect(page.locator('#liteCreateShardsBtn')).toBeEnabled();
  await page.locator('#liteCreateShardsBtn').click();
  await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(7, {
    timeout: 60_000,
  });
  const archivePayloads = await downloadEveryLiteExportRow(page, 7);
  await reimportLiteArtifacts(page, archivePayloads);
  await expectVerifiedLiteRows(page, 7);

  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(
    archivePayloads.filter((payload) => /\.qcont$/i.test(payload.name)),
  );
  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeEnabled({ timeout: 30_000 });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    await restoreButton.click();
    await expect.poll(() => downloads.length, { timeout: 60_000 }).toBe(2);
    const restored = await Promise.all(downloads.map((download) => payloadFromDownload(download)));
    const emptyEntry = restored.find((entry) => entry.name === 'empty-preservation-entry.bin');
    expect(emptyEntry).toBeDefined();
    expect(emptyEntry.buffer).toHaveLength(0);
    await expect(page.getByTestId('operations-log')).toContainText(
      'Container restored successfully from a policy-satisfying archive cohort',
    );
  } finally {
    page.off('download', onDownload);
  }
});

test('two Lite archives require 14 individual downloads and exact re-import before key settlement', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);

  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'lite-key-domain-one.txt',
    'first Lite archive key domain',
  );
  const firstPayloads = await downloadEveryLiteExportRow(page, 7);
  firstPayloads.forEach((payload) => {
    expect(payload.name).toMatch(/^qv-[0-9a-f]{32}-(?:shard-[0-9]{2}-of-[0-9]{2}\.qcont|archive-state\.json|lifecycle-bundle\.json)$/);
    expect(payload.name).not.toContain('lite-key-domain-one');
  });
  await expectVerifiedLiteRows(page, 0);
  await expect(page.locator('#liteCreateShardsBtn')).toBeDisabled();
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();

  // A missing required artifact keeps the operation key provisional and blocks
  // another create even after every download was individually requested.
  await reimportLiteArtifacts(page, firstPayloads.slice(0, -1));
  await expectVerifiedLiteRows(page, 6);
  await expect(page.locator('#liteCreateShardsBtn')).toBeDisabled();
  await expect(page.getByTestId('lite-export-session-status')).toContainText('6 of 7');
  await reimportLiteArtifacts(page, firstPayloads.slice(-1));
  await expectVerifiedLiteRows(page, 7);
  await expect(page.getByTestId('lite-raw-key-backup-ack')).toBeEnabled();
  await expect(page.getByTestId('lite-raw-key-backup-ack')).not.toBeChecked();
  await expect(page.getByTestId('lite-export-checklist')).toContainText('Threshold-only recovery preserved');
  await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();

  await beginLiteArchiveWithoutAutomaticDownloads(
    page,
    'lite-key-domain-two.txt',
    'second Lite archive key domain',
    { retainRawKeyBackup: true },
  );
  const secondPayloads = await downloadEveryLiteExportRow(page, 7);
  secondPayloads.forEach((payload) => {
    expect(payload.name).toMatch(/^qv-[0-9a-f]{32}-(?:shard-[0-9]{2}-of-[0-9]{2}\.qcont|archive-state\.json|lifecycle-bundle\.json)$/);
    expect(payload.name).not.toContain('lite-key-domain-two');
  });
  expect([...firstPayloads, ...secondPayloads]).toHaveLength(14);
  expect(new Set([...firstPayloads, ...secondPayloads].map((payload) => payload.name)).size).toBe(14);
  await reimportLiteArtifacts(page, secondPayloads);
  await expectVerifiedLiteRows(page, 7);
  await expect(page.locator('#liteDownloadKeysBtn')).toBeVisible();
  await expect(page.locator('#liteDiscardKeysBtn')).toBeVisible();
  await expect(page.locator('#liteFilesInput')).toBeDisabled();
  await expect(page.getByTestId('lite-export-checklist')).toContainText('Authorized 1-of-1 key backup pending');

  const firstShards = await parseDownloadedLiteShards(firstPayloads);
  const secondShards = await parseDownloadedLiteShards(secondPayloads);
  let firstRestore = null;
  let secondRestore = null;

  try {
    const firstMetadata = firstShards[0].metaJSON;
    const secondMetadata = secondShards[0].metaJSON;
    expect(firstMetadata.privateKeyHash).toMatch(/^[0-9a-f]{128}$/);
    expect(secondMetadata.privateKeyHash).toMatch(/^[0-9a-f]{128}$/);
    expect(firstMetadata.keyCommitmentHex).toMatch(/^[0-9a-f]{64}$/);
    expect(secondMetadata.keyCommitmentHex).toMatch(/^[0-9a-f]{64}$/);
    expect(firstMetadata.privateKeyHash).not.toBe(secondMetadata.privateKeyHash);
    expect(firstMetadata.keyCommitmentHex).not.toBe(secondMetadata.keyCommitmentHex);

    firstRestore = await restoreFromShards(firstShards, { onLog: () => {}, onError: () => {} });
    secondRestore = await restoreFromShards(secondShards, { onLog: () => {}, onError: () => {} });
    expect(firstRestore.qkeyOk).toBe(true);
    expect(secondRestore.qkeyOk).toBe(true);

    await assert.rejects(() => decryptFile(firstRestore.qencBytes, secondRestore.privKey));
    await assert.rejects(() => decryptFile(secondRestore.qencBytes, firstRestore.privKey));

    await expect(page.locator('#ctx-pub-status')).toHaveText('Loaded');
    await expect(page.locator('#ctx-sec-status')).toHaveText('Loaded');

    const unexpectedKeyDownloads = [];
    const onKeyDownload = (download) => unexpectedKeyDownloads.push(download);
    page.on('download', onKeyDownload);
    try {
      await page.locator('#liteDownloadKeysBtn').click();
      await expect(page.getByTestId('lite-export-session-rows').locator('li')).toHaveCount(2);
      await page.waitForTimeout(100);
      expect(unexpectedKeyDownloads).toHaveLength(0);
    } finally {
      page.off('download', onKeyDownload);
    }
    await expect(page.getByTestId('lite-raw-key-backup-ack')).toBeDisabled();
    await expect(page.getByTestId('lite-raw-key-backup-ack')).not.toBeChecked();
    await expect(page.locator('#liteCreateShardsBtn')).toBeDisabled();
    const backupPayloads = await downloadEveryLiteExportRow(page, 2);
    const privateBackup = backupPayloads.find((payload) => /-private\.qkey$/i.test(payload.name));
    const publicBackup = backupPayloads.find((payload) => /-public\.qkey$/i.test(payload.name));
    assert.ok(privateBackup, 'latest Lite private-key backup was not downloaded');
    assert.ok(publicBackup, 'latest Lite public-key backup was not downloaded');
    backupPayloads.forEach((payload) => {
      expect(payload.name).toMatch(/^qv-[0-9a-f]{32}-(?:private|public)\.qkey$/);
    });

    await reimportLiteArtifacts(page, backupPayloads);
    await expectVerifiedLiteRows(page, 2);
    await expect(page.getByTestId('lite-export-checklist')).toContainText('Authorized 1-of-1 key backup re-import verified');

    const backedUpPrivateKeyHash = await hashBytes(new Uint8Array(privateBackup.buffer));
    const backedUpPublicKeyHash = await hashBytes(new Uint8Array(publicBackup.buffer));
    expect(backedUpPrivateKeyHash).toBe(secondMetadata.privateKeyHash);
    expect(backedUpPrivateKeyHash).not.toBe(firstMetadata.privateKeyHash);

    const operationsLog = page.getByTestId('operations-log');
    await expect(operationsLog).not.toContainText(firstMetadata.privateKeyHash);
    await expect(operationsLog).not.toContainText(secondMetadata.privateKeyHash);
    await expect(operationsLog).not.toContainText(backedUpPublicKeyHash);
    const bodyText = await page.locator('body').innerText();
    expect(bodyText).not.toContain(firstMetadata.privateKeyHash);
    expect(bodyText).not.toContain(secondMetadata.privateKeyHash);
    expect(bodyText).not.toContain(backedUpPublicKeyHash);
    const exportPanelText = await page.getByTestId('lite-export-session').innerText();
    backupPayloads.forEach((payload) => expect(exportPanelText).not.toContain(payload.name));
    await expect(page.locator('#ctx-pub-status')).toHaveText('Not Loaded');
    await expect(page.locator('#ctx-sec-status')).toHaveText('Not Loaded');
    await expect(page.locator('#liteDownloadKeysBtn')).toBeHidden();
  } finally {
    wipeRestoreResult(firstRestore);
    wipeRestoreResult(secondRestore);
    firstShards.forEach(zeroizeParsedLifecycleShard);
    secondShards.forEach(zeroizeParsedLifecycleShard);
  }
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
    await expect(page.locator('#liteFilesList .file-name')).toContainText('Plaintext selection ready (1 file)');
    expect(await page.locator('body').innerText()).not.toContain(longName);
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
  await expect(restoreIntake).toContainText('QVqcont-7', { timeout: 15_000 });
  await openArchiveReviewHub(page, 'restore');

  await expect(restoreIntake).toBeVisible();
  await expect(restoreIntake).toContainText('QVqcont-7 shard');
  await expect(restoreIntake).toContainText('archive-approval signature');
  await expect(restoreIntake).toContainText('PQ signer key');
  await expect(restoreIntake).toContainText('OTS proof');
  await openArchiveReviewHub(page, 'restore');
  await expect(restoreIntake.locator('[data-artifact-status="accepted"]').first()).toBeVisible();
  await expect(restoreIntake.locator('[data-artifact-status="pending"]').first()).toBeVisible();
  await restoreIntake.locator('.artifact-row-details').first().locator('summary').click();
  const expandedDigestValue = restoreIntake.locator('.artifact-detail-value').first();
  await expect(expandedDigestValue).toBeVisible();
  await expect.poll(async () => expandedDigestValue.evaluate((element) => element.getBoundingClientRect().width)).toBeGreaterThan(300);

  await page.getByTestId('restore-input').setInputFiles(fixtures.legacyManifestFiles);
  await expect(restoreIntake).toContainText('unsupported', { timeout: 15_000 });
  await openArchiveReviewHub(page, 'restore');
  await expect(restoreIntake.locator('[data-artifact-status="ignored"]').first()).toBeVisible();

  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-input').setInputFiles(fixtures.legacyManifestFiles);
  await openArchiveReviewHub(page, 'attach');
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
  await expect(reviewIntake).toContainText('QVqcont-7', { timeout: 15_000 });
  await openArchiveReviewHub(page, 'review');
  await expect(reviewIntake).toBeVisible();
  await expect(reviewIntake).toContainText('QVqcont-7 shard');
  await expect(reviewIntake).toContainText('archive-approval signature');
  const reviewInspector = page.getByTestId('review-archive-inspector');
  await expect(reviewInspector).toBeVisible();
  await expect(reviewInspector).toContainText('Lifecycle timeline');
  await expect(reviewInspector).toContainText('Evidence present in bundle (counts)');
  await expect(page.getByTestId('pro-workflow-active')).toContainText('Review');
  await expect(page.getByTestId('pro-workflow-evidence')).toContainText('review files');
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
  const preflight = page.getByTestId('restore-preflight');
  await expect(preflight).toContainText('Restore decision');
  await expect(
    preflight.evaluate((el) => {
      const intake = document.getElementById('restoreArtifactIntake');
      if (!el || !intake) return false;
      return (el.compareDocumentPosition(intake) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    })
  ).resolves.toBe(true);
  await expect(preflight).toContainText('Plaintext release: allowed by integrity-only policy');
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by integrity-only policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toHaveClass(/warn/);
  await expect(restoreResult).toContainText('Plaintext released under integrity-only policy');
  await expect(restoreResult).toContainText('Allowed by integrity-only policy');
  await expect(restoreResult).toContainText('Archive policy satisfied');
  await expect(restoreResult).toContainText('No cryptographically verified archive-approval signature over archive-state');
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

test('strong-PQ restore blocks the CTA without detached archive approval', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicyFailFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeDisabled();
  await expect(restoreButton).toHaveText('Add Archive-Approval Evidence');

  const preflight = page.getByTestId('restore-preflight');
  await expect(preflight).toContainText('Restore decision');
  await expect(
    preflight.evaluate((el) => {
      const intake = document.getElementById('restoreArtifactIntake');
      if (!el || !intake) return false;
      return (el.compareDocumentPosition(intake) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    })
  ).resolves.toBe(true);
  await expect(preflight).toContainText('Plaintext release: blocked');
  await expect(preflight).toContainText('before reconstruction');
  await expect(page.getByTestId('restore-inline-error')).toBeHidden();
  await expect(page.getByTestId('restore-result')).toBeHidden();
});

test('lite restore policy blocker disables the CTA before evaluation', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('script[type="module"][src*="assets/main.js"]')).toHaveAttribute('integrity', /.+/);
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicyFailFiles);

  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeDisabled();
  await expect(restoreButton).toHaveText('Add Archive-Approval Evidence');
  const litePreflight = page.getByTestId('lite-restore-preflight');
  await expect(litePreflight).toContainText('Restore decision');
  await expect(
    litePreflight.evaluate((el) => {
      const intake = document.getElementById('liteRestoreArtifactIntake');
      if (!el || !intake) return false;
      return (el.compareDocumentPosition(intake) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    })
  ).resolves.toBe(true);
  await expect(litePreflight).toContainText('Required archive-approval signature evidence');
  await expect(page.getByTestId('lite-restore-inline-error')).toBeHidden();
});

test('delayed Lite Restore blocks competing workflows and pagehide prevents late plaintext output', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.locator('#liteTabRestore').click();
  await page.locator('#liteShardsInput').setInputFiles(fixtures.strongPolicySatisfiedFiles);
  const restoreButton = page.locator('#liteRestoreBtn');
  await expect(restoreButton).toBeEnabled({ timeout: 30_000 });

  await page.evaluate(() => {
    const originalArrayBuffer = Blob.prototype.arrayBuffer;
    let releaseRead;
    const readGate = new Promise((resolve) => { releaseRead = resolve; });
    window.__qvDelayedRestoreReadStarted = false;
    window.__qvReleaseDelayedRestoreRead = () => releaseRead();
    Blob.prototype.arrayBuffer = async function delayedRestoreArrayBuffer() {
      window.__qvDelayedRestoreReadStarted = true;
      await readGate;
      return originalArrayBuffer.call(this);
    };
  });

  const downloads = [];
  const onDownload = (download) => downloads.push(download);
  page.on('download', onDownload);
  try {
    await restoreButton.click();
    await expect.poll(
      () => page.evaluate(() => window.__qvDelayedRestoreReadStarted),
    ).toBe(true);

    const protectTab = page.locator('#liteTabProtect');
    await expect(protectTab).toBeDisabled();
    await expect(protectTab).toHaveAttribute('aria-disabled', 'true');
    await expect(page.locator('#liteCreateShardsBtn')).toBeDisabled();
    await expect(page.locator('#liteFilesInput')).toBeDisabled();

    await page.getByTestId('mode-toggle-control').click();
    await expect(page.getByTestId('mode-toggle')).not.toBeChecked();
    await expect(lastToast(page)).toContainText('active Lite Restore');

    // Disabled navigation and CTAs are presentation boundaries. Force both
    // handlers and prove the active restore token still blocks a new create.
    await protectTab.evaluate((tab) => {
      tab.disabled = false;
      tab.setAttribute('aria-disabled', 'false');
      tab.click();
    });
    await page.locator('#liteCreateShardsBtn').evaluate((button) => {
      button.disabled = false;
      button.click();
    });
    await expect(lastToast(page)).toContainText('active Lite Restore');
    await expect(page.getByTestId('lite-export-session')).toBeHidden();
    expect(downloads).toHaveLength(0);

    await dispatchPersistedPageTransition(page, 'pagehide');
    await page.getByTestId('mode-toggle-control').click();
    await expect(page.getByTestId('mode-toggle')).not.toBeChecked();
    await expect(lastToast(page)).toContainText('cancelled Lite Restore work to settle');
    expect(downloads).toHaveLength(0);

    await page.evaluate(() => window.__qvReleaseDelayedRestoreRead());
    await expect(page.getByTestId('operations-log')).toContainText(
      'Lite Restore was cancelled; no new plaintext output was released after cancellation',
    );
    await expect(page.locator('#liteTabProtect')).toBeEnabled();
    await page.waitForTimeout(250);
    expect(downloads).toHaveLength(0);
    await expect(page.locator('#liteRestoreResult')).toBeHidden();
    await expect(page.getByTestId('lite-export-session')).toBeHidden();
  } finally {
    page.off('download', onDownload);
  }
});

test('strong-PQ restore succeeds with valid qsig and matching pqpk pin', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();

  const preflight = page.getByTestId('restore-preflight');
  await expect(preflight).toContainText('Restore decision');
  await expect(
    preflight.evaluate((el) => {
      const intake = document.getElementById('restoreArtifactIntake');
      if (!el || !intake) return false;
      return (el.compareDocumentPosition(intake) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    })
  ).resolves.toBe(true);
  await expect(preflight).toContainText('Plaintext release: blocked');
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by strong PQ archive-approval policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Plaintext released under strong PQ archive-approval policy');
  await expect(restoreResult).toContainText('Strong PQ archive-approval signature verified');
  await expect(restoreResult).toContainText('Archive-approval signer pin');
  await expect(restoreResult).toContainText('Signer pinned by external user input');
  await expect(restoreResult).toContainText('User-entered signer pin matched');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('pro restore release clears evaluated outputs and requires re-evaluation before another release', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedFiles);

  const restoreButton = page.getByTestId('restore-button');
  await expect(restoreButton).toBeEnabled();
  await restoreButton.click();

  const releaseButton = page.getByTestId('release-button');
  await expect(releaseButton).toBeVisible();
  await expect(releaseButton).toBeEnabled();

  const downloads = [];
  page.on('download', (download) => {
    downloads.push(download);
  });

  await Promise.all([
    page.waitForEvent('download'),
    releaseButton.click(),
  ]);
  await expect.poll(() => downloads.length, { timeout: 10_000 }).toBe(2);

  await expect(releaseButton).toBeHidden();
  await expect(releaseButton).toBeDisabled();
  await expect(page.getByTestId('restore-result')).toContainText('Plaintext released under strong PQ archive-approval policy');

  await restoreButton.click();
  await expect(releaseButton).toBeVisible();
  await expect(releaseButton).toBeEnabled();
  await expect(page.getByTestId('restore-result')).toContainText('Plaintext release allowed under strong PQ archive-approval policy');
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
  await expect(restoreResult).toContainText('Signer pinned by external user input');
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

test('unambiguous restore hides successor selection and states lifecycle path on decision card', async ({ page }) => {
  await openProTab(page, 'tab-restore');
  await page.getByTestId('restore-input').setInputFiles(fixtures.strongPolicySatisfiedFiles);

  await expect(page.getByTestId('restore-button')).toBeEnabled();
  await expect(page.getByTestId('restore-selection')).toBeHidden();
  const preflight = page.getByTestId('restore-preflight');
  await expect(preflight).toContainText('Lifecycle path');
  await expect(preflight).toContainText('Selected automatically, no ambiguity');
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
  await expect(page.getByTestId('operations-log')).toContainText('ignored for archive policy');
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

test('archive-approval attach imports qsig plus pqpk and restore requires the pqpk again as an external pin', async ({ page }) => {
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
  await restoreButton.click();
  await expect(page.getByTestId('restore-inline-error')).toBeVisible();
  await expect(page.getByTestId('restore-inline-error')).toContainText('verified archive-approval signatures lack an external signer pin');
  await expect(page.getByTestId('operations-log')).toContainText('lifecycle-bundle key material is mutable and is not an external trust anchor');
  await expect(page.getByTestId('restore-result')).toBeHidden();

  await page.getByTestId('restore-input').setInputFiles([
    ...fixtures.archiveApprovalAttachRestoreShardFiles,
    updatedBundle,
    fixtures.archiveApprovalAttachRestorePqpkFile,
  ]);

  await expect(restoreButton).toBeEnabled();
  await evaluateAndReleaseRestore(page, 'Plaintext release: allowed by strong PQ archive-approval policy');

  const restoreResult = page.getByTestId('restore-result');
  await expect(restoreResult).toBeVisible();
  await expect(restoreResult).toContainText('Plaintext released under strong PQ archive-approval policy');
  await expect(restoreResult).toContainText('Strong PQ archive-approval signature verified');
  await expect(restoreResult).toContainText('Archive-approval signer pin');
  await expect(restoreResult).toContainText('Signer pinned by external user input');
  await expect(restoreResult).toContainText('Signature verified with bundled key (not a trust anchor)');
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
  await expect(page.getByTestId('attach-status-text')).toContainText('Partial rewrite: acknowledgement required');
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
  await expect(restoreResult).toContainText('No cryptographically verified archive-approval signature over archive-state');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('maintenance attach rejects a qsig signed over archive-state bytes instead of the transition record', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('maintenance');
  await page.getByTestId('attach-input').setInputFiles(fixtures.maintenanceWrongTargetFiles);
  await openArchiveReviewHub(page, 'attach');

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

test('source-evidence apply one file fills every digest row using each row algorithm', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('source-evidence');

  await page.getByTestId('source-evidence-add-digest').click();
  await page.locator('#sourceEvidenceDigestRows .source-evidence-digest-alg').nth(1).selectOption('SHA-256');

  const expectedSha3_512 =
    'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0';

  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.getByTestId('source-evidence-apply-file-all').click(),
  ]);
  await fileChooser.setFiles({
    name: 'probe.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('abc', 'utf8'),
  });

  await expect(page.locator('#sourceEvidenceDigestRows .source-evidence-digest-value').nth(0)).toHaveValue(expectedSha3_512);
  await expect(page.locator('#sourceEvidenceDigestRows .source-evidence-digest-value').nth(1)).toHaveValue(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );

  await expect(page.getByTestId('toast').last()).toContainText('Source evidence:');
});

test('attach target-binding preview reflects channel, archive binding, and shard rewrite mode', async ({ page }) => {
  await openProTab(page, 'tab-attach');

  await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalAttachBaseFiles);
  await openArchiveReviewHub(page, 'attach');
  let preview = page.getByTestId('attach-target-binding-preview');
  await expect(preview).toBeVisible();
  await expect(preview).toContainText('Archive approval');
  await expect(preview).toContainText('state:');
  await expect(preview).toContainText('bundle-only');
  await expect(preview).toContainText('Archive policy binding: verified signatures on this channel can satisfy archive restore policy');

  await page.getByTestId('attach-channel').selectOption('maintenance');
  await page.getByTestId('attach-input').setInputFiles(fixtures.maintenanceWrongTargetFiles);
  await openArchiveReviewHub(page, 'attach');
  preview = page.getByTestId('attach-target-binding-preview');
  await expect(preview).toContainText('Maintenance');
  await expect(preview).toContainText('transition:sha3-512:');
  await expect(preview).toContainText('does not satisfy archive restore policy by itself');

  await page.getByTestId('attach-channel').selectOption('source-evidence');
  await page.getByTestId('attach-input').setInputFiles(fixtures.sourceEvidenceWrongTargetFiles);
  await openArchiveReviewHub(page, 'attach');
  preview = page.getByTestId('attach-target-binding-preview');
  await expect(preview).toContainText('Source evidence');
  await expect(preview).toContainText('source-evidence:sha3-512:');

  await page.getByTestId('attach-channel').selectOption('archive-approval');
  await page.getByTestId('attach-input').setInputFiles(fixtures.archiveApprovalPartialShardAttachFiles);
  await openArchiveReviewHub(page, 'attach');
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
  await expect(restoreResult).toContainText('No cryptographically verified archive-approval signature over archive-state');
  await expect(restoreResult).toContainText('Archive policy satisfied');
});

test('source-evidence attach rejects a qsig signed over archive-state bytes instead of source-evidence JSON', async ({ page }) => {
  await openProTab(page, 'tab-attach');
  await page.getByTestId('attach-channel').selectOption('source-evidence');
  await page.getByTestId('attach-input').setInputFiles(fixtures.sourceEvidenceWrongTargetFiles);
  await openArchiveReviewHub(page, 'attach');

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
