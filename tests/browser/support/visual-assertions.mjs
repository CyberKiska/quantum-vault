import { expect } from '@playwright/test';

/** Tab panels use fadeIn ~0.3s; toasts ~0.22s — wait so screenshots capture settled layout. */
export async function waitForUiAnimations(page, ms = 450) {
  await page.waitForTimeout(ms);
}

export async function expectNoHorizontalOverflow(page) {
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

/**
 * Fails when visible “critical” panels horizontally clip text (scrollWidth > clientWidth).
 */
export async function expectCriticalPanelsNotClipped(page) {
  const clipped = await page.evaluate(() => {
    const selectors = [
      '[data-testid="restore-result"]',
      '[data-testid="restore-preflight"]',
      '[data-testid="restore-inline-error"]',
      '[data-testid="lite-restore-inline-error"]',
      '[data-testid="lite-restore-preflight"]',
      '[data-testid="lite-policy-consequence"]',
      '[data-testid="pro-policy-consequence"]',
      '[data-testid="split-readiness"]',
      '[data-testid="attach-partial-ack-panel"]',
      '[data-testid="attach-status"]',
      '[data-testid="restore-archive-inspector"]',
    ];
    const bad = [];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (!el || !(el instanceof HTMLElement)) continue;
      const style = window.getComputedStyle(el);
      if (style.display === 'none' || style.visibility === 'hidden') continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 8 || rect.height < 8) continue;
      const sw = el.scrollWidth;
      const cw = el.clientWidth;
      if (sw > cw + 2) {
        bad.push({ sel, scrollWidth: sw, clientWidth: cw });
      }
    }
    return bad;
  });
  expect(clipped, JSON.stringify(clipped, null, 2)).toEqual([]);
}

/** After focus-visible styles apply (focus ring not color-only). */
export async function expectFocusRingVisible(page, locator) {
  await locator.focus();
  await waitForUiAnimations(page, 80);
  const outline = await locator.evaluate((element) => {
    const style = window.getComputedStyle(element);
    return {
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth),
      boxShadow: style.boxShadow,
    };
  });
  const hasOutline = outline.outlineStyle === 'solid' && outline.outlineWidth >= 1;
  const hasShadow = outline.boxShadow && outline.boxShadow !== 'none';
  expect(hasOutline || hasShadow, JSON.stringify(outline)).toBe(true);
}
