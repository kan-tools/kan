#!/usr/bin/env node
// Real Chromium + synthetic Rust proof service, without mocked HTTP responses.
// Usage: NODE_PATH=<pinned Playwright install>/node_modules node this.cjs <test binary> <new output dir>
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {setTimeout: delay} = require('node:timers/promises');
const {chromium} = require('playwright');

async function main() {
  const binary = fs.realpathSync(process.argv[2]);
  const output = path.resolve(process.argv[3]);
  fs.mkdirSync(output, {mode: 0o700}); // Never replace a prior run.
  const infoPath = path.join(output, 'fixture.json');
  const log = fs.openSync(path.join(output, 'fixture.log'), 'wx', 0o600);
  const child = spawn(binary, ['proof_library_browser_fixture', '--ignored', '--nocapture'], {
    env: {...process.env, KAN_PROOF_LIBRARY_FIXTURE_INFO: infoPath},
    stdio: ['ignore', log, log],
  });
  fs.closeSync(log);
  let childError, browser, page;
  child.on('error', error => { childError = error; });
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({code, signal})));
  const errors = [], external = [], checked = [];
  try {
    const deadline = Date.now() + 120000;
    while (!fs.existsSync(infoPath)) {
      if (childError) throw childError;
      assert.equal(child.exitCode, null, 'Rust fixture exited before readiness; see fixture.log');
      assert.ok(Date.now() < deadline, 'Rust fixture readiness deadline');
      await delay(100);
    }
    const fixture = JSON.parse(fs.readFileSync(infoPath, 'utf8'));
    const origin = new URL(fixture.url).origin;
    browser = await chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 1440, height: 1000}, colorScheme: 'dark', acceptDownloads: true});
    // Record and refuse unintended external resources, including captured markup.
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.origin !== origin) { external.push(url.href); return route.abort(); }
      return route.continue();
    });
    page = await context.newPage();
    page.setDefaultTimeout(30000);
    page.on('pageerror', e => errors.push(e.message));
    page.on('dialog', async dialog => { errors.push(`Unexpected dialog: ${dialog.message()}`); await dialog.dismiss(); });
    const documentResponse = await page.goto(fixture.url);
    assert.equal(documentResponse.headers()['referrer-policy'], 'same-origin');
    assert.equal(await page.locator('#theme').inputValue(), 'system');
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.emulateMedia({colorScheme: 'light'});
    await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
    await page.locator('#theme').selectOption('dark');
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.reload();
    assert.equal(await page.locator('#theme').inputValue(), 'dark');
    await page.locator('#theme').selectOption('system');
    checked.push('platform default, live platform change, explicit theme, persisted preference');

    await page.locator('#token').fill(fixture.token);
    await page.locator('#connect button').click();
    await page.locator('#rows .occurrence').first().waitFor();
    assert.equal(await page.locator('#token').inputValue(), '');
    assert.equal(await page.locator('#scope option').count(), 2);
    const firstRange = await page.locator('#page-position').textContent();
    const occurrence = page.locator('#rows .occurrence').first();
    await occurrence.focus();
    await page.keyboard.press('Enter');
    await page.locator('#inspection').waitFor();
    await page.waitForFunction(() => document.activeElement.id === 'source-tab');
    assert.equal(await page.locator('#source').textContent(), fixture.expected_hex);
    assert.equal(await page.locator('#source script').count(), 0);
    const downloadPromise = Promise.all([
      page.waitForEvent('download'),
      page.waitForResponse(response => response.url() === `${origin}/api/library/download`).then(async response => {
        assert.equal(await response.request().headerValue('origin'), origin, 'native POST preserves same-origin identity');
        assert.equal(response.status(), 200, 'native download HTTP response');
        assert.match(response.headers()['content-disposition'] || '', /^attachment;/);
      }),
    ]);
    await page.locator('#download').click();
    const [download] = await downloadPromise;
    assert.equal(await download.failure(), null);
    const downloadPath = path.join(output, 'source.bin');
    await download.saveAs(downloadPath);
    assert.equal(fs.readFileSync(downloadPath).toString('hex'), fixture.expected_hex);
    checked.push('real proof API login, two archives, keyboard source inspection, byte-exact native download');

    for (const width of [1440, 768, 390]) {
      await page.setViewportSize({width, height: 1000});
      for (const theme of ['light', 'dark']) {
        await page.locator('#theme').selectOption(theme);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `body overflow at ${width}/${theme}`);
        await page.screenshot({path: path.join(output, `library-${width}-${theme}.png`), fullPage: true});
      }
    }
    checked.push('desktop/tablet/390px source view in light and dark, no document overflow');
    await page.locator('#close-inspector').click();
    assert.equal(await occurrence.evaluate(e => e === document.activeElement), true);
    await page.locator('#next').click();
    await page.waitForFunction(() => document.querySelector('#rows .availability.missing'));
    await page.locator('#rows .occurrence').filter({has: page.locator('.availability.missing')}).click();
    await page.waitForFunction(() => document.querySelector('#source').textContent.includes('source is missing'));
    assert.equal(await page.locator('#download').isDisabled(), true);
    await page.locator('#rows .occurrence').filter({has: page.locator('.availability.corrupt')}).click();
    await page.waitForFunction(() => document.querySelector('#source').textContent.includes('source is corrupt'));
    assert.equal(await page.locator('#download').isDisabled(), true);
    checked.push('real pagination, explicit missing/corrupt source, unavailable download disabled');
    await page.locator('#previous').click();
    await page.waitForFunction(range => document.querySelector('#page-position').textContent === range, firstRange);
    await page.locator('#rows .occurrence').first().click();
    await page.locator('#annotate-source').click();
    const note = 'A browser-authored note <script>throw new Error("untrusted")</script>';
    await page.locator('#annotation-subject').fill('telos/browser-qualification');
    await page.locator('#annotation-text').fill(note);
    await page.locator('#annotation-tags').fill('browser, decision');
    await page.locator('#annotation-form button[type="submit"]').click();
    await page.waitForFunction(() => !document.querySelector('#save-annotation').disabled);
    assert.ok((await page.locator('#annotation-preview').textContent()).includes('Signed by'));
    await page.locator('#save-annotation').click();
    await page.waitForFunction(text => document.querySelector('#annotation-list').textContent.includes(text), note);
    assert.equal(await page.locator('#annotation-list script').count(), 0);
    await page.locator('#search-text').fill('Hello proof archive');
    await page.locator('#search-form button[type="submit"]').click();
    await page.waitForFunction(() => !document.querySelector('#save-view').disabled && document.querySelector('#search-results').textContent.includes('Hello proof archive'), null, {timeout: 120000});
    await page.locator('#view-name').fill('Browser pinned search');
    await page.locator('#save-view').click();
    await page.waitForFunction(() => document.querySelector('#views-status').textContent.includes('Saved “Browser pinned search”'));
    await page.locator('#load-views').click();
    await page.waitForFunction(() => document.querySelector('#saved-views').textContent.includes('Browser pinned search'));
    await page.locator('#saved-views').getByRole('button', {name: 'Run pinned view', exact: true}).click();
    await page.waitForFunction(() => document.querySelector('#search-results').textContent.includes('Hello proof archive'), null, {timeout: 120000});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'annotation/search overflow at 390px');
    await page.screenshot({path: path.join(output, 'library-authored-search-390.png'), fullPage: true});
    checked.push('real signed annotation preview/save with literal untrusted text; cross-archive search and reopened pinned view');
    await page.locator('#lock').click();
    assert.equal(await page.locator('#library').isVisible(), false);
    assert.equal(await page.locator('#source').textContent(), '');
    assert.equal(await page.locator('#rows .occurrence').count(), 0);
    assert.equal(await page.locator('#annotation-list').textContent(), '');
    assert.equal(await page.locator('#search-results').textContent(), '');
    assert.equal(await page.locator('#token').evaluate(e => e === document.activeElement), true);
    assert.deepEqual(await page.evaluate(() => Object.keys(localStorage)), ['kan.theme']);
    assert.deepEqual(await page.evaluate(() => Object.keys(sessionStorage)), []);
    assert.ok(!page.url().includes(fixture.token));
    assert.deepEqual(external, []);
    assert.deepEqual(errors, []);
    checked.push('lock clears private views and focuses login; no credentials in URL/storage, no external loads or script errors');
    fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify({checked, errors, external}, null, 2));
    console.log(checked.join('\n'));
  } catch (error) {
    if (page) await page.screenshot({path: path.join(output, 'failure.png'), fullPage: true}).catch(() => {});
    fs.writeFileSync(path.join(output, 'failure.json'), JSON.stringify({message: error.message, checked, errors, external}, null, 2));
    throw error;
  } finally {
    if (browser) await browser.close();
    fs.writeFileSync(path.join(output, 'fixture.stop'), '');
    const result = await Promise.race([exited, delay(10000).then(() => null)]);
    if (!result) { child.kill('SIGKILL'); await exited; }
    else assert.equal(result.code, 0, `Rust fixture cleanup failed (${result.signal}); see fixture.log`);
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
