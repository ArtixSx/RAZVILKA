// Run from the client on the tested LAN. Successful page rendering measures
// client access; correlate it with router evidence to attribute it to a route.
import {createRequire} from 'node:module';
import {performance} from 'node:perf_hooks';

const {chromium} = createRequire(import.meta.url)('playwright');
const sites = [
  {
    name: 'Telegram Web',
    url: 'https://web.telegram.org/a/',
    loginControl(page) {
      return page.getByRole('button', {name: /log in by phone number|log in by qr code/i})
        .or(page.getByRole('textbox', {name: /phone number/i})).first();
    }
  },
  {
    name: 'Discord',
    url: 'https://discord.com/login',
    loginControl(page) {
      return page.locator('form:has(input[type="password"]:visible)')
        .getByRole('button', {name: /^log in$/i});
    }
  }
];

async function checkSite(browser, site) {
  const context = await browser.newContext({locale: 'en-US', serviceWorkers: 'block'});
  const started = performance.now();
  const result = {site: site.name, checked_at: new Date().toISOString(), status: null, login_visible: false};
  let stage = 'navigation';
  try {
    const page = await context.newPage();
    const response = await page.goto(site.url, {waitUntil: 'commit', timeout: 30000});
    result.status = response?.status() ?? null;
    if (!response?.ok()) throw new Error('document-http-error');
    stage = 'login-interface';
    await site.loginControl(page).waitFor({state: 'visible', timeout: 30000});
    if (new URL(page.url()).origin !== new URL(site.url).origin) throw new Error('unexpected-origin');
    result.login_visible = true;
  } catch (error) {
    result.failure_stage = stage;
    result.reason = error.name === 'TimeoutError' ? 'timeout' : error.message.split('\n')[0];
  } finally {
    result.elapsed_ms = Math.round(performance.now() - started);
    await context.close();
  }
  return result;
}

const browser = await chromium.launch({
  executablePath: process.env.RAZVILKA_UI_CHROME || undefined,
  args: ['--no-proxy-server']
});
try {
  const results = await Promise.all(sites.map(site => checkSite(browser, site)));
  console.log(JSON.stringify({browser: browser.version(), results}, null, 2));
  if (!results.every(result => result.login_visible)) process.exitCode = 1;
} finally {
  await browser.close();
}
