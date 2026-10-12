// Sign-in for the online copy of Ahmad's Academy.
//
// There is no server here, so the lessons are published only as an encrypted file (bundle.json).
// The key is worked out from the username and password in the browser; with the wrong ones the
// file cannot be opened. Nothing in this file or in the bundle contains the password itself.
(() => {
  'use strict';
  const SESSION_KEY = 'aa-session', SESSION_MS = 10 * 60 * 1000;
  const $ = id => document.getElementById(id);
  const form = $('form'), user = $('username'), pass = $('password'), alertBox = $('alert'), submit = $('submit'), toggle = $('toggle');
  const enc = new TextEncoder();
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const toB64 = bytes => btoa(String.fromCharCode.apply(null, bytes));
  let bundlePromise = null;
  const getBundle = () => bundlePromise || (bundlePromise = fetch('bundle.json', { cache: 'no-cache' }).then(r => { if (!r.ok) throw new Error('bundle'); return r.json(); }));

  // 64 key bytes from the sign-in details: the first 32 decrypt, the last 32 check the file is untouched.
  async function deriveKeys(username, password, b) {
    const base = await crypto.subtle.importKey('raw', enc.encode(username.trim().toLowerCase() + '\n' + password), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(b.salt), iterations: b.iter }, base, 512));
  }
  // Returns the app's files, or null when the keys are wrong.
  async function open(keys, b) {
    const iv = b64(b.iv), data = b64(b.data), signed = new Uint8Array(iv.length + data.length);
    signed.set(iv); signed.set(data, iv.length);
    const macKey = await crypto.subtle.importKey('raw', keys.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    if (!await crypto.subtle.verify('HMAC', macKey, b64(b.mac), signed)) return null;
    const aesKey = await crypto.subtle.importKey('raw', keys.slice(0, 32), { name: 'AES-CBC' }, false, ['decrypt']);
    return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, data)));
  }

  function signOut() {
    try { localStorage.removeItem(SESSION_KEY); } catch (e) { /* storage unavailable */ }
    location.reload();
  }
  function boot(files, exp) {
    $('signin').remove();
    $('login-css').remove();
    document.head.appendChild(document.createElement('style')).textContent = files.css;
    const app = document.body.appendChild(document.createElement('div'));
    app.id = 'app';
    window.ACADEMY = { exp, signOut };
    [files.content, files.app].forEach(code => { document.body.appendChild(document.createElement('script')).textContent = code; });
  }

  function fail(message, field) {
    alertBox.textContent = message;
    alertBox.hidden = false;
    form.classList.remove('shake');
    void form.offsetWidth;   // restart the animation
    form.classList.add('shake');
    (field || pass).focus();
  }

  toggle.addEventListener('click', () => {
    const show = pass.type === 'password';
    pass.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Hide' : 'Show';
    toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    toggle.setAttribute('aria-pressed', String(show));
  });

  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (!user.value.trim()) return fail('Enter your username.', user);
    if (!pass.value) return fail('Enter your password.', pass);
    alertBox.hidden = true;
    submit.disabled = true;
    submit.textContent = 'SIGNING IN…';
    try {
      const b = await getBundle(), keys = await deriveKeys(user.value, pass.value, b), files = await open(keys, b);
      if (files) {
        const exp = Date.now() + SESSION_MS;
        try { localStorage.setItem(SESSION_KEY, JSON.stringify({ exp, keys: toB64(keys), v: b.mac })); } catch (err) { /* storage unavailable */ }
        return boot(files, exp);
      }
      pass.value = '';
      fail('Incorrect username or password.');
    } catch (err) {
      fail(window.crypto && crypto.subtle ? 'Could not load the lessons. Check your connection and try again.' : 'This browser is too old to open the lessons. Please update it.');
    }
    submit.disabled = false;
    submit.textContent = 'SIGN IN';
  });

  // Still inside the 10 minutes from the last sign-in? Open straight away; otherwise show the form.
  (async () => {
    try {
      const s = JSON.parse(localStorage.getItem(SESSION_KEY) || 'null');
      if (s && s.exp > Date.now()) {
        const b = await getBundle(), files = s.v === b.mac ? await open(b64(s.keys), b) : null;
        if (files) return boot(files, s.exp);
      }
      localStorage.removeItem(SESSION_KEY);
    } catch (e) { /* fall through to the form */ }
    $('signin').hidden = false;
    user.focus();
    getBundle().catch(() => {});   // start the download while the details are typed
  })();
})();
