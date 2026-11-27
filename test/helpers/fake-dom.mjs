// A minimal stand-in for the browser DOM, enough to run public/app.js and inspect what it rendered.
//
//   baseUrl     where relative requests go (the local server, or a static site root ending in "/")
//   staticMode  mark the page the way the demo build does (<html data-static="1">)
//   onFetch     called with (url, options) for every request the page makes

export function installFakeDom({ baseUrl, staticMode = false, onFetch = null }) {
  const els = new Map();
  const changeHandlers = [];
  const makeEl = (id) => {
    const listeners = {};
    const classes = new Set();
    return {
      id, innerHTML: '', textContent: '', value: '', title: '', disabled: false, dataset: {}, listeners,
      classList: {
        add: (c) => classes.add(c),
        remove: (c) => classes.delete(c),
        contains: (c) => classes.has(c),
        toggle(c, on) { const want = on === undefined ? !classes.has(c) : Boolean(on); if (want) classes.add(c); else classes.delete(c); return want; }
      },
      addEventListener(type, fn) { (listeners[type] ||= []).push(fn); },
      querySelectorAll: () => [],
      querySelector: () => makeEl('child'),
      closest: () => makeEl('ancestor')
    };
  };
  const pills = [24, 48, 168].map((h) => Object.assign(makeEl(`pill-${h}`), { dataset: { hours: String(h) } }));

  globalThis.document = {
    documentElement: { dataset: staticMode ? { static: '1' } : {} },
    getElementById(id) { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); },
    querySelectorAll: (sel) => (sel.includes('data-hours') ? pills : [])
  };
  globalThis.window = { location: {} };
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => { store.set(k, String(v)); }
  };

  const realFetch = globalThis.fetch;
  globalThis.fetch = (url, opts) => {
    const u = String(url);
    const absolute = /^https?:\/\//.test(u) ? u : new URL(u.startsWith('/') ? u : u, baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`).href;
    if (onFetch) onFetch(absolute, opts);
    return realFetch(absolute, opts);
  };

  return {
    el: (id) => globalThis.document.getElementById(id),
    pills,
    html: (id) => globalThis.document.getElementById(id).innerHTML,
    allHtml: () => [...els.values()].map((e) => e.innerHTML).join('\n'),
    // Press a button the page rendered inside a list. The fake DOM has no real elements, so the list hands back one
    // stand-in matching `match` on its next render and the test then fires the click handler the page attached to it.
    async pressInList(listId, match, dataset) {
      const list = globalThis.document.getElementById(listId);
      const handlers = [];
      list.querySelectorAll = (sel) => (sel.includes(match) ? [{ dataset, addEventListener: (_t, fn) => handlers.push(fn) }] : []);
      const pill = pills.find((p) => p.classList.contains('active')) || pills[2];
      await pill.listeners.click[0]();
      await new Promise((r) => setTimeout(r, 150));
      list.querySelectorAll = () => [];
      await handlers.at(-1)();
      await new Promise((r) => setTimeout(r, 50));
    },
    // The page wires checkbox "change" handlers onto elements found by querySelectorAll, which this fake does not
    // model. Tests reach the same code path by letting the list element hand back one checkbox on its next render.
    async changeCheckbox(box, checked) {
      const list = globalThis.document.getElementById('lockdownList');
      list.querySelectorAll = () => [{ ...box, addEventListener: (_t, fn) => changeHandlers.push(fn) }];
      const pill = pills.find((p) => p.classList.contains('active')) || pills[2];
      await pill.listeners.click[0]();
      await new Promise((r) => setTimeout(r, 150));
      list.querySelectorAll = () => [];
      await changeHandlers.at(-1)({ target: { checked } });
    }
  };
}
