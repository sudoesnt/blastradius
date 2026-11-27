// A minimal stand-in for the browser DOM, enough to run public/app.js and inspect what it rendered.

export function installFakeDom({ baseUrl }) {
  const els = new Map();
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
    getElementById(id) { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); },
    querySelectorAll: (sel) => (sel.includes('data-hours') ? pills : [])
  };
  globalThis.window = { location: {} };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (url, opts) => realFetch(String(url).startsWith('/') ? baseUrl + url : url, opts);

  return {
    el: (id) => globalThis.document.getElementById(id),
    pills,
    html: (id) => globalThis.document.getElementById(id).innerHTML,
    allHtml: () => [...els.values()].map((e) => e.innerHTML).join('\n')
  };
}
