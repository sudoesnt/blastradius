// Lightweight zero-dependency RSS 2.0 / Atom / RDF XML parser

const ENTITY_MAP = {
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&apos;': "'",
  '&#39;': "'",
  '&nbsp;': ' ',
  '&ndash;': '–',
  '&mdash;': '—',
  '&rsquo;': "'",
  '&lsquo;': "'",
  '&rdquo;': '"',
  '&ldquo;': '"',
  '&hellip;': '...'
};

export function decodeEntities(str = '') {
  if (!str) return '';
  return str
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => {
      try { return String.fromCodePoint(parseInt(hex, 16)); } catch { return ''; }
    })
    .replace(/&#(\d+);/g, (_, dec) => {
      try { return String.fromCodePoint(parseInt(dec, 10)); } catch { return ''; }
    })
    .replace(/&[a-zA-Z0-9#]+;/g, (m) => ENTITY_MAP[m] ?? m);
}

export function stripHtml(html = '') {
  if (!html) return '';
  return decodeEntities(html)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function getTagContent(block, tagNames) {
  for (const tag of tagNames) {
    const escaped = tag.replace(':', '\\:');
    const re = new RegExp(`<${escaped}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${escaped}>`, 'i');
    const match = block.match(re);
    if (match && match[1] && match[1].trim()) {
      return match[1].trim();
    }
  }
  return '';
}

function getAtomLink(block) {
  // Prefer rel="alternate" or no rel
  const links = [...block.matchAll(/<link\b([^>]*?)\/?>/gi)];
  let fallback = '';
  for (const m of links) {
    const attrs = m[1] || '';
    const hrefMatch = attrs.match(/href=["']([^"']+)["']/i);
    if (!hrefMatch) continue;
    const href = decodeEntities(hrefMatch[1].trim());
    if (/rel=["']alternate["']/i.test(attrs)) return href;
    if (!/rel=["'](self|enclosure|replies|hub)["']/i.test(attrs) && !fallback) {
      fallback = href;
    }
  }
  return fallback || decodeEntities(getTagContent(block, ['link', 'guid']));
}

function getCategories(block) {
  const cats = [];
  for (const m of block.matchAll(/<category(?:\s+([^>]*))?>(?:([\s\S]*?)<\/category>)?/gi)) {
    const attrs = m[1] || '';
    const inner = m[2] || '';
    const term = attrs.match(/term=["']([^"']+)["']/i)?.[1];
    const val = stripHtml(term || inner);
    if (val) cats.push(val);
  }
  return [...new Set(cats)];
}

export function parseDateSafe(raw) {
  if (!raw) return null;
  const cleaned = decodeEntities(String(raw)).trim();
  if (!cleaned) return null;
  const ms = Date.parse(cleaned);
  if (!Number.isNaN(ms)) return new Date(ms);
  // Fallback for YYYY-MM-DD
  const ymd = cleaned.match(/(\d{4}-\d{2}-\d{2})/);
  if (ymd) {
    const d = new Date(ymd[1] + 'T12:00:00Z');
    if (!Number.isNaN(d.getTime())) return d;
  }
  return null;
}

export function parseFeedXml(xmlText) {
  const items = [];
  const isAtom = /<feed[\s>]/i.test(xmlText) && !/<rss[\s>]/i.test(xmlText);
  const blockRe = isAtom
    ? /<entry(?:\s[^>]*)?>([\s\S]*?)<\/entry>/gi
    : /<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi;

  for (const match of xmlText.matchAll(blockRe)) {
    const block = match[1];
    const rawTitle = getTagContent(block, ['title']);
    const title = stripHtml(rawTitle);
    const link = isAtom
      ? getAtomLink(block)
      : decodeEntities(getTagContent(block, ['link', 'guid'])).replace(/^<!\[CDATA\[|\]\]>$/g, '').trim();
    const rawDate = getTagContent(block, [
      'pubDate',
      'published',
      'updated',
      'dc:date',
      'a10:updated'
    ]);
    const publishedAt = parseDateSafe(rawDate);
    const rawDesc = getTagContent(block, ['description', 'summary', 'content:encoded', 'content']);
    const rawFull = getTagContent(block, ['content:encoded', 'content', 'description', 'summary']);
    const summary = stripHtml(rawDesc).slice(0, 700);
    const fullText = stripHtml(rawFull).slice(0, 2200);
    const categories = getCategories(block);

    if (!title && !summary) continue;
    items.push({
      title: title || summary.slice(0, 120),
      url: link && link.startsWith('http') ? link : '',
      publishedAt: publishedAt ? publishedAt.toISOString() : null,
      summary,
      fullText,
      categories
    });
  }
  return items;
}
