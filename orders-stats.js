/**
 * Pure helpers that turn Weeztix /orders rows into sales stats.
 * No network, no globals: index.js fetches the orders, this file computes and formats.
 */
const TZ = 'Europe/Brussels';
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

// Slots ("fasce orarie") in Brussels local time
const SLOTS = [
  { name: 'notte (00–06)', from: 0, to: 6 },
  { name: 'mattina (06–12)', from: 6, to: 12 },
  { name: 'pomeriggio (12–18)', from: 12, to: 18 },
  { name: 'sera (18–24)', from: 18, to: 24 }
];

const partsFmt = new Intl.DateTimeFormat('it-IT', {
  timeZone: TZ, weekday: 'long', hour: 'numeric', hourCycle: 'h23'
});

function localParts(ts) {
  const p = {};
  for (const x of partsFmt.formatToParts(new Date(ts))) p[x.type] = x.value;
  return { weekday: p.weekday, hour: Number(p.hour) };
}

function toRow(o) {
  const ts = o.created_at_int ? o.created_at_int * 1000 : Date.parse(o.created_at);
  return {
    guid: o.guid,
    ts,
    email: (o.email || '').trim(),
    name: (o.fullname || '').trim(),
    tickets: o.tickets_count == null ? 1 : Number(o.tickets_count) || 0,
    value: Number(o.finn_value) || 0, // cents, ticket value excluding service fee
    channel: o.purchase_channel,
    status: o.status
  };
}

const sum = (rows, k) => rows.reduce((a, r) => a + r[k], 0);
const fmt1 = (n) => (Math.round(n * 10) / 10).toString().replace('.', ',');
const eur = (cents) => `€${(cents / 100).toFixed(2).replace('.', ',')}`;
const fmtDate = (ts) => new Date(ts).toLocaleString('it-BE', { timeZone: TZ, dateStyle: 'short', timeStyle: 'short' });

function windowStats(rows, now, ms) {
  const inWin = rows.filter(r => r.ts > now - ms);
  return { tickets: sum(inWin, 'tickets'), orders: inWin.length, value: sum(inWin, 'value') };
}

function computeTrend(rows, now, sinceMs = 0) {
  const startTs = sinceMs || (rows.length ? Math.min(...rows.map(r => r.ts)) : now);
  const spanMs = Math.max(HOUR, now - startTs);
  return {
    startTs,
    spanMs,
    h1: windowStats(rows, now, HOUR),
    d1: windowStats(rows, now, DAY),
    w1: windowStats(rows, now, 7 * DAY),
    all: { tickets: sum(rows, 'tickets'), orders: rows.length, value: sum(rows, 'value') }
  };
}

function formatTrend(t) {
  const days = t.spanMs / DAY;
  const weeks = days / 7;
  return (
    `📈 TREND DI VENDITA\n\n` +
    `Ultima ora: ${t.h1.tickets} biglietti (${t.h1.orders} ordini)\n` +
    `Ultime 24h: ${t.d1.tickets} biglietti → media ${fmt1(t.d1.tickets / 24)}/ora\n` +
    `Ultimi 7 giorni: ${t.w1.tickets} biglietti → media ${fmt1(t.w1.tickets / 7)}/giorno (${fmt1(t.w1.tickets / (7 * 24))}/ora)\n` +
    `Dall'inizio (${fmtDate(t.startTs)}, ${fmt1(days)} giorni): ${t.all.tickets} biglietti, ${t.all.orders} ordini\n` +
    `   media ${fmt1(t.all.tickets / (t.spanMs / HOUR))}/ora · ${fmt1(t.all.tickets / days)}/giorno` +
    (days >= 7 ? ` · ${fmt1(t.all.tickets / weeks)}/settimana` : '') + `\n` +
    `Incasso biglietti (fee escluse): ${eur(t.all.value)} · media ${eur(t.all.orders ? t.all.value / t.all.orders : 0)}/ordine`
  );
}

function bump(map, key, r) {
  const e = map.get(key) || { tickets: 0, orders: 0 };
  e.tickets += r.tickets; e.orders += 1;
  map.set(key, e);
}

function computeBest(rows) {
  const byDay = new Map(), byHour = new Map(), bySlot = new Map(), byCell = new Map();
  for (const r of rows) {
    const { weekday, hour } = localParts(r.ts);
    bump(byDay, weekday, r);
    bump(byHour, hour, r);
    bump(bySlot, SLOTS.find(s => hour >= s.from && hour < s.to).name, r);
    bump(byCell, `${weekday} ${String(hour).padStart(2, '0')}–${String((hour + 1) % 24).padStart(2, '0')}`, r);
  }
  const top = (m, n) => [...m.entries()].sort((a, b) => b[1].tickets - a[1].tickets).slice(0, n);
  return { total: sum(rows, 'tickets'), byDay: top(byDay, 7), byHour: top(byHour, 3), bySlot: top(bySlot, 4), byCell: top(byCell, 3) };
}

function formatBest(b) {
  if (!b.total) return '🏆 Nessuna vendita trovata.';
  const pct = (e) => `${e.tickets} (${Math.round((e.tickets / b.total) * 100)}%)`;
  const line = ([k, e]) => `• ${k}: ${pct(e)}`;
  return (
    `🏆 QUANDO VENDIAMO DI PIÙ (ora di Bruxelles, ${b.total} biglietti)\n\n` +
    `Giorno della settimana:\n${b.byDay.map(line).join('\n')}\n\n` +
    `Fascia oraria:\n${b.bySlot.map(line).join('\n')}\n\n` +
    `Top 3 ore singole:\n${b.byHour.map(([h, e]) => `• ${String(h).padStart(2, '0')}–${String((h + 1) % 24).padStart(2, '0')}: ${pct(e)}`).join('\n')}\n\n` +
    `Top 3 giorno+ora:\n${b.byCell.map(line).join('\n')}`
  );
}

function formatLast(rows, n = 10) {
  const last = [...rows].sort((a, b) => b.ts - a.ts).slice(0, n);
  if (!last.length) return '✉️ Nessun ordine trovato.';
  return `✉️ ULTIME ${last.length} TRANSAZIONI\n\n` + last.map((r, i) =>
    `${i + 1}. ${r.email || '(senza email)'}\n    ${fmtDate(r.ts)} · ${r.tickets} ${r.tickets === 1 ? 'biglietto' : 'biglietti'} · ${eur(r.value)}`).join('\n');
}

module.exports = { toRow, computeTrend, formatTrend, computeBest, formatBest, formatLast, TZ };
