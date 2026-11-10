/* Extreme Battle — shared leaderboard server (Cloudflare Pages Function)
   Put this file in your GitHub repo at:  functions/api/[[path]].js
   Needs the D1 binding "DB" (Pages project > Settings > Bindings).
   Endpoints (all under /api): hello, start, result, me, top, ping, lobby/up, lobby/down, lobby/list
   Accounts: an anonymous id + key per device; signing in with Google links the account, so the same rank follows you to any device.
   Ranked points only change when BOTH players report the same result for the same match. */

const GOOGLE_CLIENT_ID = '37282695207-kadnh25nmu1jo3ms42kebeeodikd4u2h.apps.googleusercontent.com';
const TIERS = [0, 80, 200, 380, 620, 980, 1500, 2300, 3400];
const WIN_BASE = [36, 30, 26, 22, 18, 15, 12, 10, 8], LOSE_BASE = [6, 9, 12, 15, 18, 20, 22, 24, 26];

const CORS = { 'access-control-allow-origin':'*', 'access-control-allow-methods':'GET,POST,OPTIONS', 'access-control-allow-headers':'content-type' };
const json = (d, status = 200) => new Response(JSON.stringify(d), { status, headers:{ 'content-type':'application/json', 'cache-control':'no-store', ...CORS } });
const now = () => Math.floor(Date.now() / 1000);
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, n);
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const tierIdx = p => { let i = 0; for (let k = 0; k < TIERS.length; k++) if (p >= TIERS[k]) i = k; return i; };
function rankDelta(res, me, opp) {   /* same formula as the game */
  const ti = tierIdx(me), winB = WIN_BASE[Math.min(ti, 8)], loseB = LOSE_BASE[Math.min(ti, 8)], k = clamp((opp - me) / 400, -1, 1);
  if (res === 'win') return winB + Math.round(winB * 0.4 * k);
  if (res === 'lose') { let d = loseB + Math.round(loseB * 0.3 * (-k)); if (ti === 0) d = Math.max(2, Math.ceil(d * 0.35)); return -d; }
  return 0;
}

/* ---------- Google sign-in check (verifies the ID token's signature with Google's public keys) ---------- */
let JWKS = null, JWKS_T = 0;
const b64u = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
async function googleUser(token) {
  const [h, p, sg] = String(token || '').split('.'); if (!h || !p || !sg) throw new Error('bad token');
  const head = JSON.parse(new TextDecoder().decode(b64u(h))), pl = JSON.parse(new TextDecoder().decode(b64u(p)));
  if (!JWKS || Date.now() - JWKS_T > 3600e3) { const r = await fetch('https://www.googleapis.com/oauth2/v3/certs'); JWKS = (await r.json()).keys || []; JWKS_T = Date.now(); }
  const jwk = JWKS.find(k => k.kid === head.kid); if (!jwk) throw new Error('unknown key');
  const key = await crypto.subtle.importKey('jwk', jwk, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(sg), new TextEncoder().encode(h + '.' + p));
  if (!ok) throw new Error('bad signature');
  if (pl.aud !== GOOGLE_CLIENT_ID) throw new Error('wrong app');
  if (pl.iss !== 'accounts.google.com' && pl.iss !== 'https://accounts.google.com') throw new Error('wrong issuer');
  if (!pl.exp || pl.exp < now()) throw new Error('expired');
  return { sub:String(pl.sub), name:pl.given_name || pl.name || '' };
}

/* ---------- helpers ---------- */
const pub = (r, me) => ({ id:r.id, name:r.name, av:r.av, pts:r.pts, w:r.w, l:r.l, best:r.best, me:!!me });
async function getAuth(DB, b) {
  if (!b.id || !b.key) return null;
  return DB.prepare('SELECT * FROM lb_players WHERE id = ? AND key = ?').bind(String(b.id), String(b.key)).first();
}
const newId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 16), newKey = () => crypto.randomUUID().replace(/-/g, '');

export async function onRequest(ctx) {
  const { request, env, params } = ctx;
  if (request.method === 'OPTIONS') return new Response(null, { status:204, headers:CORS });
  const DB = env.DB; if (!DB) return json({ error:'Database not connected' }, 500);
  const url = new URL(request.url), path = '/' + [].concat(params.path || []).join('/');
  let b = {}; if (request.method === 'POST') { try { b = JSON.parse(await request.text() || '{}'); } catch (e) { b = {}; } }
  const board = clean(b.board || url.searchParams.get('board') || 'rumble', 20) || 'rumble', t = now();
  try {
    /* ---- account: create / resume / link Google ---- */
    if (path === '/hello') {
      const name = clean(b.name, 20) || 'Trainer', av = clean(b.av, 40) || 'red';
      let g = null; if (b.gtoken) { try { g = await googleUser(b.gtoken); } catch (e) { return json({ error:'Google sign-in failed: ' + e.message }, 401); } }
      let row = null;
      if (g) row = await DB.prepare('SELECT * FROM lb_players WHERE board = ? AND gsub = ?').bind(board, g.sub).first();   /* same Google account on any device */
      if (!row) row = await getAuth(DB, b);
      let isNew = false;
      if (!row) { isNew = true; row = { id:newId(), key:newKey(), board, gsub:g ? g.sub : null, name, av, pts:0, w:0, l:0, best:0 };
        await DB.prepare('INSERT INTO lb_players (id, key, board, gsub, name, av, pts, w, l, best, created, updated) VALUES (?,?,?,?,?,?,0,0,0,0,?,?)').bind(row.id, row.key, board, row.gsub, name, av, t, t).run(); }
      else {
        if (g && !row.gsub) row.gsub = g.sub;
        await DB.prepare('UPDATE lb_players SET name = ?, av = ?, gsub = COALESCE(gsub, ?), updated = ? WHERE id = ?').bind(name, av, g ? g.sub : null, t, row.id).run(); row.name = name; row.av = av;
      }
      return json({ id:row.id, key:row.key, isNew, google:!!(g || row.gsub), name:row.name, av:row.av, pts:row.pts, w:row.w, l:row.l, best:row.best });
    }
    /* ---- ranked: a match starts, each player reports, the server settles when both agree ---- */
    if (path === '/start') {
      const me = await getAuth(DB, b); if (!me) return json({ error:'unknown player' }, 401);
      await DB.prepare('INSERT OR IGNORE INTO lb_claims (mid, pid, opp, res, at) VALUES (?,?,?,NULL,?)').bind(clean(b.mid, 40), me.id, clean(b.opp, 20), t).run();
      return json({ ok:true });
    }
    if (path === '/result') {
      const me = await getAuth(DB, b); if (!me) return json({ error:'unknown player' }, 401);
      const mid = clean(b.mid, 40), res = ['win', 'lose', 'draw'].includes(b.res) ? b.res : null, opp = clean(b.opp, 20); if (!mid || !res || !opp || opp === me.id) return json({ error:'bad result' }, 400);
      await DB.prepare('INSERT INTO lb_claims (mid, pid, opp, res, at) VALUES (?,?,?,?,?) ON CONFLICT(mid, pid) DO UPDATE SET res = COALESCE(lb_claims.res, excluded.res), opp = excluded.opp').bind(mid, me.id, opp, res, t).run();
      return json(await settle(DB, mid, me.id));
    }
    if (path === '/me') {
      const me = await getAuth(DB, b); if (!me) return json({ error:'unknown player' }, 401);
      const s = b.mid ? await DB.prepare('SELECT mid FROM lb_settled WHERE mid = ?').bind(clean(b.mid, 40)).first() : null;
      return json(Object.assign({ settled:!!s }, pub(me)));
    }
    if (path === '/top') {
      const meId = clean(url.searchParams.get('me'), 20);
      const top = (await DB.prepare('SELECT * FROM lb_players WHERE board = ? AND (w + l) > 0 ORDER BY pts DESC, updated ASC LIMIT 100').bind(board).all()).results || [];
      const total = ((await DB.prepare('SELECT COUNT(*) AS n FROM lb_players WHERE board = ? AND (w + l) > 0').bind(board).first()) || {}).n || 0;
      let me = null; if (meId) { const r = await DB.prepare('SELECT * FROM lb_players WHERE id = ?').bind(meId).first();
        if (r && r.w + r.l > 0) { const above = ((await DB.prepare('SELECT COUNT(*) AS n FROM lb_players WHERE board = ? AND (w + l) > 0 AND pts > ?').bind(board, r.pts).first()) || {}).n || 0; me = Object.assign(pub(r, true), { rank:above + 1 }); } }
      return json({ top:top.map((r, i) => Object.assign(pub(r, r.id === meId), { rank:i + 1 })), me, total });
    }
    /* ---- players online ---- */
    if (path === '/ping') {
      const sid = clean(b.sid, 16); if (!sid) return json({ error:'no sid' }, 400);
      if (b.leave) await DB.prepare('DELETE FROM lb_presence WHERE sid = ?').bind(sid).run();
      else await DB.prepare('INSERT INTO lb_presence (sid, board, state, at) VALUES (?,?,?,?) ON CONFLICT(sid) DO UPDATE SET state = excluded.state, at = excluded.at').bind(sid, board, clean(b.state, 12) || 'menu', t).run();
      if (Math.random() < 0.1) await DB.prepare('DELETE FROM lb_presence WHERE at < ?').bind(t - 150).run();
      const c = (await DB.prepare("SELECT COUNT(*) AS online, SUM(state = 'battle') AS battle, SUM(state = 'searching') AS searching FROM lb_presence WHERE board = ? AND at >= ?").bind(board, t - 120).first()) || {};
      return json({ online:c.online || 0, battle:c.battle || 0, searching:c.searching || 0 });
    }
    /* ---- custom lobby room list ---- */
    if (path === '/lobby/up') {
      const me = await getAuth(DB, b); if (!me) return json({ error:'unknown player' }, 401);
      const room = b.room || {}, code = clean(room.code, 12).toUpperCase(); if (!code) return json({ error:'no room code' }, 400);
      const ad = JSON.stringify(room).slice(0, 4000);
      await DB.prepare('INSERT INTO lb_lobbies (code, board, owner, ad, at) VALUES (?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET ad = excluded.ad, at = excluded.at WHERE lb_lobbies.owner = excluded.owner').bind(code, board, me.id, ad, t).run();
      return json({ ok:true });
    }
    if (path === '/lobby/down') {
      const me = await getAuth(DB, b); if (!me) return json({ error:'unknown player' }, 401);
      await DB.prepare('DELETE FROM lb_lobbies WHERE code = ? AND owner = ?').bind(clean(b.code, 12).toUpperCase(), me.id).run();
      return json({ ok:true });
    }
    if (path === '/lobby/list') {
      const rows = (await DB.prepare('SELECT ad FROM lb_lobbies WHERE board = ? AND at >= ? ORDER BY at DESC LIMIT 60').bind(board, t - 600).all()).results || [];
      return json({ rooms:rows.map(r => { try { return JSON.parse(r.ad); } catch (e) { return null; } }).filter(Boolean) });
    }
    return json({ error:'not found' }, 404);
  } catch (e) { return json({ error:String(e && e.message || e) }, 500); }
}

async function settle(DB, mid, myId) {
  const mine = await DB.prepare('SELECT * FROM lb_claims WHERE mid = ? AND pid = ?').bind(mid, myId).first();
  const me0 = await DB.prepare('SELECT * FROM lb_players WHERE id = ?').bind(myId).first();
  const done = await DB.prepare('SELECT mid FROM lb_settled WHERE mid = ?').bind(mid).first();
  if (done) return Object.assign({ settled:true }, pub(me0));
  const theirs = mine && mine.opp ? await DB.prepare('SELECT * FROM lb_claims WHERE mid = ? AND pid = ?').bind(mid, mine.opp).first() : null;
  if (!mine || !mine.res || !theirs || !theirs.res || theirs.opp !== myId) return Object.assign({ settled:false }, pub(me0));
  const agree = (mine.res === 'win' && theirs.res === 'lose') || (mine.res === 'lose' && theirs.res === 'win') || (mine.res === 'draw' && theirs.res === 'draw');
  if (!agree) { await DB.prepare('INSERT OR IGNORE INTO lb_settled (mid, at) VALUES (?, ?)').bind(mid, now()).run(); return Object.assign({ settled:true, disputed:true }, pub(me0)); }   /* reports don't match: nobody's points change */
  const op0 = await DB.prepare('SELECT * FROM lb_players WHERE id = ?').bind(theirs.pid).first(); if (!op0) return Object.assign({ settled:false }, pub(me0));
  const claimed = await DB.prepare('INSERT OR IGNORE INTO lb_settled (mid, at) VALUES (?, ?)').bind(mid, now()).run(); if (!claimed.meta || !claimed.meta.changes) return Object.assign({ settled:true }, pub(me0));   /* settled by the other request */
  const upd = async (p, res, oppPts) => { const d = rankDelta(res, p.pts, oppPts), pts = Math.max(0, p.pts + d), w = p.w + (res === 'win' ? 1 : 0), l = p.l + (res === 'lose' ? 1 : 0), best = Math.max(p.best, pts);
    await DB.prepare('UPDATE lb_players SET pts = ?, w = ?, l = ?, best = ?, updated = ? WHERE id = ?').bind(pts, w, l, best, now(), p.id).run(); return Object.assign({}, p, { pts, w, l, best }); };
  const me1 = await upd(me0, mine.res, op0.pts); await upd(op0, theirs.res, me0.pts);
  await DB.prepare('DELETE FROM lb_claims WHERE at < ?').bind(now() - 86400).run();
  return Object.assign({ settled:true }, pub(me1));
}
