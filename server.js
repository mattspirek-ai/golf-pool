/**
 * Golf Pool Backend v2
 * Features: JWT auth, CSV tier upload, entry visibility control, ESPN score proxy
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'golf-pool-secret-change-in-production-2025';
const DATA_FILE = path.join(__dirname, 'data', 'pool-data.json');
const UPLOAD = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

// ─────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// Data helpers
// ─────────────────────────────────────────────
const DEFAULT_DATA = {
  admins: [
    { username: 'josh', passwordHash: '$2b$10$RmOV0CxpzXcK4SvIkgDV5.RcdOXJRCv6CGi3d61FWgoFvhwbKJyKi', role: 'superadmin' },
    { username: 'admin2', passwordHash: '$2b$10$MV0ZEOlvq.qSUWDwfhGtwuN2YnxXI968IlM2I/YiJT.cS0Bp5oQz2', role: 'admin' }
  ],
  tournament: {
    name: 'The British Open Championship',
    year: 2025,
    course: 'Royal Portrush',
    par: 71,
    espnEventId: '401580350',
    entriesRevealAt: null,   // ISO date string — null = always hidden
    entriesVisible: false,   // manual override
    cutPenaltyScore: 80,
    buyIn: 50,
    payouts: { first: 0.65, second: 0.25, third: 0.10 }
  },
  tiers: {
    1: { label: 'Tier 1', desc: 'Elite Favorites', players: ['Bryson DeChambeau','Collin Morikawa','Jon Rahm','Ludvig Aberg','Rory McIlroy','Scottie Scheffler','Tommy Fleetwood','Tyrrell Hatton','Viktor Hovland','Xander Schauffele'] },
    2: { label: 'Tier 2', desc: 'Strong Contenders', players: ['Brooks Koepka','Corey Conners','Joaquin Niemann','Jordan Spieth','Justin Thomas','Matt Fitzpatrick','Patrick Cantlay','Robert MacIntyre','Russell Henley','Sepp Straka','Shane Lowry'] },
    3: { label: 'Tier 3', desc: 'Solid Picks', players: ['Justin Rose','Adam Scott','Ben Griffin','Cameron Young','Chris Gotterup','Hideki Matsuyama','Jason Day','Keegan Bradley','Patrick Reed','Ryan Fox','Sam Burns'] },
    4: { label: 'Tier 4', desc: 'Value Plays', players: ['Aaron Rai','Brian Harman','Cameron Smith','Harris English','Harry Hall','J.J. Spaun','Maverick McNealy','Min Woo Lee','Si Woo Kim','Tony Finau','Wyndham Clark'] },
    5: { label: 'Tier 5', desc: 'Longshots', players: ['Akshay Bhatia','Bud Cauley','Daniel Berger','Dean Burmester','Nicolai Hojgaard','Rasmus Hojgaard','Rickie Fowler','Sergio Garcia','Sungjae Im','Taylor Pendrith','Tom Kim','Tom McKibbin'] },
    6: { label: 'Tier 6', desc: 'The Field', players: ['Adrien Saddier','Andrew Novak','Brian Campbell','Byeong Hun An','Carlos Ortiz','Chris Kirk','Christiaan Bezuidenhout','Daniel Brown','Davis Riley','Davis Thompson','Denny McCarthy','Dustin Johnson','Francesco Molinari','Guido Migliozzi','J.T. Poston','Jhonattan Vegas','Justin Hastings','Justin Suh','Laurie Canter','Louis Oosthuizen','Lucas Glover','Mackenzie Hughes','Marc Leishman','Matt McCarty','Matt Wallace','Matthieu Pavon','Max Greyserman','Michael Kim','Nico Echavarria','Niklas Norgaard','Phil Mickelson','Sahith Theegala','Sebastian Soderberg','Stephan Jaeger','Thomas Detry','Thorbjorn Olesen','Thriston Lawrence','Tom Hoge','Zach Johnson'] }
  },
  entries: [],
  scores: {},
  lastEspnFetch: null
};

function ensureDataDir() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadData() {
  ensureDataDir();
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(DEFAULT_DATA, null, 2));
    return JSON.parse(JSON.stringify(DEFAULT_DATA));
  }
  try {
    const saved = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    // Merge — ensure all keys exist
    return {
      ...DEFAULT_DATA,
      ...saved,
      tournament: { ...DEFAULT_DATA.tournament, ...saved.tournament },
      tiers: saved.tiers || DEFAULT_DATA.tiers,
      admins: saved.admins || DEFAULT_DATA.admins,
    };
  } catch { return JSON.parse(JSON.stringify(DEFAULT_DATA)); }
}

function saveData(data) {
  ensureDataDir();
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ─────────────────────────────────────────────
// Auth middleware
// ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = header.slice(7);
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireSuperAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.admin.role !== 'superadmin') {
      return res.status(403).json({ error: 'Superadmin required' });
    }
    next();
  });
}

// ─────────────────────────────────────────────
// Utility: are entries currently visible?
// ─────────────────────────────────────────────
function entriesAreVisible(tournament) {
  if (tournament.entriesVisible) return true;
  if (tournament.entriesRevealAt && new Date() >= new Date(tournament.entriesRevealAt)) return true;
  return false;
}

// ─────────────────────────────────────────────
// ESPN score cache
// ─────────────────────────────────────────────
let scoreCache = null;
let cacheFetchedAt = null;
const CACHE_TTL_LIVE = 5 * 60 * 1000;
const CACHE_TTL_IDLE = 60 * 60 * 1000;

function isCacheValid(isLive) {
  if (!scoreCache || !cacheFetchedAt) return false;
  const ttl = isLive ? CACHE_TTL_LIVE : CACHE_TTL_IDLE;
  return (Date.now() - cacheFetchedAt) < ttl;
}

async function fetchESPN(eventId) {
  // Use dynamic import for node-fetch v3 or fallback to https
  return new Promise((resolve, reject) => {
    const https = require('https');
    const url = `https://site.api.espn.com/apis/site/v2/sports/golf/pga/leaderboard?event=${eventId}`;
    const req = https.get(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; GolfPoolApp/2.0)', 'Accept': 'application/json' }
    }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('Invalid JSON from ESPN')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('ESPN timeout')); });
  });
}

function parseESPN(data) {
  const players = {};
  const competitors = data?.events?.[0]?.competitions?.[0]?.competitors || [];
  competitors.forEach(comp => {
    const athlete = comp.athlete;
    if (!athlete) return;
    const name = athlete.displayName || `${athlete.firstName} ${athlete.lastName}`;
    const status = comp.status?.type?.name || '';
    const isMC = ['STATUS_MISSED_CUT', 'STATUS_WD', 'STATUS_DQ'].includes(status);
    const rounds = {};
    (comp.linescores || []).forEach((ls, i) => {
      rounds[`r${i + 1}`] = (ls.value && ls.value !== 0) ? Math.round(ls.value) : null;
    });
    players[name] = {
      r1: rounds.r1 || null, r2: rounds.r2 || null,
      r3: rounds.r3 || null, r4: rounds.r4 || null,
      mc: isMC, pos: comp.status?.position?.displayName || null,
      espnId: athlete.id
    };
  });
  return players;
}

// ─────────────────────────────────────────────
// CSV → Tiers parser
// ─────────────────────────────────────────────
function parseOddsCSV(csvText) {
  const lines = csvText.trim().split('\n').map(l => l.trim()).filter(Boolean);
  const players = [];

  for (const line of lines) {
    // Skip header rows
    if (/player|name|golfer|odds/i.test(line) && players.length === 0) continue;

    // Support: "Player Name,+1200" or "Player Name,1200" or "Player Name,12/1" or "Player Name,+1200,other cols"
    const parts = line.split(',').map(s => s.trim().replace(/^"|"$/g, ''));
    if (parts.length < 2) continue;

    const name = parts[0];
    let oddsStr = parts[1].replace(/[+\s]/g, '');

    let oddsValue = Infinity;

    if (oddsStr.includes('/')) {
      // Fractional: 12/1 → 1200
      const [num, den] = oddsStr.split('/').map(Number);
      oddsValue = den > 0 ? (num / den) * 100 : 9999;
    } else {
      const n = parseInt(oddsStr);
      if (!isNaN(n)) oddsValue = Math.abs(n);
    }

    if (name) players.push({ name, odds: oddsValue });
  }

  // Sort by odds ascending (favorites first)
  players.sort((a, b) => a.odds - b.odds);

  // Divide into 6 tiers by odds groups
  // Tier 1: top ~8-10, Tier 2: next ~10, etc.
  const total = players.length;
  const TIER_SIZES = [
    Math.max(6, Math.round(total * 0.08)),   // ~8%  → Tier 1
    Math.max(8, Math.round(total * 0.12)),   // ~12% → Tier 2
    Math.max(8, Math.round(total * 0.14)),   // ~14% → Tier 3
    Math.max(8, Math.round(total * 0.14)),   // ~14% → Tier 4
    Math.max(8, Math.round(total * 0.14)),   // ~14% → Tier 5
    Infinity                                  // Rest → Tier 6
  ];

  const tiers = { 1: [], 2: [], 3: [], 4: [], 5: [], 6: [] };
  let idx = 0;
  for (let t = 1; t <= 6; t++) {
    const cap = TIER_SIZES[t - 1];
    while (idx < players.length && tiers[t].length < cap && (t < 6)) {
      tiers[t].push(players[idx++].name);
    }
  }
  // Dump rest into tier 6
  while (idx < players.length) {
    tiers[6].push(players[idx++].name);
  }

  return { tiers, players, total };
}

// ─────────────────────────────────────────────
// Scoring engine
// ─────────────────────────────────────────────
function getPlayerTotal(player, scores, cutVal) {
  const sc = scores[player];
  if (!sc) return null;
  let { r1, r2, r3, r4 } = sc;
  if (sc.mc) { r3 = r3 ?? cutVal; r4 = r4 ?? cutVal; }
  const vals = [r1, r2, r3, r4].filter(v => v !== null && v !== undefined);
  return vals.length > 0 ? vals.reduce((a, b) => a + b, 0) : null;
}

function scoreEntry(entry, scores, cutVal, par) {
  const tierBests = [];
  for (let t = 1; t <= 6; t++) {
    const picks = entry.picks[t] || entry.picks[String(t)] || [];
    const [p0, p1] = picks;
    const s0 = getPlayerTotal(p0, scores, cutVal);
    const s1 = getPlayerTotal(p1, scores, cutVal);
    let best = null, used = null;
    if (s0 !== null && s1 !== null) { if (s0 <= s1) { best = s0; used = p0; } else { best = s1; used = p1; } }
    else if (s0 !== null) { best = s0; used = p0; }
    else if (s1 !== null) { best = s1; used = p1; }
    if (best !== null) tierBests.push({ tier: t, score: best, used });
  }

  let droppedTier = null;
  if (tierBests.length > 0) {
    const worst = tierBests.reduce((a, b) => b.score > a.score ? b : a);
    droppedTier = worst.tier;
  }

  const used = tierBests.filter(tb => tb.tier !== droppedTier);
  let total = used.length > 0 ? used.reduce((a, b) => a + b.score, 0) : null;

  // Find current leader
  let leaderName = null, leaderScore = Infinity;
  Object.entries(scores).forEach(([p, sc]) => {
    const t = getPlayerTotal(p, scores, cutVal);
    if (t !== null && t < leaderScore) { leaderScore = t; leaderName = p; }
  });

  let winnerBonus = false;
  if (leaderName && entry.winner === leaderName) {
    winnerBonus = true;
    if (total !== null) total -= 10;
  }

  const allPicks = Object.values(entry.picks).flat();
  const cutMakers = allPicks.filter(p => { const sc = scores[p]; return sc && !sc.mc; }).length;
  const actualPar = leaderScore < Infinity ? leaderScore - (par * 4) : null;

  return { total, droppedTier, tierBests, usedBests: used, winnerBonus, cutMakers, leaderName, actualPar };
}

// ═════════════════════════════════════════════
// ROUTES
// ═════════════════════════════════════════════

// ── Auth ──────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const db = loadData();
  const admin = db.admins.find(a => a.username.toLowerCase() === username.toLowerCase());
  if (!admin || !bcrypt.compareSync(password, admin.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { username: admin.username, role: admin.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, username: admin.username, role: admin.role });
});

app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ valid: true, username: req.admin.username, role: req.admin.role });
});

// ── Admin management (superadmin only) ───────
app.get('/api/admins', requireSuperAdmin, (req, res) => {
  const db = loadData();
  res.json(db.admins.map(a => ({ username: a.username, role: a.role })));
});

app.post('/api/admins', requireSuperAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const db = loadData();
  if (db.admins.find(a => a.username === username)) return res.status(409).json({ error: 'Username taken' });
  db.admins.push({ username, passwordHash: bcrypt.hashSync(password, 10), role: role || 'admin' });
  saveData(db);
  res.json({ ok: true });
});

app.delete('/api/admins/:username', requireSuperAdmin, (req, res) => {
  const db = loadData();
  if (req.params.username === req.admin.username) return res.status(400).json({ error: 'Cannot delete yourself' });
  db.admins = db.admins.filter(a => a.username !== req.params.username);
  saveData(db);
  res.json({ ok: true });
});

app.post('/api/admins/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const db = loadData();
  const admin = db.admins.find(a => a.username === req.admin.username);
  if (!bcrypt.compareSync(currentPassword, admin.passwordHash)) {
    return res.status(401).json({ error: 'Current password incorrect' });
  }
  admin.passwordHash = bcrypt.hashSync(newPassword, 10);
  saveData(db);
  res.json({ ok: true });
});

// ── Tournament config ─────────────────────────
app.get('/api/tournament', (req, res) => {
  const db = loadData();
  const t = db.tournament;
  res.json({
    name: t.name, year: t.year, course: t.course, par: t.par,
    buyIn: t.buyIn, payouts: t.payouts,
    entriesRevealAt: t.entriesRevealAt,
    entriesVisible: entriesAreVisible(t),
    cutPenaltyScore: t.cutPenaltyScore,
    // Don't expose espnEventId to public
  });
});

app.put('/api/tournament', requireAuth, (req, res) => {
  const db = loadData();
  const allowed = ['name','year','course','par','buyIn','payouts','entriesRevealAt','entriesVisible','cutPenaltyScore','espnEventId'];
  allowed.forEach(k => { if (req.body[k] !== undefined) db.tournament[k] = req.body[k]; });
  saveData(db);
  res.json({ ok: true, tournament: db.tournament });
});

// ── Tiers ─────────────────────────────────────
app.get('/api/tiers', (req, res) => {
  const db = loadData();
  res.json(db.tiers);
});

app.put('/api/tiers', requireAuth, (req, res) => {
  const db = loadData();
  db.tiers = req.body;
  saveData(db);
  res.json({ ok: true });
});

// CSV upload → preview tiers (no save yet)
app.post('/api/tiers/upload-csv', requireAuth, UPLOAD.single('csv'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const text = req.file.buffer.toString('utf8');
  try {
    const result = parseOddsCSV(text);
    res.json({ ok: true, preview: result.tiers, players: result.players, total: result.total });
  } catch (e) {
    res.status(400).json({ error: 'Could not parse CSV: ' + e.message });
  }
});

// Confirm and save previewed tiers
app.post('/api/tiers/confirm', requireAuth, (req, res) => {
  const { tiers } = req.body;
  if (!tiers) return res.status(400).json({ error: 'tiers required' });
  const db = loadData();
  db.tiers = tiers;
  // Clear existing entries & scores when tiers change (new tournament)
  const reset = req.body.resetEntries === true;
  if (reset) { db.entries = []; db.scores = {}; }
  saveData(db);
  res.json({ ok: true, tierCounts: Object.fromEntries(Object.entries(tiers).map(([k,v]) => [k, v.players?.length || 0])) });
});

// ── Entries ───────────────────────────────────
// Public — only returns entries if visible
app.get('/api/entries', (req, res) => {
  const db = loadData();
  const visible = entriesAreVisible(db.tournament);
  if (!visible) {
    return res.json({ visible: false, count: db.entries.length, entries: [] });
  }
  res.json({ visible: true, count: db.entries.length, entries: db.entries });
});

// Admin — always sees all entries
app.get('/api/admin/entries', requireAuth, (req, res) => {
  const db = loadData();
  res.json({ entries: db.entries, visible: entriesAreVisible(db.tournament), revealAt: db.tournament.entriesRevealAt });
});

app.post('/api/entries', (req, res) => {
  const { name, picks, winner, scoreVsPar } = req.body;
  if (!name || !picks || !winner) return res.status(400).json({ error: 'name, picks, winner required' });
  // Validate 2 picks per tier
  for (let t = 1; t <= 6; t++) {
    const tp = picks[t] || picks[String(t)];
    if (!tp || tp.length !== 2 || tp[0] === tp[1]) {
      return res.status(400).json({ error: `Invalid picks for tier ${t}` });
    }
  }
  const db = loadData();
  // Check for duplicate name
  if (db.entries.find(e => e.name.toLowerCase() === name.toLowerCase())) {
    return res.status(409).json({ error: 'An entry with that name already exists' });
  }
  const entry = { id: Date.now(), name, picks, winner, scoreVsPar: parseInt(scoreVsPar) || 0, submitted: new Date().toISOString() };
  db.entries.push(entry);
  saveData(db);
  res.json({ ok: true, entry: { id: entry.id, name: entry.name, submitted: entry.submitted } });
});

app.delete('/api/entries/:id', requireAuth, (req, res) => {
  const db = loadData();
  db.entries = db.entries.filter(e => e.id !== parseInt(req.params.id));
  saveData(db);
  res.json({ ok: true });
});

// ── Scores ────────────────────────────────────
app.get('/api/scores', async (req, res) => {
  const db = loadData();
  const eventId = db.tournament.espnEventId;
  const force = req.query.force === 'true';

  if (!force && isCacheValid(scoreCache?._isLive)) {
    return res.json({ source: 'cache', fetchedAt: cacheFetchedAt, scores: { ...db.scores, ...scoreCache } });
  }

  try {
    const raw = await fetchESPN(eventId);
    const parsed = parseESPN(raw);
    const status = raw?.events?.[0]?.competitions?.[0]?.status?.type?.name;
    scoreCache = { ...parsed, _isLive: status === 'STATUS_IN_PROGRESS', _status: status, _name: raw?.events?.[0]?.name };
    cacheFetchedAt = Date.now();
    // Merge: manual overrides win
    const merged = { ...parsed, ...db.scores };
    res.json({ source: 'espn', fetchedAt: cacheFetchedAt, scores: merged, tournamentStatus: status });
  } catch (err) {
    console.error('ESPN error:', err.message);
    res.json({ source: 'manual', fetchedAt: null, scores: db.scores, error: err.message });
  }
});

app.post('/api/scores/manual', requireAuth, (req, res) => {
  const { playerName, r1, r2, r3, r4, mc } = req.body;
  if (!playerName) return res.status(400).json({ error: 'playerName required' });
  const db = loadData();
  db.scores[playerName] = { r1: r1 ?? null, r2: r2 ?? null, r3: r3 ?? null, r4: r4 ?? null, mc: mc ?? false };
  saveData(db);
  res.json({ ok: true });
});

app.delete('/api/scores/manual/:player', requireAuth, (req, res) => {
  const db = loadData();
  delete db.scores[decodeURIComponent(req.params.player)];
  saveData(db);
  res.json({ ok: true });
});

// ── Leaderboard ───────────────────────────────
app.get('/api/leaderboard', async (req, res) => {
  const db = loadData();
  const visible = entriesAreVisible(db.tournament);
  const cutVal = parseInt(req.query.cutScore) || db.tournament.cutPenaltyScore || 80;
  const par = db.tournament.par || 71;

  // Build merged scores
  let espnScores = {};
  if (scoreCache && isCacheValid(scoreCache._isLive)) {
    const { _isLive, _status, _name, ...clean } = scoreCache;
    espnScores = clean;
  }
  const scores = { ...espnScores, ...db.scores };

  const results = db.entries.map(entry => {
    const scored = scoreEntry(entry, scores, cutVal, par);
    return {
      entry: visible ? entry : { id: entry.id, name: entry.name, submitted: entry.submitted },
      ...scored
    };
  });

  results.sort((a, b) => {
    if (a.total === null && b.total === null) return 0;
    if (a.total === null) return 1;
    if (b.total === null) return -1;
    if (a.total !== b.total) return a.total - b.total;
    // Tiebreak 1: score guess
    if (results[0]?.actualPar !== null) {
      const aDiff = Math.abs(a.entry.scoreVsPar - (a.actualPar || 0));
      const bDiff = Math.abs(b.entry.scoreVsPar - (b.actualPar || 0));
      if (aDiff !== bDiff) return aDiff - bDiff;
    }
    return b.cutMakers - a.cutMakers;
  });

  res.json({ results, visible, entriesRevealAt: db.tournament.entriesRevealAt, fetchedAt: cacheFetchedAt });
});

// ── Status ────────────────────────────────────
app.get('/api/status', (req, res) => {
  const db = loadData();
  const tierCounts = Object.fromEntries(Object.entries(db.tiers).map(([k, v]) => [k, (v.players||[]).length]));
  res.json({
    entries: db.entries.length,
    manualScores: Object.keys(db.scores).length,
    entriesVisible: entriesAreVisible(db.tournament),
    entriesRevealAt: db.tournament.entriesRevealAt,
    espnCacheAge: cacheFetchedAt ? Math.round((Date.now() - cacheFetchedAt) / 1000) + 's' : 'no cache',
    isLive: scoreCache?._isLive || false,
    tournament: db.tournament.name,
    tierCounts,
  });
});

// ─────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════╗
║   🏌️  Golf Pool v2 — Port ${PORT}                   ║
║                                                  ║
║  Default logins:                                 ║
║    josh / admin123        (superadmin)           ║
║    admin2 / commish2025   (admin)                ║
║                                                  ║
║  ⚠  Change passwords after first login!         ║
╚══════════════════════════════════════════════════╝
`);
});

module.exports = app;
