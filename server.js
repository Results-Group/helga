const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3001;
const CTM_API_BASE = 'https://api.calltrackingmetrics.de';
const cache = new Map();
const CACHE_TTL = 15 * 60 * 1000;
const CACHE_FILE = path.join(__dirname, '.cache.json');

function loadCache() {
    try {
        const raw = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
        let loaded = 0;
        for (const [k, v] of Object.entries(raw)) {
            if (Date.now() - v.time < CACHE_TTL) { cache.set(k, v); loaded++; }
        }
        if (loaded) console.log(`[CACHE] Restored ${loaded} entries from disk`);
    } catch {}
}

function persistCache() {
    try {
        const obj = {};
        for (const [k, v] of cache.entries()) {
            if (Date.now() - v.time < CACHE_TTL) obj[k] = v;
        }
        fs.writeFileSync(CACHE_FILE, JSON.stringify(obj));
    } catch (e) { console.error('[CACHE] persist error:', e.message); }
}

loadCache();
setInterval(persistCache, 60 * 1000);
const CTM_AUTH = 'Basic YTgzZDlmMzM3NWY1ZDIyNzEwYWUwMDY2YWNkMzU1YTNkYzdkOjM0ODVjN2Q2ZWFkZWYzOTYzZmY3MWQ3MWVhNTdjM2VlNTQ1MQ==';
const ACCOUNT_ID = '83';
const SESSION_SECRET = 'tb-dashboard-2026-results-group-secret-key';
const USERS_FILE = path.join(__dirname, 'users.json');
const TARGETS_FILE = path.join(__dirname, 'targets.json');

const DEFAULT_TARGETS = { meetRate: 50, arrRate: 30, dealRate: 40 };

function loadTargets() {
    try { return JSON.parse(fs.readFileSync(TARGETS_FILE, 'utf8')); }
    catch { return { ...DEFAULT_TARGETS }; }
}
function saveTargets(t) { fs.writeFileSync(TARGETS_FILE, JSON.stringify(t, null, 2)); }

function hashPw(pw) { return crypto.createHash('sha256').update(pw + SESSION_SECRET).digest('hex'); }

function loadUsers() {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
    catch { return []; }
}
function saveUsers(users) { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }

function initUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        saveUsers([
            { id: '1', username: 'admin', password: hashPw('admin123'), name: 'מנהל מערכת', role: 'admin', branch: '' },
            { id: '2', username: 'helga', password: hashPw('helga2026'), name: 'הלגה רקנטי', role: 'client', branch: '' },
        ]);
        console.log('[AUTH] Created default users (admin/admin123, helga/helga2026)');
    }
}

const sessions = new Map();

function createSession(user) {
    const sid = crypto.randomBytes(24).toString('hex');
    sessions.set(sid, { userId: user.id, role: user.role, branch: user.branch, name: user.name, created: Date.now() });
    return sid;
}

function getSession(req) {
    const cookies = (req.headers.cookie || '').split(';').reduce((o, c) => {
        const [k, v] = c.trim().split('=');
        if (k) o[k] = v;
        return o;
    }, {});
    const sid = cookies['sid'];
    if (!sid) return null;
    const sess = sessions.get(sid);
    if (!sess) return null;
    if (Date.now() - sess.created > 24 * 60 * 60 * 1000) { sessions.delete(sid); return null; }
    return sess;
}

function readBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
    });
}

function json(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

const PUBLIC = ['/login.html', '/favicon.ico'];
const AUTH_ROUTES = ['/auth/login', '/auth/logout', '/auth/me', '/auth/users', '/auth/users/create', '/auth/users/update', '/auth/users/delete', '/auth/targets', '/auth/targets/update'];

initUsers();

const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    // ── Auth Routes ──
    if (pathname === '/auth/login' && req.method === 'POST') {
        const body = await readBody(req);
        const users = loadUsers();
        const user = users.find(u => u.username === body.username && u.password === hashPw(body.password));
        if (!user) return json(res, 401, { error: 'שם משתמש או סיסמה שגויים' });
        const sid = createSession(user);
        res.setHeader('Set-Cookie', `sid=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`);
        return json(res, 200, { name: user.name, role: user.role, branch: user.branch });
    }

    if (pathname === '/auth/logout') {
        res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; Max-Age=0');
        return json(res, 200, { ok: true });
    }

    if (pathname === '/auth/me') {
        const sess = getSession(req);
        if (!sess) return json(res, 401, { error: 'not logged in' });
        return json(res, 200, { name: sess.name, role: sess.role, branch: sess.branch });
    }

    if (pathname === '/auth/users' && req.method === 'GET') {
        const sess = getSession(req);
        if (!sess || sess.role !== 'admin') return json(res, 403, { error: 'forbidden' });
        const users = loadUsers().map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, branch: u.branch }));
        return json(res, 200, users);
    }

    if (pathname === '/auth/users/create' && req.method === 'POST') {
        const sess = getSession(req);
        if (!sess || sess.role !== 'admin') return json(res, 403, { error: 'forbidden' });
        const body = await readBody(req);
        if (!body.username || !body.password) return json(res, 400, { error: 'missing fields' });
        const users = loadUsers();
        if (users.find(u => u.username === body.username)) return json(res, 400, { error: 'שם משתמש כבר קיים' });
        const newUser = { id: crypto.randomBytes(8).toString('hex'), username: body.username, password: hashPw(body.password), name: body.name || body.username, role: body.role || 'client', branch: body.branch || '' };
        users.push(newUser);
        saveUsers(users);
        return json(res, 200, { id: newUser.id, username: newUser.username, name: newUser.name, role: newUser.role, branch: newUser.branch });
    }

    if (pathname === '/auth/users/update' && req.method === 'POST') {
        const sess = getSession(req);
        if (!sess || sess.role !== 'admin') return json(res, 403, { error: 'forbidden' });
        const body = await readBody(req);
        const users = loadUsers();
        const user = users.find(u => u.id === body.id);
        if (!user) return json(res, 404, { error: 'user not found' });
        if (body.name) user.name = body.name;
        if (body.role) user.role = body.role;
        if (body.branch !== undefined) user.branch = body.branch;
        if (body.password) user.password = hashPw(body.password);
        saveUsers(users);
        return json(res, 200, { ok: true });
    }

    if (pathname === '/auth/users/delete' && req.method === 'POST') {
        const sess = getSession(req);
        if (!sess || sess.role !== 'admin') return json(res, 403, { error: 'forbidden' });
        const body = await readBody(req);
        let users = loadUsers();
        users = users.filter(u => u.id !== body.id);
        saveUsers(users);
        return json(res, 200, { ok: true });
    }

    if (pathname === '/auth/targets' && req.method === 'GET') {
        const sess = getSession(req);
        if (!sess) return json(res, 401, { error: 'not authenticated' });
        return json(res, 200, loadTargets());
    }

    if (pathname === '/auth/targets/update' && req.method === 'POST') {
        const sess = getSession(req);
        if (!sess || sess.role !== 'admin') return json(res, 403, { error: 'forbidden' });
        const body = await readBody(req);
        const targets = loadTargets();
        if (body.meetRate !== undefined) targets.meetRate = Math.max(0, Math.min(100, Number(body.meetRate) || 0));
        if (body.arrRate !== undefined) targets.arrRate = Math.max(0, Math.min(100, Number(body.arrRate) || 0));
        if (body.dealRate !== undefined) targets.dealRate = Math.max(0, Math.min(100, Number(body.dealRate) || 0));
        saveTargets(targets);
        return json(res, 200, targets);
    }

    // ── Protected pages ──
    if (!pathname.startsWith('/api/') && !AUTH_ROUTES.includes(pathname) && !PUBLIC.includes(pathname)) {
        const sess = getSession(req);
        if (!sess) {
            if (pathname === '/' || pathname.endsWith('.html')) {
                res.writeHead(302, { 'Location': '/login.html' });
                res.end();
                return;
            }
        }
    }

    // ── API Proxy ──
    if (pathname.startsWith('/api/')) {
        const sess = getSession(req);
        if (!sess) return json(res, 401, { error: 'not authenticated' });

        const apiPath = pathname.replace(/^\/api/, '');
        const queryString = parsedUrl.search || '';
        const targetUrl = `${CTM_API_BASE}/api/v1/accounts/${ACCOUNT_ID}${apiPath}${queryString}`;
        const t0 = Date.now();
        console.log(`[API] ${req.method} ${apiPath}${queryString} (${sess.name})`);

        const targetParsed = url.parse(targetUrl);
        const options = {
            hostname: targetParsed.hostname, port: 443, path: targetParsed.path, method: req.method,
            headers: { 'Authorization': CTM_AUTH, 'Content-Type': 'application/json', 'Accept': 'application/json' }
        };

        const cacheKey = targetUrl;
        const cached = cache.get(cacheKey);
        if (cached && Date.now() - cached.time < CACHE_TTL) {
            console.log(`[CACHE] HIT (${Math.round((Date.now()-cached.time)/1000)}s old)`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(cached.body);
            return;
        }

        const isCallsEndpoint = apiPath.includes('/calls');
        const proxyReq = https.request(options, (proxyRes) => {
            console.log(`[API] → ${proxyRes.statusCode} (${Date.now()-t0}ms)`);
            if (isCallsEndpoint && proxyRes.statusCode === 200) {
                let body = '';
                proxyRes.on('data', chunk => body += chunk);
                proxyRes.on('end', () => {
                    try {
                        const data = JSON.parse(body);
                        if (data.calls) {
                            const KEEP = ['id','called_at','name','direction','dial_status','source',
                                'tag_list','custom_fields','is_new_caller','caller_number_bare',
                                'talk_time','duration','business_label','tracking_label','email',
                                'unix_time','form','campaign','web_source','day','hour',
                                'caller_number_format','audio','ring_time','call_path',
                                'referrer','location','webvisit'];
                            data.calls = data.calls.map(c => {
                                const slim = {};
                                KEEP.forEach(k => { if (c[k] !== undefined) slim[k] = c[k]; });
                                if (slim.form) {
                                    const custom = (slim.form.custom || []).reduce((o,f) => { o[f.id] = f.value; return o; }, {});
                                    slim.form = {
                                        form_name: slim.form.form_name || '', name: slim.form.name || '',
                                        campaign_name: custom.api_campaign_name || '', adset_name: custom.api_adset_name || '',
                                        ad_name: custom.api_ad_name || '', platform: custom.api_platform || '',
                                    };
                                }
                                return slim;
                            });
                        }
                        const out = JSON.stringify(data);
                        console.log(`[API] Stripped: ${body.length} → ${out.length} bytes`);
                        cache.set(cacheKey, { body: out, time: Date.now() });
                        persistCache();
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(out);
                    } catch(e) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(body);
                    }
                });
            } else {
                res.writeHead(proxyRes.statusCode, { 'Content-Type': proxyRes.headers['content-type'] || 'application/json' });
                proxyRes.pipe(res);
            }
        });
        proxyReq.on('error', (err) => { json(res, 502, { error: err.message }); });
        if (req.method === 'POST' || req.method === 'PUT') { req.pipe(proxyReq); } else { proxyReq.end(); }
        return;
    }

    // ── Static Files ──
    if (pathname === '/.cache.json' || pathname === '/users.json' || pathname === '/targets.json') {
        res.writeHead(404); res.end('Not Found'); return;
    }
    let filePath = pathname === '/' ? '/dashboard.html' : pathname;
    filePath = path.join(__dirname, filePath);
    const ext = path.extname(filePath);
    const mime = { '.html':'text/html', '.css':'text/css', '.js':'application/javascript',
                   '.json':'application/json', '.png':'image/png', '.jpg':'image/jpeg', '.svg':'image/svg+xml' };

    fs.readFile(filePath, (err, data) => {
        if (err) { res.writeHead(404); res.end('Not Found'); return; }
        res.writeHead(200, { 'Content-Type': mime[ext] || 'text/plain' });
        res.end(data);
    });
});

server.listen(PORT, () => {
    console.log(`\n  Dashboard: http://localhost:${PORT}\n`);
});
