const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const crypto = require('crypto'); 

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); 
app.use(express.static('public')); 
app.use(session({ secret: 'super-secret-bank-key', resave: false, saveUninitialized: false }));

// ==========================================
// DATABASE SETUP (SQLite)
// ==========================================
let db;
async function initDB() {
    const dbPath = process.env.RAILWAY_ENVIRONMENT ? '/data/shmuper.db' : './shmuper.db';
    
    db = await open({ filename: dbPath, driver: sqlite3.Database });
    
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, initial_password TEXT, is_admin INTEGER DEFAULT 0, status TEXT DEFAULT 'PENDING');
        CREATE TABLE IF NOT EXISTS profiles (user_id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT, street TEXT, city TEXT, state TEXT, postal_code TEXT, country TEXT);
        CREATE TABLE IF NOT EXISTS accounts (
            user_id INTEGER PRIMARY KEY, iban TEXT, swift TEXT, btc_address TEXT, eth_address TEXT, 
            fiat_cents INTEGER DEFAULT 0, btc_sats INTEGER DEFAULT 0, eth_sats INTEGER DEFAULT 0, hisa_cents INTEGER DEFAULT 0,
            btc_status TEXT DEFAULT 'INACTIVE', eth_status TEXT DEFAULT 'INACTIVE', hisa_status TEXT DEFAULT 'INACTIVE'
        );
        CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, direction TEXT, currency TEXT, amount TEXT, raw_amount REAL, status TEXT, date TEXT);
        CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, sender TEXT, content TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
    `);

    try { await db.exec("ALTER TABLE accounts ADD COLUMN hisa_tier TEXT DEFAULT 'Standard'"); } catch (e) {}
    try { await db.exec("ALTER TABLE accounts ADD COLUMN account_tier TEXT DEFAULT 'Basic'"); } catch (e) {}
    try { await db.exec("ALTER TABLE accounts ADD COLUMN tier_status TEXT DEFAULT 'ACTIVE'"); } catch (e) {}
    try { await db.exec("ALTER TABLE accounts ADD COLUMN requested_tier TEXT DEFAULT ''"); } catch (e) {}

    const adminExists = await db.get('SELECT * FROM users WHERE username = ?', ['admin']);
    if (!adminExists) {
        const adminHash = await bcrypt.hash('admin123', 10);
        await db.run('INSERT INTO users (username, password, initial_password, is_admin, status) VALUES (?, ?, ?, 1, ?)', ['admin', adminHash, 'admin123', 'ACTIVE']);
        console.log("🛡️ Master Admin account created!");
    }
    console.log("🗄️ Local Database Ready! (Venra Bank Engine)");
}
initDB();

// ==========================================
// SECURITY MIDDLEWARE
// ==========================================
function requireAuth(req, res, next) { if (!req.session.userId) return res.redirect('/login'); next(); }
async function requireAdmin(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    const user = await db.get('SELECT is_admin FROM users WHERE id = ?', [req.session.userId]);
    if (!user || user.is_admin !== 1) return res.redirect('/dashboard'); 
    next();
}

// ==========================================
// PUBLIC & AUTH ROUTES
// ==========================================
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // BACKEND NORMALIZE: Trim spaces and force completely lowercase
    const cleanUsername = username.trim().toLowerCase();
    
    const user = await db.get('SELECT * FROM users WHERE username = ?', [cleanUsername]);
    if (user && await bcrypt.compare(password, user.password)) {
        if (user.status === 'LOCKED' && user.is_admin !== 1) return res.render('login', { error: `Account is LOCKED. Please contact support.` });
        req.session.userId = user.id;
        if (user.is_admin === 1) return res.redirect('/admin');
        res.redirect('/dashboard');
    } else { res.render('login', { error: "Invalid username or password" }); }
});

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
    const { username, password, confirm_password, full_name, email, phone, street, city, state, postal_code, country } = req.body;
    
    // BACKEND NORMALIZE: Trim spaces and force completely lowercase
    const cleanUsername = username.trim().toLowerCase();
    
    // BACKEND VALIDATION: Strictly reject anything that isn't a letter or number
    const usernameRegex = /^[a-z0-9]+$/;
    if (!usernameRegex.test(cleanUsername)) {
        return res.render('register', { error: "Username can only contain letters and numbers. No spaces or special symbols allowed." });
    }

    if (password !== confirm_password) return res.render('register', { error: "Passwords do not match." });
    const existing = await db.get('SELECT * FROM users WHERE username = ?', [cleanUsername]);
    if (existing) return res.render('register', { error: "Username already taken." });
    
    const hash = await bcrypt.hash(password, 10);
    try {
        const result = await db.run('INSERT INTO users (username, password, initial_password, status) VALUES (?, ?, ?, ?)', [cleanUsername, hash, password, 'PENDING']);
        const newId = result.lastID;
        await db.run('INSERT INTO profiles (user_id, full_name, email, phone, street, city, state, postal_code, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [newId, full_name, email, phone, street, city, state, postal_code, country]);
        
        const iban = "VEN" + Math.floor(Math.random() * 100000000000);
        const btc_address = "bc1q" + crypto.randomBytes(20).toString('hex');
        const eth_address = "0x" + crypto.randomBytes(20).toString('hex');

        await db.run('INSERT INTO accounts (user_id, iban, swift, btc_address, eth_address, fiat_cents, btc_sats, eth_sats, hisa_cents, btc_status, eth_status, hisa_status, hisa_tier, account_tier, tier_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
            [newId, iban, 'VENRAXX', btc_address, eth_address, 0, 0, 0, 0, 'INACTIVE', 'INACTIVE', 'INACTIVE', 'Standard', 'Basic', 'ACTIVE']); 

        req.session.userId = newId;
        res.redirect('/dashboard');
    } catch (err) { res.render('register', { error: "System error during registration." }); }
});
app.post('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

// ==========================================
// USER APP ROUTES
// ==========================================
async function getUserData(userId) {
    const user = await db.get('SELECT username, id, status FROM users WHERE id = ?', [userId]);
    const profile = await db.get('SELECT * FROM profiles WHERE user_id = ?', [userId]);
    const account = await db.get('SELECT * FROM accounts WHERE user_id = ?', [userId]);
    const txs = await db.all('SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC', [userId]);
    const formattedTxs = txs.map(tx => ({ name: tx.name, detail: tx.currency === 'EUR' ? 'Bank Transfer' : (tx.currency==='HISA' ? 'Internal Transfer' : 'Network Transfer'), direction: tx.direction, amountStr: tx.amount, date: tx.date, icon: tx.currency === 'EUR' || tx.currency === 'HISA' ? '💶' : (tx.currency === 'BTC' ? '₿' : '⟠'), status: tx.status }));

    let dailyLimit = 10000;
    if (account && account.account_tier === 'Standard') dailyLimit = 50000;
    if (account && account.account_tier === 'Premium') dailyLimit = 100000;
    if (account && account.account_tier === 'VIP') dailyLimit = 250000;

    return {
        username: user.username, userId: user.id, userStatus: user.status, profile: profile || {},
        fiatBalance: account ? account.fiat_cents / 100 : 0, 
        btcBalance: account ? account.btc_sats / 100000000 : 0, 
        ethBalance: account ? account.eth_sats / 100000000 : 0,
        hisaBalance: account ? account.hisa_cents / 100 : 0,
        account: account ? { 
            tier: account.account_tier || 'Basic', 
            account_tier: account.account_tier || 'Basic',
            tier_status: account.tier_status || 'ACTIVE',
            requested_tier: account.requested_tier || '',
            daily_limit: dailyLimit,
            balance: account.fiat_cents, name: profile ? profile.full_name : user.username, 
            iban: account.iban, swift: account.swift, 
            btc_address: account.btc_address, btc_status: account.btc_status, 
            eth_address: account.eth_address, eth_status: account.eth_status,
            hisa_status: account.hisa_status, hisa_tier: account.hisa_tier || 'Standard'
        } : {},
        transactions: formattedTxs
    };
}

app.get('/dashboard', requireAuth, async (req, res) => res.render('dashboard', await getUserData(req.session.userId)));
app.get('/account', requireAuth, async (req, res) => res.render('account', await getUserData(req.session.userId)));
app.post('/account/upgrade', requireAuth, async (req, res) => { await db.run('UPDATE accounts SET tier_status = ?, requested_tier = ? WHERE user_id = ?', ['PENDING', req.body.tier, req.session.userId]); res.redirect('/account'); });
app.get('/transfers', requireAuth, async (req, res) => res.render('transfers', await getUserData(req.session.userId)));
app.get('/receive', requireAuth, async (req, res) => res.render('receive', await getUserData(req.session.userId)));

app.get('/send', requireAuth, async (req, res) => {
    const data = await getUserData(req.session.userId);
    data.error = req.query.error || null;
    res.render('send', data);
});

app.get('/support', requireAuth, async (req, res) => res.render('support', await getUserData(req.session.userId)));
app.get('/hisa', requireAuth, async (req, res) => res.render('hisa', await getUserData(req.session.userId)));
app.post('/hisa/activate', requireAuth, async (req, res) => { await db.run('UPDATE accounts SET hisa_status = ? WHERE user_id = ?', ['PENDING', req.session.userId]); res.redirect('/hisa'); });

app.post('/transfer/internal', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const userCheck = await db.get('SELECT status FROM users WHERE id = ?', [userId]);
    if (userCheck.status === 'SUSPENDED' || userCheck.status === 'PENDING') return res.redirect('/hisa');

    const { amount, from_account, to_account } = req.body;
    const numAmount = parseFloat(amount);
    const cents = Math.round(numAmount * 100);
    const account = await db.get('SELECT * FROM accounts WHERE user_id = ?', [userId]);
    const today = new Date().toLocaleDateString();

    if (cents > 0) {
        if (from_account === 'main' && to_account === 'hisa' && account.fiat_cents >= cents && account.hisa_status === 'ACTIVE') {
            await db.run('UPDATE accounts SET fiat_cents = fiat_cents - ?, hisa_cents = hisa_cents + ? WHERE user_id = ?', [cents, cents, userId]);
            await db.run('INSERT INTO transactions (user_id, name, direction, currency, amount, raw_amount, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [userId, 'Transfer to Savings', 'OUTGOING', 'HISA', `${numAmount.toLocaleString('en-US', {minimumFractionDigits: 2})} EUR`, numAmount, 'COMPLETED', today]);
        } else if (from_account === 'hisa' && to_account === 'main' && account.hisa_cents >= cents) {
            await db.run('UPDATE accounts SET hisa_cents = hisa_cents - ?, fiat_cents = fiat_cents + ? WHERE user_id = ?', [cents, cents, userId]);
            await db.run('INSERT INTO transactions (user_id, name, direction, currency, amount, raw_amount, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [userId, 'Transfer from Savings', 'INCOMING', 'HISA', `${numAmount.toLocaleString('en-US', {minimumFractionDigits: 2})} EUR`, numAmount, 'COMPLETED', today]);
        }
    }
    res.redirect('/hisa');
});

app.get('/api/chat', requireAuth, async (req, res) => { res.json(await db.all('SELECT * FROM messages WHERE user_id = ? ORDER BY id ASC', [req.session.userId])); });
app.post('/api/chat', requireAuth, async (req, res) => {
    if (req.body.content.trim()) await db.run('INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)', [req.session.userId, 'user', req.body.content]);
    res.json({ success: true });
});

app.get('/profile', requireAuth, async (req, res) => { const data = await getUserData(req.session.userId); res.render('profile', { user: data, profile: data.profile, msg: req.query.msg }); });
app.post('/profile', requireAuth, async (req, res) => {
    const { full_name, email, phone, street, city, state, postal_code, country } = req.body;
    await db.run('UPDATE profiles SET full_name=?, email=?, phone=?, street=?, city=?, state=?, postal_code=?, country=? WHERE user_id=?', [full_name, email, phone, street, city, state, postal_code, country, req.session.userId]);
    res.redirect('/profile?msg=Profile Updated');
});
app.post('/profile/password', requireAuth, async (req, res) => {
    const { current_password, new_password, confirm_password } = req.body;
    if (new_password !== confirm_password) return res.redirect('/profile?msg=Passwords Do Not Match');
    const user = await db.get('SELECT password FROM users WHERE id = ?', [req.session.userId]);
    if (await bcrypt.compare(current_password, user.password)) {
        await db.run('UPDATE users SET password = ? WHERE id = ?', [await bcrypt.hash(new_password, 10), req.session.userId]);
        res.redirect('/profile?msg=Password Changed Successfully');
    } else { res.redirect('/profile?msg=Incorrect Current Password'); }
});

app.post('/send', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const userCheck = await db.get('SELECT status FROM users WHERE id = ?', [userId]);
    if (userCheck.status === 'SUSPENDED' || userCheck.status === 'PENDING') return res.redirect('/send');

    const { amount, recipient_name, crypto_address, currency_type } = req.body;
    const account = await db.get('SELECT * FROM accounts WHERE user_id = ?', [userId]);
    const today = new Date().toLocaleDateString();
    const numAmount = parseFloat(amount);

    if (isNaN(numAmount) || numAmount <= 0) {
        return res.redirect('/send?error=Please enter a valid amount.');
    }

    let dailyLimit = 10000;
    if (account.account_tier === 'Standard') dailyLimit = 50000;
    if (account.account_tier === 'Premium') dailyLimit = 100000;
    if (account.account_tier === 'VIP') dailyLimit = 250000;

    const todaysTxs = await db.all('SELECT raw_amount FROM transactions WHERE user_id = ? AND date = ? AND direction = ? AND currency = ? AND status != ?', [userId, today, 'OUTGOING', 'EUR', 'DECLINED']);
    let sentToday = 0;
    todaysTxs.forEach(tx => { sentToday += tx.raw_amount; });

    if (currency_type === 'btc' && account.btc_status === 'ACTIVE') {
        const sats = Math.round(numAmount * 100000000);
        if (account.btc_sats < sats) return res.redirect('/send?error=Insufficient Bitcoin balance for this transfer.');
        await db.run('UPDATE accounts SET btc_sats = btc_sats - ? WHERE user_id = ?', [sats, userId]);
        await db.run('INSERT INTO transactions (user_id, name, direction, currency, amount, raw_amount, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [userId, 'Network Transfer', 'OUTGOING', 'BTC', `${numAmount} BTC`, numAmount, 'PENDING', today]);
        
    } else if (currency_type === 'eth' && account.eth_status === 'ACTIVE') {
        const sats = Math.round(numAmount * 100000000);
        if (account.eth_sats < sats) return res.redirect('/send?error=Insufficient Ethereum balance for this transfer.');
        await db.run('UPDATE accounts SET eth_sats = eth_sats - ? WHERE user_id = ?', [sats, userId]);
        await db.run('INSERT INTO transactions (user_id, name, direction, currency, amount, raw_amount, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [userId, 'Network Transfer', 'OUTGOING', 'ETH', `${numAmount} ETH`, numAmount, 'PENDING', today]);
        
    } else if (currency_type === 'eur') {
        const cents = Math.round(numAmount * 100);
        if (account.fiat_cents < cents) return res.redirect('/send?error=Insufficient EUR balance for this transfer.');
        if ((sentToday + numAmount) > dailyLimit) return res.redirect(`/send?error=Daily transfer limit of €${dailyLimit.toLocaleString()} exceeded. Please request a tier upgrade.`);
        await db.run('UPDATE accounts SET fiat_cents = fiat_cents - ? WHERE user_id = ?', [cents, userId]);
        await db.run('INSERT INTO transactions (user_id, name, direction, currency, amount, raw_amount, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [userId, recipient_name || 'Bank Transfer', 'OUTGOING', 'EUR', `${numAmount.toLocaleString('en-US', {minimumFractionDigits: 2})} EUR`, numAmount, 'PENDING', today]);
    }
    res.redirect('/transfers');
});

// ==========================================
// ADMIN ROUTES (GOD MODE)
// ==========================================
app.get('/admin', requireAdmin, async (req, res) => {
    const userCount = await db.get('SELECT COUNT(*) as count FROM users WHERE is_admin = 0');
    const volume = await db.get('SELECT SUM(fiat_cents) + SUM(hisa_cents) as totalFiat, SUM(btc_sats) as totalBtc, SUM(eth_sats) as totalEth FROM accounts');
    const pendingTxs = await db.all(`SELECT t.id, t.user_id, u.username, p.full_name, t.currency, t.amount, t.direction, t.name as tx_detail FROM transactions t JOIN users u ON t.user_id = u.id LEFT JOIN profiles p ON u.id = p.user_id WHERE t.status = 'PENDING' ORDER BY t.id DESC`);
    const recentUsers = await db.all(`SELECT u.id, u.username, u.status as acc_status, a.fiat_cents, a.hisa_cents, a.btc_status FROM users u LEFT JOIN accounts a ON u.id = a.user_id WHERE u.is_admin = 0 ORDER BY u.id DESC LIMIT 10`);
    res.render('admin', { stats: { totalUsers: userCount.count, totalFiat: volume.totalFiat || 0, totalBtc: volume.totalBtc || 0, totalEth: volume.totalEth || 0, pendingCount: pendingTxs.length }, pendingTxs: pendingTxs, recentUsers: recentUsers });
});

app.get('/admin/users', requireAdmin, async (req, res) => {
    const allUsers = await db.all(`SELECT u.id, u.username, u.status, p.full_name, p.email, a.fiat_cents, a.btc_status, a.eth_status, a.hisa_status FROM users u LEFT JOIN profiles p ON u.id = p.user_id LEFT JOIN accounts a ON u.id = a.user_id WHERE u.is_admin = 0 ORDER BY u.id DESC`);
    res.render('admin-users', { users: allUsers });
});

app.get('/admin/user/:id', requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const user = await db.get('SELECT id, username, status, initial_password FROM users WHERE id = ?', [userId]);
    const profile = await db.get('SELECT * FROM profiles WHERE user_id = ?', [userId]);
    const account = await db.get('SELECT * FROM accounts WHERE user_id = ?', [userId]);
    const txs = await db.all('SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC', [userId]);
    if(!user) return res.redirect('/admin/users');
    res.render('admin-user-edit', { client: user, profile: profile, account: account, txs: txs });
});

app.post('/admin/user/:id/edit', requireAdmin, async (req, res) => {
    const { full_name, email, phone, street, city, state, postal_code, country, iban, swift, fiat_balance, hisa_balance, btc_balance, eth_balance } = req.body;
    const userId = req.params.id;
    await db.run('UPDATE profiles SET full_name=?, email=?, phone=?, street=?, city=?, state=?, postal_code=?, country=? WHERE user_id=?', [full_name, email, phone, street, city, state, postal_code, country, userId]);
    await db.run('UPDATE accounts SET iban=?, swift=?, fiat_cents=?, hisa_cents=?, btc_sats=?, eth_sats=? WHERE user_id=?', [iban, swift, Math.round(parseFloat(fiat_balance)*100), Math.round(parseFloat(hisa_balance)*100), Math.round(parseFloat(btc_balance)*100000000), Math.round(parseFloat(eth_balance)*100000000), userId]);
    res.redirect(`/admin/user/${userId}`);
});

app.post('/admin/user/:id/status', requireAdmin, async (req, res) => { await db.run('UPDATE users SET status = ? WHERE id = ?', [req.body.status, req.params.id]); res.redirect(`/admin/user/${req.params.id}`); });
app.post('/admin/user/:id/password', requireAdmin, async (req, res) => { await db.run('UPDATE users SET password = ? WHERE id = ?', [await bcrypt.hash(req.body.new_password, 10), req.params.id]); res.redirect(`/admin/user/${req.params.id}`); });

app.post('/admin/user/:id/toggle/:coin', requireAdmin, async (req, res) => {
    let column = 'btc_status';
    if(req.params.coin === 'eth') column = 'eth_status';
    if(req.params.coin === 'hisa') column = 'hisa_status';
    await db.run(`UPDATE accounts SET ${column} = ? WHERE user_id = ?`, [req.body.current_status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE', req.params.id]);
    res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/user/:id/toggle_tier', requireAdmin, async (req, res) => {
    await db.run('UPDATE accounts SET hisa_tier = ? WHERE user_id = ?', [req.body.current_tier === 'Premium' ? 'Standard' : 'Premium', req.params.id]);
    res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/user/:id/approve_tier', requireAdmin, async (req, res) => {
    const acc = await db.get('SELECT requested_tier FROM accounts WHERE user_id = ?', [req.params.id]);
    if(acc && acc.requested_tier) { await db.run('UPDATE accounts SET account_tier = ?, tier_status = ?, requested_tier = ? WHERE user_id = ?', [acc.requested_tier, 'ACTIVE', '', req.params.id]); }
    res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/user/:id/reject_tier', requireAdmin, async (req, res) => {
    await db.run('UPDATE accounts SET tier_status = ?, requested_tier = ? WHERE user_id = ?', ['ACTIVE', '', req.params.id]);
    res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/user/:id/set_tier', requireAdmin, async (req, res) => {
    await db.run('UPDATE accounts SET account_tier = ?, tier_status = ?, requested_tier = ? WHERE user_id = ?', [req.body.account_tier, 'ACTIVE', '', req.params.id]);
    res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/user/:id/inject', requireAdmin, async (req, res) => {
    const { amount, currency, sender_name, sender_iban } = req.body;
    const numAmount = parseFloat(amount);
    const today = new Date().toLocaleDateString();
    let txName = sender_name || 'External Transfer';
    if (sender_iban) txName += ` • ${sender_iban}`;
    let amountStr = '';
    if (currency === 'EUR') amountStr = `${numAmount.toLocaleString('en-US', {minimumFractionDigits: 2})} EUR`;
    else if (currency === 'BTC') amountStr = `${numAmount} BTC`;
    else if (currency === 'ETH') amountStr = `${numAmount} ETH`;
    await db.run('INSERT INTO transactions (user_id, name, direction, currency, amount, raw_amount, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [req.params.id, txName, 'INCOMING', currency, amountStr, numAmount, 'PENDING', today]);
    res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/tx/:id/approve', requireAdmin, async (req, res) => {
    const tx = await db.get('SELECT * FROM transactions WHERE id = ?', [req.params.id]);
    if (tx && tx.status === 'PENDING') {
        if (tx.direction === 'INCOMING') {
            if (tx.currency === 'BTC') await db.run('UPDATE accounts SET btc_sats = btc_sats + ? WHERE user_id = ?', [Math.round(tx.raw_amount*100000000), tx.user_id]);
            else if (tx.currency === 'ETH') await db.run('UPDATE accounts SET eth_sats = eth_sats + ? WHERE user_id = ?', [Math.round(tx.raw_amount*100000000), tx.user_id]);
            else await db.run('UPDATE accounts SET fiat_cents = fiat_cents + ? WHERE user_id = ?', [Math.round(tx.raw_amount*100), tx.user_id]);
        }
        await db.run('UPDATE transactions SET status = ? WHERE id = ?', ['COMPLETED', req.params.id]);
    }
    res.redirect(req.get('referer') || '/admin/users');
});

app.post('/admin/tx/:id/decline', requireAdmin, async (req, res) => {
    const tx = await db.get('SELECT * FROM transactions WHERE id = ?', [req.params.id]);
    if (tx && tx.status === 'PENDING') {
        if (tx.direction === 'OUTGOING') {
            if (tx.currency === 'BTC') await db.run('UPDATE accounts SET btc_sats = btc_sats + ? WHERE user_id = ?', [Math.round(tx.raw_amount*100000000), tx.user_id]);
            else if (tx.currency === 'ETH') await db.run('UPDATE accounts SET eth_sats = eth_sats + ? WHERE user_id = ?', [Math.round(tx.raw_amount*100000000), tx.user_id]);
            else await db.run('UPDATE accounts SET fiat_cents = fiat_cents + ? WHERE user_id = ?', [Math.round(tx.raw_amount*100), tx.user_id]);
        }
        await db.run('UPDATE transactions SET status = ? WHERE id = ?', ['DECLINED', req.params.id]);
    }
    res.redirect(req.get('referer') || '/admin/users');
});

app.post('/admin/tx/:id/delete', requireAdmin, async (req, res) => {
    await db.run('DELETE FROM transactions WHERE id = ?', [req.params.id]);
    res.redirect(req.get('referer') || '/admin/users');
});

app.post('/admin/user/:id/delete', requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const user = await db.get('SELECT is_admin FROM users WHERE id = ?', [userId]);
    if (user && user.is_admin === 0) {
        await db.run('DELETE FROM users WHERE id = ?', [userId]);
        await db.run('DELETE FROM profiles WHERE user_id = ?', [userId]);
        await db.run('DELETE FROM accounts WHERE user_id = ?', [userId]);
        await db.run('DELETE FROM transactions WHERE user_id = ?', [userId]);
        await db.run('DELETE FROM messages WHERE user_id = ?', [userId]);
    }
    res.redirect('/admin/users');
});

app.get('/admin/comms', requireAdmin, async (req, res) => { res.render('admin-comms', { users: await db.all(`SELECT u.id, u.username, (SELECT content FROM messages WHERE user_id = u.id ORDER BY id DESC LIMIT 1) as last_msg FROM users u WHERE u.is_admin = 0`) }); });
app.get('/admin/api/chat/:userId', requireAdmin, async (req, res) => { res.json(await db.all('SELECT * FROM messages WHERE user_id = ? ORDER BY id ASC', [req.params.userId])); });
app.post('/admin/api/chat/:userId', requireAdmin, async (req, res) => { if (req.body.content.trim()) await db.run('INSERT INTO messages (user_id, sender, content) VALUES (?, ?, ?)', [req.params.userId, 'admin', req.body.content]); res.json({ success: true }); });

app.listen(PORT, () => console.log(`🚀 VENRA BANK LIVE on http://localhost:${PORT}`));