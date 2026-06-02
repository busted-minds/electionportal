// Busted Minds Election Portal
// File: server.js
// Run: npm install express dotenv multer && node server.js

require('dotenv').config();

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'busted-minds-secret';

const uploadsDir = process.env.UPLOADS_DIR || path.join(__dirname, 'uploads');
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
const votesFile = path.join(dataDir, 'votes.json');

fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(dataDir, { recursive: true });

if (!fs.existsSync(votesFile)) {
  fs.writeFileSync(votesFile, '[]');
}

app.use(express.json({ limit: '2mb' }));
app.use('/uploads', express.static(uploadsDir));

const members = [
  'pravin',
  'amirthan',
  'aniruddhan',
  'charan',
  'mukilan',
  'kalai',
  'yasar',
  'test'
];

const users = Object.fromEntries(
  members.map((name) => [name, process.env[`PIN_${name.toUpperCase()}`]])
);

const parties = [
  {
    id: 'rbm',
    party: 'Republic Party of Busted Minds',
    candidate: 'Mukilan R',
    symbol: '🧿',
    color: '#38bdf8'
  },
  {
    id: 'blood-hounds',
    party: 'Blood Hounds',
    candidate: 'Charan',
    symbol: '🥊',
    color: '#fb7185'
  },
  {
    id: 'vanguard',
    party: 'Vanguard',
    candidate: 'A. Amirtha Narayanan',
    symbol: '🛡️',
    color: '#a78bfa'
  }
];

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('base64url');

  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;

  const [body, sig] = token.split('.');
  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('base64url');

  if (sig !== expected) return null;

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.name || !members.includes(payload.name)) return null;
    return payload;
  } catch {
    return null;
  }
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = verifyToken(token);

  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  req.user = user;
  next();
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safeUser = req.user.name.replace(/[^a-z0-9_-]/gi, '');
    const stamp = Date.now();
    cb(null, `${safeUser}-${stamp}.webm`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Only video files are allowed'));
    }
  }
});

function escapeHtmlServer(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function safeJsonRead(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

app.get('/', (_req, res) => {
  res.type('html').send(html);
});

app.post('/api/login', (req, res) => {
  const name = String(req.body.name || '').trim().toLowerCase();
  const pin = String(req.body.pin || '').trim();

  if (!members.includes(name)) {
    return res.status(401).json({ error: 'Invalid member name' });
  }

  if (!users[name]) {
    return res.status(500).json({ error: `PIN for ${name} is missing in .env` });
  }

  if (users[name] !== pin) {
    return res.status(401).json({ error: 'Wrong PIN' });
  }

  const token = signToken({ name, loginAt: Date.now() });
  res.json({ token, name, parties });
});

app.get('/api/me', auth, (req, res) => {
  const votes = safeJsonRead(votesFile, []);
  const existingVote = votes.find((vote) => vote.name === req.user.name);

  res.json({
    name: req.user.name,
    parties,
    existingVote: existingVote || null
  });
});

app.post('/api/vote', auth, upload.single('video'), (req, res) => {
  const { partyId } = req.body;
  const selectedParty = parties.find((party) => party.id === partyId);

  if (!selectedParty) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Invalid party selected' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Video is required' });
  }

  const votes = safeJsonRead(votesFile, []);
  const existingIndex = votes.findIndex((vote) => vote.name === req.user.name);

  if (existingIndex !== -1) {
    if (req.file) fs.unlinkSync(req.file.path);

    return res.status(403).json({
      error: 'You have already voted. Votes cannot be changed.'
    });
  }

  const vote = {
    name: req.user.name,
    partyId: selectedParty.id,
    party: selectedParty.party,
    candidate: selectedParty.candidate,
    symbol: selectedParty.symbol,
    color: selectedParty.color,
    videoUrl: `/uploads/${req.file.filename}`,
    submittedAt: new Date().toISOString()
  };

  votes.push(vote);
  fs.writeFileSync(votesFile, JSON.stringify(votes, null, 2));

  res.json({ success: true, vote });
});

function requireAdmin(req, res, next) {
  const key = req.query.key || req.headers['x-admin-key'];

  if (!process.env.ADMIN_KEY) {
    return res.status(500).send('ADMIN_KEY is not set.');
  }

  if (key !== process.env.ADMIN_KEY) {
    return res.status(403).send('Forbidden');
  }

  next();
}

app.post('/admin/delete-vote', requireAdmin, (req, res) => {
  const name = String(req.body.name || '').trim().toLowerCase();

  if (!name) {
    return res.status(400).json({ error: 'Member name is required' });
  }

  const votes = safeJsonRead(votesFile, []);
  const vote = votes.find((item) => item.name === name);

  if (!vote) {
    return res.status(404).json({ error: 'No vote found for this member' });
  }

  if (vote.videoUrl) {
    const videoFile = path.basename(vote.videoUrl);
    const videoPath = path.join(uploadsDir, videoFile);

    if (fs.existsSync(videoPath)) {
      fs.unlinkSync(videoPath);
    }
  }

  const updatedVotes = votes.filter((item) => item.name !== name);
  fs.writeFileSync(votesFile, JSON.stringify(updatedVotes, null, 2));

  res.json({
    success: true,
    deleted: name
  });
});

app.get('/admin/results', requireAdmin, (req, res) => {
  const votes = safeJsonRead(votesFile, []);

  const counts = parties.map((party) => ({
    ...party,
    votes: votes.filter((vote) => vote.partyId === party.id).length
  }));

  const rows = votes.map((vote) => {
    const safeName = escapeHtmlServer(vote.name);
    const safeNameJson = JSON.stringify(vote.name);
    const safeSymbol = escapeHtmlServer(vote.symbol);
    const safeParty = escapeHtmlServer(vote.party);
    const safeCandidate = escapeHtmlServer(vote.candidate);
    const safeVideoUrl = escapeHtmlServer(vote.videoUrl);
    const safeSubmittedAt = escapeHtmlServer(
      vote.submittedAt ? new Date(vote.submittedAt).toLocaleString() : ''
    );

    return `
      <tr>
        <td><span class="member-pill">${safeName}</span></td>
        <td>${safeSymbol} ${safeParty}</td>
        <td>${safeCandidate}</td>
        <td>${safeSubmittedAt}</td>
        <td><a href="${safeVideoUrl}" target="_blank">Open video</a></td>
        <td>
          <button class="delete-btn" onclick='deleteVote(${safeNameJson})'>Delete</button>
        </td>
      </tr>
    `;
  }).join('');

  const countRows = counts.map((party) => {
    return `
      <tr>
        <td>${escapeHtmlServer(party.symbol)} ${escapeHtmlServer(party.party)}</td>
        <td>${escapeHtmlServer(party.candidate)}</td>
        <td>${party.votes}</td>
      </tr>
    `;
  }).join('');

  const countCards = counts.map((party) => {
    return `
      <div class="result-card" style="--party-color: ${escapeHtmlServer(party.color)};">
        <div class="result-symbol">${escapeHtmlServer(party.symbol)}</div>
        <div>
          <h3>${escapeHtmlServer(party.party)}</h3>
          <p>${escapeHtmlServer(party.candidate)}</p>
        </div>
        <strong>${party.votes}</strong>
      </div>
    `;
  }).join('');

  res.type('html').send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Results</title>
      <style>
        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        :root {
          --bg: #070711;
          --card: rgba(255,255,255,.1);
          --border: rgba(255,255,255,.18);
          --text: #f8fafc;
          --muted: #b8bfd7;
          --gold: #facc15;
          --cyan: #38bdf8;
          --rose: #fb7185;
          --green: #34d399;
        }

        body {
          min-height: 100vh;
          font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: var(--text);
          background:
            radial-gradient(circle at top left, rgba(56,189,248,.22), transparent 34%),
            radial-gradient(circle at top right, rgba(250,204,21,.18), transparent 30%),
            radial-gradient(circle at bottom, rgba(167,139,250,.2), transparent 35%),
            var(--bg);
          padding: 28px;
        }

        body::before {
          content: "";
          position: fixed;
          inset: 0;
          pointer-events: none;
          background-image:
            linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px);
          background-size: 36px 36px;
          opacity: .46;
        }

        .admin-shell {
          position: relative;
          z-index: 1;
          width: min(1120px, 100%);
          margin: 0 auto;
        }

        .admin-topbar {
          display: flex;
          justify-content: space-between;
          gap: 18px;
          align-items: center;
          padding: 18px 20px;
          border: 1px solid var(--border);
          border-radius: 28px;
          background: rgba(7,7,17,.72);
          box-shadow: 0 18px 60px rgba(0,0,0,.32);
          backdrop-filter: blur(18px);
          margin-bottom: 22px;
        }

        .admin-topbar p,
        .panel p,
        .result-card p {
          color: var(--muted);
          line-height: 1.5;
        }

        h1, h2 {
          letter-spacing: 0;
        }

        h1 {
          font-size: clamp(2rem, 5vw, 4.2rem);
          line-height: .95;
        }

        h2 {
          color: var(--gold);
          margin-bottom: 14px;
        }

        .admin-badge {
          padding: 10px 13px;
          border-radius: 999px;
          background: rgba(52,211,153,.12);
          border: 1px solid rgba(52,211,153,.34);
          color: #bbf7d0;
          font-weight: 950;
          white-space: nowrap;
        }

        .admin-note {
          padding: 15px 16px;
          border-radius: 18px;
          background: rgba(56,189,248,.1);
          border: 1px solid rgba(56,189,248,.25);
          color: #bae6fd;
          margin-bottom: 22px;
          line-height: 1.55;
          font-weight: 750;
        }

        .summary-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 14px;
          margin-bottom: 22px;
        }

        .result-card,
        .panel {
          border: 1px solid var(--border);
          background: linear-gradient(145deg, rgba(255,255,255,.13), rgba(255,255,255,.045));
          box-shadow: 0 28px 84px rgba(0,0,0,.34);
          backdrop-filter: blur(18px);
        }

        .result-card {
          min-height: 146px;
          padding: 18px;
          border-radius: 24px;
          display: grid;
          grid-template-columns: auto 1fr auto;
          align-items: center;
          gap: 14px;
          border-color: color-mix(in srgb, var(--party-color) 48%, rgba(255,255,255,.14));
        }

        .result-symbol {
          width: 56px;
          height: 56px;
          border-radius: 18px;
          display: grid;
          place-items: center;
          font-size: 2rem;
          background: color-mix(in srgb, var(--party-color) 18%, transparent);
          border: 1px solid color-mix(in srgb, var(--party-color) 34%, transparent);
        }

        .result-card h3 {
          font-size: 1rem;
          line-height: 1.2;
          margin-bottom: 6px;
        }

        .result-card strong {
          color: var(--gold);
          font-size: 2.4rem;
          line-height: 1;
        }

        .panel {
          border-radius: 28px;
          overflow: hidden;
          margin-bottom: 28px;
        }

        .panel-header {
          padding: 22px;
          border-bottom: 1px solid rgba(255,255,255,.12);
        }

        .table-wrap {
          overflow-x: auto;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          background: rgba(255,255,255,.045);
        }

        th, td {
          border-bottom: 1px solid rgba(255,255,255,.12);
          padding: 14px 16px;
          text-align: left;
          vertical-align: middle;
        }

        th {
          background: rgba(250,204,21,.14);
          color: #fde68a;
          font-size: .78rem;
          letter-spacing: 0;
          text-transform: uppercase;
        }

        a {
          color: var(--cyan);
          font-weight: 900;
          text-decoration: none;
        }

        .delete-btn {
          border: 0;
          border-radius: 14px;
          padding: 10px 13px;
          background: rgba(251,113,133,.24);
          border: 1px solid rgba(251,113,133,.42);
          color: white;
          font-weight: 950;
          cursor: pointer;
        }

        .delete-btn:hover {
          background: rgba(225,29,72,.78);
        }

        .member-pill {
          display: inline-flex;
          align-items: center;
          border-radius: 999px;
          padding: 7px 10px;
          background: rgba(52,211,153,.11);
          border: 1px solid rgba(52,211,153,.26);
          color: #bbf7d0;
          font-weight: 900;
        }

        @media (max-width: 860px) {
          body {
            padding: 18px;
          }

          .admin-topbar {
            align-items: flex-start;
            flex-direction: column;
          }

          .summary-grid {
            grid-template-columns: 1fr;
          }
        }
      </style>
    </head>
    <body>
      <main class="admin-shell">
        <div class="admin-topbar">
          <div>
            <h1>BMEC Results</h1>
            <p>Private Busted Minds vote control room.</p>
          </div>
          <div class="admin-badge">Admin verified</div>
        </div>

        <div class="admin-note">
          Admin mode is active. Use Delete only for testing or corrections.
        </div>

        <section class="summary-grid">
          ${countCards}
        </section>

        <section class="panel">
          <div class="panel-header">
            <h2>Vote Count</h2>
            <p>Live party totals from submitted verified videos.</p>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Party</th>
                  <th>Candidate</th>
                  <th>Votes</th>
                </tr>
              </thead>
              <tbody>
                ${countRows}
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <h2>Submitted Videos</h2>
            <p>Audit trail for each locked member ballot.</p>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Member</th>
                  <th>Party</th>
                  <th>Candidate</th>
                  <th>Submitted At</th>
                  <th>Video</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                ${rows || '<tr><td colspan="6">No votes yet.</td></tr>'}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      <script>
        async function deleteVote(name) {
          const confirmed = confirm('Delete vote for ' + name + '? This cannot be undone.');

          if (!confirmed) return;

          const params = new URLSearchParams(window.location.search);
          const key = params.get('key') || '';

          try {
            const res = await fetch('/admin/delete-vote?key=' + encodeURIComponent(key), {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ name })
            });

            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
              alert(data.error || 'Failed to delete vote');
              return;
            }

            alert('Deleted vote for ' + name);
            window.location.reload();
          } catch (err) {
            alert('Failed to delete vote: ' + err.message);
          }
        }
      </script>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log(`Busted Minds Election Portal running at http://localhost:${PORT}`);
});

const html = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Busted Minds Election Portal</title>

  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    :root {
      --bg: #070711;
      --card: rgba(255,255,255,.09);
      --card2: rgba(255,255,255,.14);
      --border: rgba(255,255,255,.18);
      --text: #f8fafc;
      --muted: #b8bfd7;
      --gold: #facc15;
      --cyan: #38bdf8;
      --rose: #fb7185;
      --violet: #a78bfa;
      --green: #34d399;
      --orange: #fb923c;
    }

    body {
      min-height: 100vh;
      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(56,189,248,.24), transparent 34%),
        radial-gradient(circle at top right, rgba(250,204,21,.18), transparent 30%),
        radial-gradient(circle at bottom, rgba(167,139,250,.22), transparent 35%),
        var(--bg);
      overflow-x: hidden;
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px);
      background-size: 36px 36px;
      opacity: .5;
    }

    button,
    input {
      font: inherit;
    }

    button {
      cursor: pointer;
    }

    .page {
      position: relative;
      z-index: 1;
      width: min(980px, calc(100% - 28px));
      margin: 0 auto;
      padding: 24px 0 54px;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 16px;
      border: 1px solid var(--border);
      border-radius: 28px;
      background: rgba(7,7,17,.68);
      backdrop-filter: blur(20px);
      box-shadow: 0 18px 60px rgba(0,0,0,.32);
      position: sticky;
      top: 14px;
      z-index: 5;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 950;
    }

    .brand img {
      width: 46px;
      height: 46px;
      object-fit: contain;
      border-radius: 14px;
      background: rgba(255,255,255,.1);
      padding: 5px;
    }

    .brand small {
      display: block;
      color: var(--muted);
      font-weight: 800;
      margin-top: 2px;
    }

    .status-pill {
      padding: 10px 13px;
      border-radius: 999px;
      background: rgba(250,204,21,.12);
      border: 1px solid rgba(250,204,21,.28);
      color: #fde68a;
      font-weight: 950;
      font-size: .88rem;
    }

    .status-pill.verified {
      background: rgba(52,211,153,.12);
      border-color: rgba(52,211,153,.34);
      color: #bbf7d0;
    }

    .status-pill.submitted {
      background: rgba(56,189,248,.13);
      border-color: rgba(56,189,248,.34);
      color: #bae6fd;
    }

    .hero {
      text-align: center;
      padding: 56px 0 34px;
    }

    .logo-main {
      width: 128px;
      height: 128px;
      object-fit: contain;
      padding: 12px;
      border-radius: 36px;
      background: var(--card);
      border: 1px solid var(--border);
      box-shadow: 0 30px 90px rgba(0,0,0,.42);
      animation: float 3.2s ease-in-out infinite;
    }

    @keyframes float {
      0%, 100% {
        transform: translateY(0) rotate(-2deg);
      }

      50% {
        transform: translateY(-8px) rotate(2deg);
      }
    }

    h1 {
      font-size: clamp(2.6rem, 8vw, 6.7rem);
      line-height: .9;
      letter-spacing: 0;
      margin: 22px auto 18px;
      max-width: 900px;
    }

    .gradient {
      background: linear-gradient(90deg, var(--gold), var(--cyan), var(--violet), var(--rose));
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }

    .subtitle {
      max-width: 740px;
      margin: 0 auto;
      color: var(--muted);
      line-height: 1.7;
      font-size: 1.08rem;
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 22px;
      align-items: start;
    }

    .card {
      border: 1px solid var(--border);
      border-radius: 34px;
      background: linear-gradient(145deg, var(--card2), rgba(255,255,255,.045));
      box-shadow: 0 28px 84px rgba(0,0,0,.34);
      backdrop-filter: blur(18px);
      overflow: hidden;
    }

    .card-header {
      padding: 24px;
      border-bottom: 1px solid rgba(255,255,255,.12);
    }

    .card-header h2 {
      font-size: 1.55rem;
      letter-spacing: 0;
    }

    .card-header p {
      color: var(--muted);
      margin-top: 6px;
      line-height: 1.55;
    }

    .card-body {
      padding: 24px;
    }

    label {
      display: block;
      color: var(--muted);
      font-weight: 900;
      font-size: .82rem;
      text-transform: uppercase;
      letter-spacing: 0;
      margin: 0 0 8px;
    }

    input {
      width: 100%;
      padding: 14px 15px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(255,255,255,.08);
      color: var(--text);
      outline: none;
      margin-bottom: 14px;
    }

    input:focus {
      border-color: rgba(250,204,21,.6);
      box-shadow: 0 0 0 4px rgba(250,204,21,.12);
    }

    .btn {
      border: 0;
      border-radius: 18px;
      padding: 14px 17px;
      color: #17120a;
      background: var(--gold);
      font-weight: 1000;
      box-shadow: 0 18px 46px rgba(250,204,21,.24);
      transition: .18s ease;
      width: 100%;
      min-height: 50px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
    }

    .btn:hover {
      transform: translateY(-3px);
    }

    .btn-icon {
      width: 23px;
      height: 23px;
      border-radius: 9px;
      display: inline-grid;
      place-items: center;
      flex: 0 0 auto;
      background: rgba(23,18,10,.12);
      font-size: 1rem;
      line-height: 1;
    }

    .btn.secondary .btn-icon,
    .btn.danger .btn-icon {
      background: rgba(255,255,255,.12);
    }

    .btn:disabled {
      cursor: not-allowed;
      opacity: .72;
    }

    .btn:disabled:hover {
      transform: none;
    }

    .btn-loader {
      width: 18px;
      height: 18px;
      border: 3px solid rgba(23,18,10,.28);
      border-top-color: #17120a;
      border-radius: 999px;
      display: none;
      animation: spin .75s linear infinite;
    }

    .btn.loading .btn-loader {
      display: inline-block;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .btn.secondary {
      color: var(--text);
      background: rgba(255,255,255,.1);
      border: 1px solid rgba(255,255,255,.16);
      box-shadow: none;
    }

    .btn.danger {
      color: #fff;
      background: rgba(251,113,133,.28);
      border: 1px solid rgba(251,113,133,.4);
      box-shadow: none;
    }

    .actions {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 14px;
    }

    .flow {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 8px;
      margin-bottom: 16px;
    }

    .flow-step {
      min-height: 70px;
      padding: 10px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      color: var(--muted);
      display: grid;
      align-content: center;
      gap: 6px;
      text-align: center;
      transition: .18s ease;
    }

    .flow-step strong {
      color: var(--text);
      font-size: .85rem;
      line-height: 1;
    }

    .flow-step span {
      font-size: .75rem;
      line-height: 1.2;
    }

    .flow-step.active {
      border-color: rgba(250,204,21,.46);
      background: rgba(250,204,21,.13);
      box-shadow: 0 12px 38px rgba(250,204,21,.12);
      color: #fde68a;
    }

    .flow-step.done {
      border-color: rgba(52,211,153,.28);
      background: rgba(52,211,153,.09);
      color: #bbf7d0;
    }

    .party-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
    }

    .party {
      padding: 18px;
      border-radius: 24px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.075);
      transition: .18s ease;
      cursor: pointer;
      min-height: 160px;
      position: relative;
      overflow: hidden;
    }

    .party::after {
      content: "Select";
      position: absolute;
      top: 14px;
      right: 14px;
      padding: 6px 9px;
      border-radius: 999px;
      background: rgba(255,255,255,.09);
      border: 1px solid rgba(255,255,255,.12);
      color: var(--muted);
      font-size: .72rem;
      font-weight: 950;
      opacity: 0;
      transform: translateY(-4px);
      transition: .18s ease;
    }

    .party:hover::after,
    .party.active::after {
      opacity: 1;
      transform: translateY(0);
    }

    .party.active::after {
      content: "Locked in";
      color: #bbf7d0;
      border-color: rgba(52,211,153,.28);
      background: rgba(52,211,153,.12);
    }

    .party:hover,
    .party.active {
      transform: translateY(-5px);
      border-color: var(--party-color);
      box-shadow:
        0 18px 50px rgba(0,0,0,.3),
        0 0 34px color-mix(in srgb, var(--party-color) 45%, transparent);
    }

    .party-symbol {
      font-size: 2.6rem;
      margin-bottom: 10px;
    }

    .party h3 {
      font-size: 1rem;
      line-height: 1.16;
      margin-bottom: 8px;
    }

    .party p {
      color: var(--muted);
      font-size: .9rem;
      line-height: 1.4;
    }

    video {
      width: 100%;
      border-radius: 24px;
      background: #000;
      border: 1px solid rgba(255,255,255,.15);
      min-height: 260px;
      object-fit: cover;
    }

    .media-stage {
      position: relative;
      border-radius: 30px;
      padding: 10px;
      background:
        linear-gradient(135deg, rgba(56,189,248,.2), rgba(250,204,21,.12), rgba(167,139,250,.18)),
        rgba(255,255,255,.06);
      border: 1px solid rgba(255,255,255,.16);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 24px 70px rgba(0,0,0,.26);
    }

    .media-stage video {
      display: block;
    }

    .stage-meta {
      position: absolute;
      left: 20px;
      top: 20px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      z-index: 2;
    }

    .stage-chip {
      padding: 7px 10px;
      border-radius: 999px;
      background: rgba(7,7,17,.72);
      border: 1px solid rgba(255,255,255,.18);
      color: #e0f2fe;
      font-size: .78rem;
      font-weight: 950;
      backdrop-filter: blur(12px);
    }

    .stage-chip.recording {
      color: #fecdd3;
      border-color: rgba(251,113,133,.38);
      background: rgba(127,29,29,.52);
    }

    .stage-chip.recording::before {
      content: "";
      width: 8px;
      height: 8px;
      display: inline-block;
      margin-right: 7px;
      border-radius: 999px;
      background: var(--rose);
      box-shadow: 0 0 0 0 rgba(251,113,133,.56);
      animation: pulse 1s infinite;
    }

    @keyframes pulse {
      70% {
        box-shadow: 0 0 0 10px rgba(251,113,133,0);
      }

      100% {
        box-shadow: 0 0 0 0 rgba(251,113,133,0);
      }
    }

    .notice {
      padding: 14px;
      border-radius: 18px;
      background: rgba(56,189,248,.1);
      border: 1px solid rgba(56,189,248,.25);
      color: #bae6fd;
      line-height: 1.55;
      margin-bottom: 16px;
      font-weight: 750;
    }

    .error {
      background: rgba(251,113,133,.11);
      border-color: rgba(251,113,133,.32);
      color: #fecdd3;
    }

    .success {
      background: rgba(52,211,153,.11);
      border-color: rgba(52,211,153,.3);
      color: #bbf7d0;
    }

    .hidden {
      display: none !important;
    }

    .timer {
      text-align: center;
      font-size: 2rem;
      font-weight: 1000;
      color: var(--gold);
      margin: 10px 0;
    }

    .timer-chip {
      display: flex;
      justify-content: center;
      margin: 12px 0 2px;
    }

    .timer {
      min-width: 94px;
      margin: 0;
      padding: 9px 14px;
      border-radius: 999px;
      background: rgba(250,204,21,.12);
      border: 1px solid rgba(250,204,21,.3);
      box-shadow: 0 12px 34px rgba(250,204,21,.12);
    }

    .vote-receipt {
      text-align: center;
      padding: 28px;
      border-radius: 28px;
      background:
        radial-gradient(circle at top, rgba(52,211,153,.22), transparent 55%),
        rgba(52,211,153,.09);
      border: 1px solid rgba(52,211,153,.35);
      box-shadow: 0 24px 70px rgba(0,0,0,.32);
      position: relative;
      overflow: hidden;
    }

    .vote-receipt::before {
      content: "BMEC";
      position: absolute;
      right: -22px;
      top: 22px;
      color: rgba(255,255,255,.045);
      font-size: clamp(4rem, 15vw, 9rem);
      font-weight: 1000;
      line-height: .8;
      pointer-events: none;
    }

    .receipt-icon {
      width: 74px;
      height: 74px;
      margin: 0 auto 16px;
      border-radius: 999px;
      display: grid;
      place-items: center;
      font-size: 2.2rem;
      background: rgba(52,211,153,.2);
      border: 1px solid rgba(52,211,153,.45);
    }

    .receipt-stamp {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 14px;
      padding: 9px 12px;
      border-radius: 999px;
      color: #bbf7d0;
      background: rgba(52,211,153,.12);
      border: 1px solid rgba(52,211,153,.35);
      font-weight: 1000;
      font-size: .82rem;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .vote-receipt h2 {
      color: #bbf7d0;
      margin-bottom: 8px;
      font-size: 1.8rem;
    }

    .lock-note {
      color: var(--muted);
      line-height: 1.6;
      font-size: .95rem;
    }

    .voted-party-card {
      margin: 22px 0;
      padding: 22px;
      border-radius: 24px;
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.16);
    }

    .voted-symbol {
      font-size: 3rem;
      margin-bottom: 10px;
    }

    .voted-party-card h3 {
      margin-bottom: 8px;
      line-height: 1.2;
    }

    .voted-party-card p {
      color: var(--muted);
      line-height: 1.5;
    }

    .submitted-video {
      margin-top: 20px;
      text-align: left;
    }

    .submitted-video label {
      margin-bottom: 10px;
    }

    .submitted-video video {
      width: 100%;
      border-radius: 24px;
      border: 1px solid rgba(255,255,255,.16);
      background: #000;
      min-height: 280px;
    }

    .submitted-meta {
      margin-top: 16px;
      color: var(--muted);
      line-height: 1.6;
      font-size: .94rem;
    }

    .receipt-meta-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
      margin-top: 18px;
      text-align: left;
    }

    .receipt-meta-item {
      padding: 13px;
      border-radius: 18px;
      background: rgba(255,255,255,.07);
      border: 1px solid rgba(255,255,255,.12);
    }

    .receipt-meta-item span {
      display: block;
      color: var(--muted);
      font-size: .74rem;
      text-transform: uppercase;
      letter-spacing: 0;
      font-weight: 950;
      margin-bottom: 5px;
    }

    .receipt-meta-item strong {
      color: var(--text);
      overflow-wrap: anywhere;
    }

    .submit-overlay {
      position: fixed;
      inset: 0;
      z-index: 50;
      display: grid;
      place-items: center;
      padding: 24px;
      background:
        radial-gradient(circle at center, rgba(56,189,248,.14), transparent 34%),
        rgba(7,7,17,.82);
      backdrop-filter: blur(18px);
    }

    .submit-overlay.hidden {
      display: none;
    }

    .submit-modal {
      width: min(440px, 100%);
      padding: 30px;
      border-radius: 32px;
      border: 1px solid rgba(250,204,21,.28);
      background:
        radial-gradient(circle at top, rgba(250,204,21,.2), transparent 58%),
        linear-gradient(145deg, rgba(255,255,255,.14), rgba(255,255,255,.055));
      box-shadow: 0 34px 120px rgba(0,0,0,.52);
      text-align: center;
    }

    .portal-ring {
      width: 118px;
      height: 118px;
      margin: 0 auto 18px;
      border-radius: 999px;
      border: 2px solid rgba(250,204,21,.18);
      display: grid;
      place-items: center;
      position: relative;
    }

    .portal-ring::before,
    .portal-ring::after {
      content: "";
      position: absolute;
      inset: 8px;
      border-radius: inherit;
      border: 3px solid transparent;
      border-top-color: var(--gold);
      border-right-color: rgba(56,189,248,.8);
      animation: spin 1s linear infinite;
    }

    .portal-ring::after {
      inset: 22px;
      border-top-color: var(--green);
      border-right-color: rgba(167,139,250,.8);
      animation-duration: 1.35s;
      animation-direction: reverse;
    }

    .portal-ring span {
      width: 42px;
      height: 42px;
      border-radius: 15px;
      display: grid;
      place-items: center;
      background: rgba(250,204,21,.16);
      border: 1px solid rgba(250,204,21,.32);
      font-size: 1.4rem;
      z-index: 1;
    }

    .submit-modal h2 {
      color: #fde68a;
      margin-bottom: 8px;
      letter-spacing: 0;
    }

    .submit-modal p {
      color: var(--muted);
      line-height: 1.6;
      font-weight: 750;
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
        scroll-behavior: auto !important;
      }
    }

    @media (max-width: 900px) {
      .flow {
        grid-template-columns: 1fr;
      }

      .flow-step {
        min-height: auto;
        grid-template-columns: auto 1fr;
        text-align: left;
        align-items: center;
      }

      .party-grid {
        grid-template-columns: 1fr;
      }

      .actions {
        grid-template-columns: 1fr;
      }

      .topbar {
        position: relative;
        top: auto;
        align-items: flex-start;
        flex-direction: column;
      }

      .status-pill {
        width: 100%;
        text-align: center;
      }

      .hero {
        padding-top: 34px;
      }

      .logo-main {
        width: 104px;
        height: 104px;
      }

      video {
        min-height: 220px;
      }

      .submitted-video video {
        min-height: 220px;
      }

      .receipt-meta-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>

<body>
  <div class="page">
    <div class="topbar">
      <div class="brand">
        <img src="https://bustedminds.us.kg/images/Busted-Minds-Logo.png" alt="Busted Minds Logo" />
        <div>
          Busted Minds Election Portal
          <small>BMEC verified video voting</small>
        </div>
      </div>

      <div class="status-pill" id="loginStatus">Not logged in</div>
    </div>

    <section class="hero">
      <img class="logo-main" src="https://bustedminds.us.kg/images/Busted-Minds-Logo.png" alt="Busted Minds Logo" />
      <h1>Busted Minds<br><span class="gradient">Voting Portal</span></h1>
      <p class="subtitle">Login, choose a party, record a 10-second video saying the party name and candidate, then submit your official vote.</p>
    </section>

    <section class="grid">
      <div class="card" id="loginCard">
        <div class="card-header">
          <h2>Member Login</h2>
          <p>Only approved Busted Minds members can enter using their personal PIN.</p>
        </div>

        <div class="card-body">
          <label for="memberName">Member name</label>
          <input id="memberName" placeholder="example: pravin" autocomplete="username" />

          <label for="pin">PIN</label>
          <input id="pin" type="password" placeholder="Enter PIN" autocomplete="current-password" />

          <button class="btn" onclick="login()">
            <span class="btn-icon" aria-hidden="true">🔐</span>
            <span>Enter Portal</span>
          </button>
          <div id="loginMessage" style="margin-top:14px"></div>
        </div>
      </div>

      <div class="card hidden" id="voteCard">
        <div class="card-header">
          <h2>Record Your Vote</h2>
          <p>BMEC member mode is active. Say clearly: “I vote for [party name], candidate [candidate name].”</p>
        </div>

        <div class="card-body">
          <div class="flow" id="voteFlow" aria-label="Vote progress">
            <div class="flow-step active" data-stage="party">
              <strong>Party</strong>
              <span>Pick one</span>
            </div>
            <div class="flow-step" data-stage="camera">
              <strong>Camera</strong>
              <span>Get ready</span>
            </div>
            <div class="flow-step" data-stage="record">
              <strong>Record</strong>
              <span>10 seconds</span>
            </div>
            <div class="flow-step" data-stage="review">
              <strong>Review</strong>
              <span>Check video</span>
            </div>
            <div class="flow-step" data-stage="submit">
              <strong>Submit</strong>
              <span>Lock vote</span>
            </div>
          </div>

          <div id="voteMessage" class="notice">Select a party, start camera, record your vote, then submit.</div>

          <label>Choose party</label>
          <div class="party-grid" id="partyGrid"></div>

          <div style="height:16px"></div>

          <div class="media-stage">
            <div class="stage-meta">
              <span class="stage-chip" id="cameraState">Camera idle</span>
              <span class="stage-chip hidden" id="recordingState">Recording</span>
            </div>
            <video id="preview" autoplay muted playsinline></video>
          </div>

          <div class="timer-chip">
            <div class="timer" id="timer">10s</div>
          </div>

          <div class="actions">
            <button class="btn secondary" onclick="startCamera()">
              <span class="btn-icon" aria-hidden="true">📷</span>
              <span>Start Camera</span>
            </button>
            <button class="btn" onclick="startRecording()">
              <span class="btn-icon" aria-hidden="true">●</span>
              <span>Record 10s</span>
            </button>
            <button class="btn danger" onclick="stopCamera()">
              <span class="btn-icon" aria-hidden="true">■</span>
              <span>Stop Camera</span>
            </button>
          </div>

          <div style="height:10px"></div>

          <button class="btn" id="submitVoteBtn" onclick="submitVote()">
            <span class="btn-icon" aria-hidden="true">📤</span>
            <span class="btn-label">Submit Vote Video</span>
            <span class="btn-loader" aria-hidden="true"></span>
          </button>
        </div>
      </div>
    </section>
  </div>

  <div class="submit-overlay hidden" id="submitOverlay" role="status" aria-live="polite">
    <div class="submit-modal">
      <div class="portal-ring">
        <span aria-hidden="true">🗳️</span>
      </div>
      <h2>Locking Your Vote</h2>
      <p>Uploading your verified video ballot to the private BMEC record.</p>
    </div>
  </div>

  <script>
    let token = localStorage.getItem('bmecToken') || '';
    let currentUser = '';
    let parties = [];
    let selectedPartyId = '';
    let stream = null;
    let recorder = null;
    let chunks = [];
    let recordedBlob = null;
    let countdownInterval = null;
    let isSubmitting = false;

    const voteStages = ['party', 'camera', 'record', 'review', 'submit'];

    async function api(path, options = {}) {
      const headers = options.headers || {};

      if (token) {
        headers.Authorization = 'Bearer ' + token;
      }

      const res = await fetch(path, { ...options, headers });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || 'Request failed');
      }

      return data;
    }

    function message(el, text, type = 'notice') {
      el.className = type;
      el.textContent = text;
    }

    function escapeHtml(value) {
      return String(value || '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    function setStatusPill(text, state = '') {
      const pill = document.getElementById('loginStatus');

      pill.textContent = text;
      pill.className = state ? 'status-pill ' + state : 'status-pill';
    }

    function updateWorkflow(activeStage) {
      const activeIndex = voteStages.indexOf(activeStage);

      document.querySelectorAll('.flow-step').forEach((step) => {
        const stepIndex = voteStages.indexOf(step.dataset.stage);

        step.classList.toggle('active', stepIndex === activeIndex);
        step.classList.toggle('done', stepIndex >= 0 && stepIndex < activeIndex);
      });
    }

    function setCameraState(text, isRecording = false) {
      const cameraState = document.getElementById('cameraState');
      const recordingState = document.getElementById('recordingState');

      if (cameraState) {
        cameraState.textContent = text;
      }

      if (recordingState) {
        recordingState.classList.toggle('hidden', !isRecording);
        recordingState.classList.toggle('recording', isRecording);
      }
    }

    function setSubmitLoading(isLoading) {
      const button = document.getElementById('submitVoteBtn');
      const overlay = document.getElementById('submitOverlay');

      isSubmitting = isLoading;

      if (overlay) {
        overlay.classList.toggle('hidden', !isLoading);
      }

      if (!button) return;

      const label = button.querySelector('.btn-label');

      button.disabled = isLoading;
      button.classList.toggle('loading', isLoading);

      if (label) {
        label.textContent = isLoading ? 'Submitting...' : 'Submit Vote Video';
      }
    }

    function createReceiptId(vote) {
      const source = [vote.name, vote.partyId, vote.submittedAt].join('-');
      let hash = 0;

      for (let i = 0; i < source.length; i += 1) {
        hash = ((hash << 5) - hash) + source.charCodeAt(i);
        hash |= 0;
      }

      return 'BMEC-' + Math.abs(hash).toString(36).toUpperCase().padStart(6, '0');
    }

    async function login() {
      const name = document.getElementById('memberName').value;
      const pin = document.getElementById('pin').value;
      const box = document.getElementById('loginMessage');

      try {
        const data = await api('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, pin })
        });

        token = data.token;
        currentUser = data.name;
        parties = data.parties;

        localStorage.setItem('bmecToken', token);

        message(box, 'Login successful. Welcome to democracy.', 'notice success');
        showPortal();
      } catch (err) {
        message(box, err.message, 'notice error');
      }
    }

    async function restoreSession() {
      if (!token) return;

      try {
        const data = await api('/api/me');

        currentUser = data.name;
        parties = data.parties;

        showPortal(data.existingVote);
      } catch {
        localStorage.removeItem('bmecToken');
        token = '';
      }
    }

    function showPortal(existingVote = null) {
      setStatusPill('BMEC Verified - ' + currentUser, 'verified');
      document.getElementById('loginCard').classList.add('hidden');
      document.getElementById('voteCard').classList.remove('hidden');

      if (existingVote) {
        showSubmittedVote(existingVote);
        return;
      }

      updateWorkflow('party');
      setCameraState('Camera idle');
      renderParties();
    }

    function showSubmittedVote(vote) {
      stopCamera();

      const voteCard = document.getElementById('voteCard');
      const partyColor = escapeHtml(vote.color || 'rgba(255,255,255,.16)');
      const symbol = escapeHtml(vote.symbol);
      const party = escapeHtml(vote.party);
      const candidate = escapeHtml(vote.candidate);
      const videoUrl = escapeHtml(vote.videoUrl);
      const submittedAt = vote.submittedAt
        ? new Date(vote.submittedAt).toLocaleString()
        : new Date().toLocaleString();
      const receiptId = escapeHtml(createReceiptId(vote));
      const memberName = escapeHtml(vote.name || currentUser);

      voteCard.innerHTML =
        '<div class="card-header">' +
          '<h2>Your Submitted Vote</h2>' +
          '<p>Your BMEC ballot is locked and cannot be changed.</p>' +
        '</div>' +
        '<div class="card-body">' +
          '<div class="vote-receipt">' +
            '<div class="receipt-stamp">BMEC ballot locked</div>' +
            '<div class="receipt-icon">✅</div>' +
            '<h2>Vote Submitted Successfully</h2>' +
            '<p class="lock-note">' +
              'Your private member vote is sealed with the video you submitted.' +
            '</p>' +
            '<div class="voted-party-card" style="border-color: ' + partyColor + '; box-shadow: 0 0 34px color-mix(in srgb, ' + partyColor + ' 35%, transparent);">' +
              '<div class="voted-symbol">' + symbol + '</div>' +
              '<h3>' + party + '</h3>' +
              '<p>Candidate: <strong>' + candidate + '</strong></p>' +
            '</div>' +
            '<div class="receipt-meta-grid">' +
              '<div class="receipt-meta-item">' +
                '<span>Member</span>' +
                '<strong>' + memberName + '</strong>' +
              '</div>' +
              '<div class="receipt-meta-item">' +
                '<span>Receipt</span>' +
                '<strong>' + receiptId + '</strong>' +
              '</div>' +
            '</div>' +
            '<div class="submitted-video">' +
              '<label>Your submitted video</label>' +
              '<video src="' + videoUrl + '" controls playsinline></video>' +
            '</div>' +
            '<p class="submitted-meta">Submitted at ' + escapeHtml(submittedAt) + '</p>' +
          '</div>' +
        '</div>';

      setStatusPill('Vote locked - ' + currentUser, 'submitted');
    }

    function renderParties() {
      const grid = document.getElementById('partyGrid');
      grid.innerHTML = '';

      parties.forEach((party) => {
        const div = document.createElement('div');

        div.className = 'party';
        div.style.setProperty('--party-color', party.color);

        div.innerHTML =
          '<div class="party-symbol">' + escapeHtml(party.symbol) + '</div>' +
          '<h3>' + escapeHtml(party.party) + '</h3>' +
          '<p>Candidate: <strong>' + escapeHtml(party.candidate) + '</strong></p>';

        div.onclick = () => {
          selectedPartyId = party.id;

          document.querySelectorAll('.party').forEach((p) => {
            p.classList.remove('active');
          });

          div.classList.add('active');

          message(
            document.getElementById('voteMessage'),
            'Selected: ' + party.party + ', candidate ' + party.candidate + '.',
            'notice'
          );
          updateWorkflow(stream ? 'record' : 'camera');
        };

        grid.appendChild(div);
      });
    }

    async function startCamera() {
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: true,
          audio: true
        });

        const preview = document.getElementById('preview');
        preview.srcObject = stream;
        preview.controls = false;
        preview.muted = true;

        setCameraState('Camera ready');
        updateWorkflow(selectedPartyId ? 'record' : 'party');

        message(
          document.getElementById('voteMessage'),
          selectedPartyId
            ? 'Camera started. You can now record your 10-second vote.'
            : 'Camera started. Select a party before recording.',
          'notice success'
        );
      } catch (err) {
        message(
          document.getElementById('voteMessage'),
          'Camera permission failed: ' + err.message,
          'notice error'
        );
      }
    }

    function stopCamera() {
      if (recorder && recorder.state === 'recording') {
        recorder.stop();
      }

      clearInterval(countdownInterval);

      if (stream) {
        stream.getTracks().forEach((track) => track.stop());
      }

      stream = null;

      const preview = document.getElementById('preview');
      if (preview) {
        preview.srcObject = null;
      }

      setCameraState(recordedBlob ? 'Video ready' : 'Camera idle');
    }

    async function startRecording() {
      if (!selectedPartyId) {
        updateWorkflow('party');

        return message(
          document.getElementById('voteMessage'),
          'Select a party first.',
          'notice error'
        );
      }

      if (!stream) {
        await startCamera();
      }

      if (!stream) return;

      chunks = [];
      recordedBlob = null;

      recorder = new MediaRecorder(stream, { mimeType: 'video/webm' });

      recorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          chunks.push(event.data);
        }
      };

      recorder.onstop = () => {
        recordedBlob = new Blob(chunks, { type: 'video/webm' });

        const url = URL.createObjectURL(recordedBlob);
        const preview = document.getElementById('preview');

        preview.srcObject = null;
        preview.src = url;
        preview.controls = true;
        preview.muted = false;

        setCameraState('Video ready');
        updateWorkflow('review');

        message(
          document.getElementById('voteMessage'),
          'Recording complete. Review it and submit your vote.',
          'notice success'
        );
      };

      recorder.start();

      let seconds = 10;
      document.getElementById('timer').textContent = seconds + 's';
      setCameraState('Recording vote', true);
      updateWorkflow('record');

      message(
        document.getElementById('voteMessage'),
        'Recording started. Speak clearly.',
        'notice'
      );

      clearInterval(countdownInterval);

      countdownInterval = setInterval(() => {
        seconds -= 1;
        document.getElementById('timer').textContent = seconds + 's';

        if (seconds <= 0) {
          clearInterval(countdownInterval);

          if (recorder && recorder.state === 'recording') {
            recorder.stop();
          }

          stopCamera();
        }
      }, 1000);
    }

    async function submitVote() {
      if (isSubmitting) return;

      if (!selectedPartyId) {
        updateWorkflow('party');

        return message(
          document.getElementById('voteMessage'),
          'Select a party first.',
          'notice error'
        );
      }

      if (!recordedBlob) {
        updateWorkflow(selectedPartyId ? 'record' : 'party');

        return message(
          document.getElementById('voteMessage'),
          'Record a 10-second video first.',
          'notice error'
        );
      }

      const form = new FormData();
      form.append('partyId', selectedPartyId);
      form.append('video', recordedBlob, currentUser + '-vote.webm');

      try {
        setSubmitLoading(true);
        updateWorkflow('submit');
        message(
          document.getElementById('voteMessage'),
          'Submitting your vote video...',
          'notice'
        );

        const res = await fetch('/api/vote', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + token },
          body: form
        });

        const data = await res.json();

        if (!res.ok) {
          throw new Error(data.error || 'Upload failed');
        }

        setSubmitLoading(false);
        showSubmittedVote(data.vote);
      } catch (err) {
        setSubmitLoading(false);
        updateWorkflow('review');

        message(
          document.getElementById('voteMessage'),
          err.message,
          'notice error'
        );
      }
    }

    restoreSession();
  </script>
</body>
</html>`;
