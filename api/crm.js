// api/crm.js
// Vercel Serverless Function — proxy giữa client và Apps Script.
// Client gọi '/api/crm' (relative path, cùng domain Vercel).
// Function này đọc URL Apps Script THẬT từ Environment Variable
// (không hardcode trong code, không lên GitHub), rồi forward request.

export default async function handler(req, res) {
  const GAS_URL = process.env.GAS_CRM_URL; // đặt trong Vercel → Settings → Environment Variables
  if (!GAS_URL) {
    res.status(500).json({ success: false, error: 'Server misconfigured: GAS_CRM_URL missing' });
    return;
  }

  try {
    if (req.method === 'GET') {
      // Forward query string (action=getAll&email=...&token=...)
      const qs = req.url.split('?')[1] || '';
      const upstream = await fetch(`${GAS_URL}?${qs}`, { method: 'GET' });
      const text = await upstream.text();
      res.status(upstream.status).setHeader('Content-Type', 'application/json').send(text);
      return;
    }

    if (req.method === 'POST') {
      const upstream = await fetch(GAS_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body),
      });
      const text = await upstream.text();
      res.status(upstream.status).setHeader('Content-Type', 'application/json').send(text);
      return;
    }

    res.status(405).json({ success: false, error: 'Method not allowed' });
  } catch (err) {
    res.status(502).json({ success: false, error: 'Upstream error: ' + String(err) });
  }
}
