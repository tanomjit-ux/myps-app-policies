const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

function safeEqual(a, b) {
  const ab = Buffer.from(a || '');
  const bb = Buffer.from(b || '');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
    res.writeHead(200, {'content-type':'application/json'});
    return res.end(JSON.stringify({ok:true, service:'MYPS HR LINE Gateway'}));
  }

  if (req.method !== 'POST' || req.url !== '/webhook') {
    res.writeHead(404);
    return res.end('Not Found');
  }

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  const signature = req.headers['x-line-signature'] || '';
  const secret = process.env.LINE_CHANNEL_SECRET || '';

  if (!secret) {
    res.writeHead(500);
    return res.end('LINE_CHANNEL_SECRET missing');
  }

  const generated = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  if (!safeEqual(generated, signature)) {
    res.writeHead(401);
    return res.end('Invalid signature');
  }

  let payload;
  try { payload = JSON.parse(rawBody.toString('utf8')); }
  catch {
    res.writeHead(400);
    return res.end('Invalid JSON');
  }

  const upstream = process.env.N8N_WEBHOOK_URL || '';
  if (!upstream) {
    res.writeHead(200, {'content-type':'application/json'});
    return res.end(JSON.stringify({ok:true, verified:true, forwarded:false, events:Array.isArray(payload.events)?payload.events.length:0}));
  }

  try {
    const r = await fetch(upstream, {
      method:'POST',
      headers:{
        'content-type':'application/json',
        'x-myps-line-verified':'1',
        'x-myps-gateway-token':process.env.GATEWAY_SHARED_TOKEN || ''
      },
      body: rawBody
    });
    if (!r.ok) {
      res.writeHead(502);
      return res.end('Upstream error');
    }
    res.writeHead(200);
    return res.end('OK');
  } catch (e) {
    res.writeHead(502);
    return res.end('Upstream unavailable');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('MYPS HR LINE Gateway listening on', PORT);
});
