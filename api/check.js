const crypto = require('crypto');

const forbidden = /^(accept-encoding|connection|content-length|cookie|host|origin|referer|user-agent|sec-|transfer-encoding)$/i;

/* ===== Croma ka "InCallResponse" desalt karke real public key nikalna ===== */
function textFromBase64(value) {
  return Buffer.from(String(value).replace(/\s/g, ''), 'base64').toString('utf8');
}

function desaltPublicKey(stored) {
  let token = String(stored || '');
  try { if (token.startsWith('"')) token = JSON.parse(token); } catch {}
  let salted = textFromBase64(token);
  let point = salted.indexOf('|'); const trimEnd = parseInt(salted.slice(0, point)); salted = salted.slice(point + 1);
  point = salted.indexOf('|'); const trimStart = parseInt(salted.slice(0, point)); salted = salted.slice(point + 1);
  point = salted.indexOf('|'); const keyLength = parseInt(salted.slice(0, point)); salted = salted.slice(point + 1);
  point = salted.indexOf('|'); const removeLength = parseInt(salted.slice(0, point)); salted = salted.slice(point + 1);
  salted = salted.slice(0, salted.length - trimEnd - 18);
  let key = textFromBase64(salted).slice(trimStart);
  key = key.slice(0, keyLength) + key.slice(keyLength + removeLength);
  if (!key.includes('BEGIN PUBLIC KEY')) key = `-----BEGIN PUBLIC KEY-----\n${key}\n-----END PUBLIC KEY-----`;
  return key;
}

/* ===== InCallReqHeader banane wala encryption (har coupon ka fresh) ===== */
function makeInCallHeader(body, publicKeyStored) {
  const pem = desaltPublicKey(publicKeyStored);
  const json = JSON.stringify(body);
  const sha256Hex = crypto.createHash('sha256').update(json, 'utf8').digest('hex');
  return crypto.publicEncrypt(
    { key: pem, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(sha256Hex, 'utf8')
  ).toString('base64');
}

/* ===== cURL paste karo to URL+headers parse karta hai ===== */
function parseCurl(text) {
  const result = { url: '', headers: {} };
  const trimmed = String(text || '').trim();
  if (!trimmed.toLowerCase().startsWith('curl')) {
    result.url = trimmed.split('\n')[0].trim();
    return result;
  }
  /* URL nikalna (aage --url bhi ho sakta hai, plain bhi) */
  const urlWithFlag = trimmed.match(/--url\s+'(https:\/\/[^']+)'/) ||
                      trimmed.match(/--url\s+"(https:\/\/[^"]+)"/);
  const urlPlain = trimmed.match(/'(https:\/\/[^']+)'/) ||
                   trimmed.match(/"(https:\/\/[^"]+)"/) ||
                   trimmed.match(/(https:\/\/[^\s'"]+)/);
  if (urlWithFlag) result.url = urlWithFlag[1];
  else if (urlPlain) result.url = urlPlain[1];

  /* Headers nikalna: -H 'name: value' ke saath saath --header bhi */
  const headerRegex = /(?:-H|--header)\s+'([^']*)'|(?:-H|--header)\s+"([^"]*)"/g;
  let m;
  while ((m = headerRegex.exec(trimmed)) !== null) {
    const raw = m[1] !== undefined ? m[1] : m[2];
    const idx = raw.indexOf(':');
    if (idx > 0) {
      const name = raw.slice(0, idx).trim();
      const value = raw.slice(idx + 1).trim();
      if (!forbidden.test(name)) result.headers[name] = value;
    }
  }
  return result;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const { curl, publicKeyStored, body } = req.body || {};
    const parsed = parseCurl(curl || '');

    if (!parsed.url.includes('cart-modification')) {
      return res.status(400).json({ error: 'cart-modification URL nahi mila. Cart page se POST request copy karke paste karo.' });
    }

    const headers = { ...parsed.headers, 'Content-Type': 'application/json' };

    /* Purana incallreqheader hata do — fresh generate hoga */
    delete headers.incallreqheader;
    delete headers.InCallReqHeader;

    if (publicKeyStored && String(publicKeyStored).length > 20) {
      try { headers.incallreqheader = makeInCallHeader(body, publicKeyStored); } catch {}
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    let response, data;
    try {
      response = await fetch(parsed.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal
      });
      data = await response.json().catch(() => ({}));
    } finally {
      clearTimeout(timer);
    }

    return res.status(200).json({ httpStatus: response.status, data });
  } catch (error) {
    const retryable = /abort/i.test(String(error.message || error));
    return res.status(200).json({ error: String(error.message || error), retryable, httpStatus: 0 });
  }
};
