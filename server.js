// Simple Node.js server to serve static files and provide JSON endpoints
// Run: node server.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.join(__dirname);
const dbDir = path.join(root, 'database');

function sendFile(res, filePath, type){
  fs.readFile(filePath, (err, data)=>{
    if(err){res.writeHead(404);res.end('Not found');return}
    res.writeHead(200, {'Content-Type': type});
    res.end(data);
  });
}

function readJSON(file){
  try{const raw = fs.readFileSync(path.join(dbDir,file),'utf8'); return JSON.parse(raw)}catch(e){return null}
}
function writeJSON(file, obj){
  fs.writeFileSync(path.join(dbDir,file), JSON.stringify(obj, null, 2), 'utf8');
}

function hashPassword(password, salt){
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function sanitizeAccountsForPublic(accounts){
  return (accounts||[]).map(a=>{
    const {passwordHash,passwordSalt,resetTokenHash,resetTokenExpiry,...rest} = a;
    return rest;
  });
}

function getRequestData(req){
  return new Promise((resolve,reject)=>{
    let body='';
    req.on('data', chunk=>{body+=chunk});
    req.on('end', ()=>{
      try{resolve(body ? JSON.parse(body) : {});}catch(e){reject(e)}
    });
    req.on('error', reject);
  });
}

const server = http.createServer((req,res)=>{
  try{
    const url = req.url.split('?')[0];
    // log requests for easier debugging
    console.log(new Date().toISOString(), req.method, req.url);
    // simple CORS for local testing
    res.setHeader('Access-Control-Allow-Origin','*');
    res.setHeader('Access-Control-Allow-Headers','Content-Type');
    res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
    if(req.method === 'OPTIONS'){
      res.writeHead(204);
      return res.end();
    }
  if(url === '/api/accounts' && req.method === 'GET'){
    console.log('route: GET /api/accounts');
    const accounts = readJSON('accounts.json') || [];
    res.writeHead(200, {'Content-Type':'application/json'});
    return res.end(JSON.stringify(sanitizeAccountsForPublic(accounts)));
  }
  if(url === '/api/accounts' && req.method === 'POST'){
    console.log('route: POST /api/accounts (create)');
    // create account with hashed password
    getRequestData(req).then(body=>{
      const {name,email,password,role='user'} = body||{};
      if(!email || !password) return res.writeHead(400).end(JSON.stringify({error:'email and password required'}));
      const accounts = readJSON('accounts.json') || [];
      if(accounts.find(a=>a.email === email)) return res.writeHead(409).end(JSON.stringify({error:'email exists'}));
      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = hashPassword(password, salt);
      const id = 'acct_'+(Date.now());
      const acct = {id,name,email,role,createdAt:new Date().toISOString(),passwordHash,passwordSalt:salt,resetTokenHash:null,resetTokenExpiry:null};
      accounts.push(acct);
      writeJSON('accounts.json', accounts);
      res.writeHead(201, {'Content-Type':'application/json'});
      return res.end(JSON.stringify({id:acct.id,email:acct.email,name:acct.name,createdAt:acct.createdAt,role:acct.role}));
    }).catch(err=>{res.writeHead(400);res.end('invalid body')});
    return;
  }
  if(url === '/api/accounts/login' && req.method === 'POST'){
    return getRequestData(req).then(body=>{
      const {email,password} = body||{};
      if(!email || !password) return res.writeHead(400).end(JSON.stringify({error:'email and password required'}));
      const accounts = readJSON('accounts.json') || [];
      const acct = accounts.find(a=>a.email === email);
      if(!acct) return res.writeHead(401).end(JSON.stringify({error:'invalid credentials'}));
      // try scrypt-based hash first
      const scryptHash = hashPassword(password, acct.passwordSalt);
      let authenticated = false;
      if(scryptHash === acct.passwordHash) authenticated = true;
      else {
        // fallback: support legacy MD5-style hashes (32 hex chars)
        try{
          const md5 = crypto.createHash('md5').update(password).digest('hex');
          if(md5 === acct.passwordHash) authenticated = true;
          // if legacy matched, upgrade to scrypt
          if(authenticated){
            const newSalt = crypto.randomBytes(16).toString('hex');
            acct.passwordSalt = newSalt;
            acct.passwordHash = hashPassword(password, newSalt);
            writeJSON('accounts.json', accounts);
            console.log('Upgraded legacy password for', acct.email);
          }
        }catch(e){/* ignore */}
      }
      if(!authenticated) return res.writeHead(401).end(JSON.stringify({error:'invalid credentials'}));
      const safe = (({passwordHash,passwordSalt,resetTokenHash,resetTokenExpiry,...rest})=>rest)(acct);
      res.writeHead(200, {'Content-Type':'application/json'});
      return res.end(JSON.stringify(safe));
    }).catch(()=>{res.writeHead(400);res.end(JSON.stringify({error:'invalid body'}))});
  }

  if(url.startsWith('/api/account') && req.method === 'GET'){
    // query param ?id=acct_1
    try{
      const q = new URL(req.url, 'http://localhost').searchParams;
      const id = q.get('id');
      if(!id) return res.writeHead(400).end(JSON.stringify({error:'id required'}));
      const accounts = readJSON('accounts.json') || [];
      const acct = accounts.find(a=>a.id === id);
      if(!acct) return res.writeHead(404).end(JSON.stringify({error:'not found'}));
      const safe = (({passwordHash,passwordSalt,resetTokenHash,resetTokenExpiry,...rest})=>rest)(acct);
      res.writeHead(200, {'Content-Type':'application/json'});
      return res.end(JSON.stringify(safe));
    }catch(e){res.writeHead(400);res.end(JSON.stringify({error:'invalid request'}))}
  }
  if(url === '/api/accounts/update' && req.method === 'POST'){
    console.log('route: POST /api/accounts/update');
    // update account fields (demo: name, description)
    return getRequestData(req).then(body=>{
      const {id,name,description} = body||{};
      if(!id) return res.writeHead(400).end(JSON.stringify({error:'id required'}));
      const accounts = readJSON('accounts.json') || [];
      const acct = accounts.find(a=>a.id === id);
      if(!acct) return res.writeHead(404).end(JSON.stringify({error:'not found'}));
      if(typeof name === 'string') acct.name = name;
      if(typeof description === 'string') acct.description = description;
      writeJSON('accounts.json', accounts);
      res.writeHead(200, {'Content-Type':'application/json'});
      return res.end(JSON.stringify({message:'updated', id:acct.id, name:acct.name, description:acct.description}));
    }).catch(()=>{res.writeHead(400);res.end(JSON.stringify({error:'invalid body'}))});
  }
  if(url === '/api/media'){
    console.log('route: GET /api/media');
    const media = readJSON('media.json') || [];
    res.writeHead(200, {'Content-Type':'application/json'});
    return res.end(JSON.stringify(media));
  }
  if(url === '/api/media/upload' && req.method === 'POST'){
    console.log('route: POST /api/media/upload');
    return getRequestData(req).then(body=>{
      const {title, filename, data, ownerId} = body||{};
      if(!filename || !data) return res.writeHead(400).end(JSON.stringify({error:'filename and data required'}));
      const uploadsDir = path.join(root,'uploads');
      if(!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
      // data may be a data URL (data:<mime>;base64,<b64>) or raw base64
      let mimeType = '';
      let b64 = data;
      const m = String(data).match(/^data:(.+);base64,(.+)$/);
      if(m){ mimeType = m[1]; b64 = m[2]; }
      const ext = path.extname(filename) || '';
      const safeName = 'media_'+Date.now()+ext;
      const filePath = path.join(uploadsDir, safeName);
      try{ fs.writeFileSync(filePath, Buffer.from(b64,'base64')); }catch(e){ console.error('write failed',e); return res.writeHead(500).end(JSON.stringify({error:'failed to write file'})); }
      const media = readJSON('media.json') || [];
      const entry = {id:'med_'+Date.now(), title: title||filename, filename:'/uploads/'+safeName, mimeType, ownerId: ownerId||null, createdAt:new Date().toISOString()};
      media.push(entry);
      writeJSON('media.json', media);
      res.writeHead(201, {'Content-Type':'application/json'});
      return res.end(JSON.stringify(entry));
    }).catch(err=>{console.error('upload parse',err);res.writeHead(400);res.end(JSON.stringify({error:'invalid body'}))});
  }
  if(url === '/api/followers'){
    console.log('route: /api/followers', req.method);
    const followers = readJSON('followers.json') || [];
    if(req.method === 'GET'){
      res.writeHead(200, {'Content-Type':'application/json'});
      return res.end(JSON.stringify(followers));
    }
    if(req.method === 'POST'){
      return getRequestData(req).then(body=>{
        const {accountId,email,name} = body||{};
        if(!accountId || !email) return res.writeHead(400).end(JSON.stringify({error:'accountId and email required'}));
        const followers = readJSON('followers.json') || [];
        const id = 'foll_'+Date.now();
        const entry = {id,accountId,email,name: name||null,subscribedAt:new Date().toISOString()};
        followers.push(entry);
        writeJSON('followers.json', followers);
        res.writeHead(201, {'Content-Type':'application/json'});
        return res.end(JSON.stringify(entry));
      }).catch(()=>{res.writeHead(400);res.end(JSON.stringify({error:'invalid body'}))});
    }
    return;
  }

  if(url === '/api/notify-followers' && req.method === 'POST'){
    console.log('route: POST /api/notify-followers');
    // Demo endpoint: check follower count and return list of emails to notify if threshold reached
    return getRequestData(req).then(body=>{
      const {accountId,threshold,message} = body||{};
      if(!accountId || !threshold) return res.writeHead(400).end(JSON.stringify({error:'accountId and threshold required'}));
      const followers = readJSON('followers.json') || [];
      const accountFollowers = followers.filter(f=>f.accountId === accountId);
      if(accountFollowers.length < threshold){
        res.writeHead(200, {'Content-Type':'application/json'});
        return res.end(JSON.stringify({notified:false,count:accountFollowers.length,needed:threshold}));
      }
      const emails = accountFollowers.map(f=>f.email);
      // In a real app you'd queue/send emails here. For demo, return the list.
      res.writeHead(200, {'Content-Type':'application/json'});
      return res.end(JSON.stringify({notified:true,count:accountFollowers.length,emails,message:message||null}));
    }).catch(()=>{res.writeHead(400);res.end(JSON.stringify({error:'invalid body'}))});
  }
  if(url === '/api/accounts/request-reset' && req.method === 'POST'){
    console.log('route: POST /api/accounts/request-reset');
    // demo password reset: generate token, store hash+expiry, return token (in real app you'd email it)
    getRequestData(req).then(body=>{
      const {email} = body||{};
      if(!email) return res.writeHead(400).end(JSON.stringify({error:'email required'}));
      const accounts = readJSON('accounts.json') || [];
      const acct = accounts.find(a=>a.email === email);
      if(!acct) return res.writeHead(404).end(JSON.stringify({error:'not found'}));
      const token = crypto.randomBytes(24).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      acct.resetTokenHash = tokenHash;
      acct.resetTokenExpiry = Date.now() + 1000*60*60; // 1 hour
      writeJSON('accounts.json', accounts);
      res.writeHead(200, {'Content-Type':'application/json'});
      // return token in response only for demo; in production you'd send email instead
      return res.end(JSON.stringify({message:'reset token generated (demo)', token}));
    }).catch(()=>{res.writeHead(400);res.end(JSON.stringify({error:'invalid body'}))});
    return;
  }
  if(url === '/api/accounts/reset' && req.method === 'POST'){
    console.log('route: POST /api/accounts/reset');
    getRequestData(req).then(body=>{
      const {email,token,newPassword} = body||{};
      if(!email || !token || !newPassword) return res.writeHead(400).end(JSON.stringify({error:'email,token,newPassword required'}));
      const accounts = readJSON('accounts.json') || [];
      const acct = accounts.find(a=>a.email === email);
      if(!acct || !acct.resetTokenHash || !acct.resetTokenExpiry) return res.writeHead(400).end(JSON.stringify({error:'no reset requested'}));
      if(Date.now() > acct.resetTokenExpiry) return res.writeHead(400).end(JSON.stringify({error:'token expired'}));
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      if(tokenHash !== acct.resetTokenHash) return res.writeHead(400).end(JSON.stringify({error:'invalid token'}));
      // set new password
      const salt = crypto.randomBytes(16).toString('hex');
      acct.passwordSalt = salt;
      acct.passwordHash = hashPassword(newPassword, salt);
      acct.resetTokenHash = null;
      acct.resetTokenExpiry = null;
      writeJSON('accounts.json', accounts);
      res.writeHead(200, {'Content-Type':'application/json'});
      return res.end(JSON.stringify({message:'password updated'}));
    }).catch(()=>{res.writeHead(400);res.end(JSON.stringify({error:'invalid body'}))});
    return;
  }
  if(url === '/sse/updates'){
    console.log('route: SSE /sse/updates');
    res.writeHead(200, {
      'Content-Type':'text/event-stream',
      'Cache-Control':'no-cache',
      Connection:'keep-alive'
    });
    // send initial ping
    res.write('event: connected\n');
    res.write('data: connected\n\n');
    // watch files and notify client
    const watchAccounts = fs.watch(path.join(dbDir,'accounts.json'), ()=>{
      const data = JSON.parse(fs.readFileSync(path.join(dbDir,'accounts.json'),'utf8'));
      res.write('event: accounts\n');
      res.write('data: '+JSON.stringify(sanitizeAccountsForPublic(data))+'\n\n');
    });
    const watchMedia = fs.watch(path.join(dbDir,'media.json'), ()=>{
      const data = fs.readFileSync(path.join(dbDir,'media.json'),'utf8');
      res.write('event: media\n');
      res.write('data: '+JSON.stringify(JSON.parse(data))+'\n\n');
    });
    const watchFollowers = fs.watch(path.join(dbDir,'followers.json'), ()=>{
      const data = fs.readFileSync(path.join(dbDir,'followers.json'),'utf8');
      res.write('event: followers\n');
      res.write('data: '+JSON.stringify(JSON.parse(data))+'\n\n');
    });
    req.on('close', ()=>{watchAccounts.close();watchMedia.close();watchFollowers && watchFollowers.close && watchFollowers.close()});
    return;
  }

  // static serve for workspace files
  let filePath = path.join(root, url === '/' ? 'index.html' : decodeURIComponent(url));
  const ext = path.extname(filePath).toLowerCase();
  const mime = {'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.png':'image/png','.jpg':'image/jpeg'}[ext]||'text/plain';
  if(fs.existsSync(filePath) && fs.statSync(filePath).isFile()){
    console.log('serving file', filePath);
    return sendFile(res,filePath,mime);
  }
  // If requester tried to reach an API route that wasn't matched, return JSON 404 (avoid sending HTML)
  if(url.startsWith('/api/')){
    console.log('unmatched api route', url);
    res.writeHead(404, {'Content-Type':'application/json'});
    return res.end(JSON.stringify({error:'not found'}));
  }
  // fallback: index (for SPA navigation)
  sendFile(res,path.join(root,'index.html'),'text/html');
  }catch(err){
    console.error('server error', err);
    try{res.writeHead(500, {'Content-Type':'application/json'});res.end(JSON.stringify({error:'server error'}));}catch(e){console.error('failed to send 500',e)}
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>console.log('Server running on http://localhost:'+PORT));
