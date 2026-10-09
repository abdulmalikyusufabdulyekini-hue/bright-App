import {createServer} from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes,createHash,scrypt as scryptCb,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import {readFileSync,mkdirSync,appendFileSync} from 'node:fs';
import {resolve,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
const scrypt=promisify(scryptCb), root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const hash=s=>createHash('sha256').update(s).digest('hex'), token=()=>randomBytes(32).toString('hex');
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const fail=(status,message)=>{throw Object.assign(new Error(message),{status})};
export async function createApp(env=process.env,transport=fetch){
 const production=env.NODE_ENV==='production', origin=env.APP_ORIGIN||'http://localhost:3000';
 if(new URL(origin).origin!==origin)throw Error('APP_ORIGIN must be an origin without a trailing slash');
 if(production&&(!origin.startsWith('https://')||!env.RESEND_API_KEY||!env.EMAIL_FROM||!env.ADMIN_EMAIL))throw Error('Production requires HTTPS APP_ORIGIN, RESEND_API_KEY, EMAIL_FROM and ADMIN_EMAIL');
 const paymentMode=env.FLW_MODE||'test';
 if(!['test','live'].includes(paymentMode))throw Error('FLW_MODE must be test or live');
 if(env.PAYMENTS_ENABLED==='true'){
  if(!env.FLW_SECRET_KEY||!env.FLW_WEBHOOK_SECRET||env.FLW_WEBHOOK_SECRET.length<32)throw Error('Set FLW_SECRET_KEY and a FLW_WEBHOOK_SECRET of at least 32 characters');
  const keyPrefix=paymentMode==='test'?'FLWSECK_TEST-':'FLWSECK-';
  if(!env.FLW_SECRET_KEY.startsWith(keyPrefix))throw Error('FLW_SECRET_KEY must be a Flutterwave v3 key matching FLW_MODE');
  if(paymentMode==='live'&&!production)throw Error('Live payments require NODE_ENV=production and HTTPS hosting');
 }
 const dir=env.DATA_DIR||resolve(root,'data');mkdirSync(dir,{recursive:true,mode:0o700});
 const db=new DatabaseSync(resolve(dir,'bright.sqlite')); db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
 db.exec(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE,name TEXT,password TEXT,verified INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user TEXT REFERENCES users(id),expires INTEGER);
 CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY,user TEXT REFERENCES users(id),kind TEXT,expires INTEGER);
 CREATE TABLE IF NOT EXISTS courses(id TEXT PRIMARY KEY,title TEXT,category TEXT,image TEXT,description TEXT,published INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS lessons(id TEXT PRIMARY KEY,course TEXT REFERENCES courses(id),title TEXT,body TEXT,sample INTEGER,position INTEGER);
 CREATE TABLE IF NOT EXISTS orders(ref TEXT PRIMARY KEY,user TEXT REFERENCES users(id),course TEXT REFERENCES courses(id),amount INTEGER,currency TEXT,status TEXT DEFAULT 'pending',transaction_id TEXT UNIQUE,link TEXT,created INTEGER);
 CREATE TABLE IF NOT EXISTS access(user TEXT REFERENCES users(id),course TEXT REFERENCES courses(id),PRIMARY KEY(user,course));
 CREATE TABLE IF NOT EXISTS progress(user TEXT REFERENCES users(id),lesson TEXT REFERENCES lessons(id),PRIMARY KEY(user,lesson));`);
 const get=(sql,...v)=>db.prepare(sql).get(...v), all=(sql,...v)=>db.prepare(sql).all(...v), run=(sql,...v)=>db.prepare(sql).run(...v);
 // Older orders belong to Squad. Never reuse their checkout links or verify them with Flutterwave.
 const orderColumns=all('PRAGMA table_info(orders)').map(c=>c.name);
 if(!orderColumns.includes('provider'))db.exec("ALTER TABLE orders ADD COLUMN provider TEXT NOT NULL DEFAULT 'squad'");
 if(!orderColumns.includes('mode'))db.exec("ALTER TABLE orders ADD COLUMN mode TEXT NOT NULL DEFAULT 'legacy'");
 if(paymentMode==='live'&&get("SELECT 1 FROM orders WHERE (provider='flutterwave' AND mode='test') OR (provider='squad' AND status='paid') LIMIT 1")){
  db.close();throw Error('Test or unclassified legacy purchases exist in this database. Use a separate clean production DATA_DIR; keep your test data backup.');
 }
 for(const c of JSON.parse(readFileSync(resolve(root,'server/catalogue.json')))){
  run('INSERT OR IGNORE INTO courses(id,title,category,image,description) VALUES(?,?,?,?,?)',c.id,c.title,c.category,c.image,c.desc);
  c.lessons.forEach((title,i)=>run('INSERT OR IGNORE INTO lessons VALUES(?,?,?,?,?,?)',`${c.id}-${i}`,c.id,title,c.body[i],1,i));
 }
 const dummy=await passwordHash('dummy-password-not-used');
 async function passwordHash(p){const salt=randomBytes(16).toString('hex');return salt+':'+(await scrypt(p,salt,64)).toString('hex')}
 function password(p){if(typeof p!=='string'||p.length<12||p.length>128)fail(400,'Use a password between 12 and 128 characters');return p}
 function email(e){if(typeof e!=='string'||e.length>254||!/^\S+@\S+\.\S+$/.test(e))fail(400,'Enter a valid email');return e.trim().toLowerCase()}
 async function mail(user,kind){
  const raw=token();run('INSERT INTO tokens VALUES(?,?,?,?)',hash(raw),user.id,kind,Date.now()+3600000);
  const link=`${origin}/#${kind}/${raw}`, message=`${kind==='verify'?'Verify your Bright Tech email':'Reset your Bright Tech password'}: ${link}\nThis link expires in one hour. If you did not request it, ignore this email.`;
  if(!production&&!env.RESEND_API_KEY){appendFileSync(resolve(dir,'dev-mail.txt'),`${user.email}\n${message}\n\n`,{mode:0o600});return;}
  const r=await transport('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:env.EMAIL_FROM,to:[user.email],subject:'Bright Tech account',text:message}),signal:AbortSignal.timeout(15000)});
  if(!r.ok)fail(503,'Email delivery unavailable. Please retry later.');
 }
 async function flutterwave(path,body){const r=await transport('https://api.flutterwave.com/v3'+path,{method:body?'POST':'GET',headers:{Authorization:`Bearer ${env.FLW_SECRET_KEY}`,'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(15000)});if(!r.ok)fail(503,'Payment provider unavailable. Please retry.');const j=await r.json();if(j.status!=='success'||!j.data)fail(409,'Payment has not been confirmed');return j.data}
 async function verify(ref){
  const o=get('SELECT orders.*,users.email FROM orders JOIN users ON users.id=orders.user WHERE ref=?',ref);if(!o)fail(404,'Order not found');if(o.provider!=='flutterwave'||o.mode!==paymentMode)fail(409,'This order belongs to a different payment provider or mode. Contact support.');if(o.status==='paid'||o.status==='revoked')return o.status;
  const d=await flutterwave('/transactions/verify_by_reference?tx_ref='+encodeURIComponent(ref));
  // Flutterwave sandbox may prefix customer emails; never normalize this prefix in live mode.
  const returnedEmail=typeof d.customer?.email==='string'?d.customer.email.toLowerCase():'';
  const emailMatches=returnedEmail===o.email||(paymentMode==='test'&&/^ravesb_[a-f0-9]{20}_/.test(returnedEmail)&&returnedEmail.replace(/^ravesb_[a-f0-9]{20}_/,'')===o.email);
  if(d.tx_ref!==o.ref||d.status!=='successful'||Number(d.amount)!==o.amount||d.currency!==o.currency||!emailMatches||!Number.isSafeInteger(d.id)||d.id<=0)fail(409,'Payment details do not match this order');
  db.exec('BEGIN IMMEDIATE');try{const current=get('SELECT status FROM orders WHERE ref=?',ref);if(current.status!=='pending'){db.exec('COMMIT');return current.status}run("UPDATE orders SET status='paid',transaction_id=? WHERE ref=? AND status='pending'",'flutterwave:'+paymentMode+':'+d.id,ref);run('INSERT OR IGNORE INTO access VALUES(?,?)',o.user,o.course);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return 'paid';
 }
 const limits=new Map();
 function rate(key,max){const now=Date.now();let v=limits.get(key);if(!v||v.until<now){v={count:0,until:now+600000};limits.set(key,v)}if(++v.count>max)fail(429,'Too many attempts. Try again in 10 minutes.');if(limits.size>10000)for(const [k,v]of limits)if(v.until<now)limits.delete(k)}
 const server=createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");if(production)res.setHeader('Strict-Transport-Security','max-age=31536000');
  const send=(data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(data))};
  try{
   const url=new URL(req.url,origin),p=url.pathname, post=req.method==='POST';
   if(!['GET','POST'].includes(req.method))fail(405,'Method not allowed');
   const sid=req.headers.cookie?.match(/(?:^|;\s*)session=([a-f0-9]{64})(?:;|$)/)?.[1];
   const user=sid?get('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user WHERE token=? AND expires>?',hash(sid),Date.now()):null;
   const admin=!!user?.verified&&user.email===(env.ADMIN_EMAIL||'').toLowerCase();
   const auth=()=>{if(!user)fail(401,'Please sign in');if(!user.verified)fail(403,'Verify your email first');return user};
   let b={};if(post){if(p!=='/api/webhook'&&req.headers.origin!==origin)fail(403,'Request origin rejected');if(!req.headers['content-type']?.startsWith('application/json'))fail(415,'JSON required');let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>200000)fail(413,'Request too large')}try{b=JSON.parse(raw)}catch{fail(400,'Invalid JSON')}if(!b||typeof b!=='object'||Array.isArray(b))fail(400,'Invalid request');}
   if(p.startsWith('/api/')&&p!=='/api/webhook')rate('ip:'+req.socket.remoteAddress,300);
   if(post&&['/api/register','/api/login','/api/forgot','/api/resend'].includes(p)){rate('auth:'+req.socket.remoteAddress,30);rate('email:'+String(b.email).toLowerCase(),8)}
   if(p==='/api/register'&&post){const e=email(b.email),pw=await passwordHash(password(b.password));if(typeof b.name!=='string'||!b.name.trim()||b.name.length>60)fail(400,'Enter your name');if(!get('SELECT id FROM users WHERE email=?',e)){const id=token();run('INSERT INTO users(id,email,name,password) VALUES(?,?,?,?)',id,e,b.name.trim(),pw);await mail({id,email:e},'verify')}return send({message:'If this email is new, a verification link has been sent. Existing students can sign in or reset their password.'})}
   if(p==='/api/login'&&post){const u=get('SELECT * FROM users WHERE email=?',email(b.email));password(b.password);const [salt,stored]=(u?.password||dummy).split(':');if(!equal((await scrypt(b.password,salt,64)).toString('hex'),stored)||!u)fail(401,'Email or password incorrect');if(!u.verified)fail(403,'Verify your email before signing in');if(sid)run('DELETE FROM sessions WHERE token=?',hash(sid));const raw=token();run('INSERT INTO sessions VALUES(?,?,?)',hash(raw),u.id,Date.now()+604800000);res.setHeader('Set-Cookie',`session=${raw}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${production?'; Secure':''}`);return send({ok:true})}
   if(post&&(p==='/api/forgot'||p==='/api/resend')){const u=get('SELECT * FROM users WHERE email=?',email(b.email));if(u&&(p==='/api/forgot'||!u.verified))await mail(u,p==='/api/forgot'?'reset':'verify');return send({message:'If eligible, an email has been sent. Check your inbox and spam folder.'})}
   if(post&&(p==='/api/verify'||p==='/api/reset')){const kind=p.slice(5),t=get('SELECT * FROM tokens WHERE token=? AND kind=? AND expires>?',hash(String(b.token)),kind,Date.now());if(!t)fail(400,'This link is invalid or expired');const pw=kind==='reset'?await passwordHash(password(b.password)):null;db.exec('BEGIN IMMEDIATE');try{const still=get('SELECT token FROM tokens WHERE token=?',t.token);if(!still)fail(400,'Link already used');if(kind==='verify')run('UPDATE users SET verified=1 WHERE id=?',t.user);else{run('UPDATE users SET password=? WHERE id=?',pw,t.user);run('DELETE FROM sessions WHERE user=?',t.user)}run('DELETE FROM tokens WHERE user=? AND kind=?',t.user,kind);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return send({message:'Account updated. You can now sign in.'})}
   if(p==='/api/logout'&&post){if(sid)run('DELETE FROM sessions WHERE token=?',hash(sid));res.setHeader('Set-Cookie','session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');return send({ok:true})}
   if(p==='/api/me')return send({user:user?{name:user.name,email:user.email,admin}:null,access:user?all('SELECT course FROM access WHERE user=?',user.id).map(x=>x.course):[],done:user?all('SELECT lesson FROM progress WHERE user=?',user.id).map(x=>x.lesson):[],paymentMode,payments:env.PAYMENTS_ENABLED==='true'});
   if(p==='/api/courses')return send(all('SELECT * FROM courses').map(c=>({...c,price:7000,lessons:all('SELECT id,title,sample FROM lessons WHERE course=? ORDER BY position,id',c.id)})));
   if(p.startsWith('/api/lesson/')){const l=get('SELECT * FROM lessons WHERE id=?',p.slice(12));if(!l)fail(404,'Lesson missing');if(!l.sample){auth();if(!get('SELECT 1 FROM access WHERE user=? AND course=?',user.id,l.course)&&!admin)fail(403,'Purchase this course to access the lesson')}if(post){auth();if(b.done===true)run('INSERT OR IGNORE INTO progress VALUES(?,?)',user.id,l.id);else run('DELETE FROM progress WHERE user=? AND lesson=?',user.id,l.id);return send({ok:true})}return send(l)}
   if(p==='/api/checkout'&&post){auth();if(env.PAYMENTS_ENABLED!=='true')fail(503,'Payments are not enabled yet');const c=get('SELECT * FROM courses WHERE id=?',String(b.course));if(!c?.published)fail(409,'This course is not open for purchase yet');if(get('SELECT 1 FROM access WHERE user=? AND course=?',user.id,c.id))fail(409,'You already own this course');const prior=get("SELECT * FROM orders WHERE user=? AND course=? AND status='pending' AND provider='flutterwave' AND mode=? ORDER BY created DESC LIMIT 1",user.id,c.id,paymentMode);if(prior?.link)return send({link:prior.link});if(prior&&Date.now()-prior.created<60000)fail(409,'Checkout is being prepared. Try again shortly.');const ref='BRIGHT'+token();run('INSERT INTO orders(ref,user,course,amount,currency,created,provider,mode) VALUES(?,?,?,?,?,?,?,?)',ref,user.id,c.id,7000,'NGN',Date.now(),'flutterwave',paymentMode);const data=await flutterwave('/payments',{tx_ref:ref,amount:7000,currency:'NGN',redirect_url:origin+'/payment-return',customer:{email:user.email,name:user.name},customizations:{title:'Bright Tech Learning',description:c.title+' — one-time course purchase'},meta:{course:c.id},payload_hash:hash('7000'+'NGN'+user.email+ref+hash(env.FLW_SECRET_KEY))});const link=new URL(data.link);if(link.protocol!=='https:'||!(link.hostname==='checkout.flutterwave.com'||(paymentMode==='test'&&link.hostname==='checkout-v2.dev-flutterwave.com'))||link.port||link.username||link.password)fail(502,'Unexpected checkout address: '+link.origin);run('UPDATE orders SET link=? WHERE ref=?',link.href,ref);return send({link:link.href})}
   if(p==='/api/orders'){auth();return send(all('SELECT ref,course,amount,currency,status,created,provider,mode FROM orders WHERE user=? ORDER BY created DESC',user.id))}
   if(p==='/api/check-payment'&&post){auth();const o=get('SELECT * FROM orders WHERE ref=? AND user=?',String(b.ref),user.id);if(!o)fail(404,'Order not found');if(o.provider!=='flutterwave'||o.mode!==paymentMode)fail(409,'This order belongs to a different payment provider or mode. Contact support.');if(o.status!=='pending')return send({status:o.status});return send({status:await verify(o.ref)})}
   if(p==='/api/webhook'&&post){
    if(!env.FLW_SECRET_KEY||!env.FLW_WEBHOOK_SECRET)fail(503,'Payments not configured');
    // Flutterwave v3 Standard uses verif-hash (not the v4 HMAC contract).
    if(!equal(req.headers['verif-hash'],env.FLW_WEBHOOK_SECRET))fail(401,'Invalid webhook signature');
    if(b.event==='charge.completed'&&b.data?.status==='successful'&&typeof b.data.tx_ref==='string'){
     const o=get('SELECT provider,mode FROM orders WHERE ref=?',b.data.tx_ref);
     if(o?.provider==='flutterwave'&&o.mode===paymentMode)await verify(b.data.tx_ref);
    }
    return send({ok:true});
   }
   if(p==='/payment-return'){if(url.searchParams.get('tx_ref')){try{await verify(url.searchParams.get('tx_ref'))}catch{/* A browser callback cannot grant access without verification. Retry from the app. */}}res.writeHead(200,{'Content-Type':'text/html'});return res.end('<!doctype html><meta name="viewport" content="width=device-width"><title>Bright Tech payment</title><h1>Return to Bright Tech</h1><p>Reopen the app and select Orders → Check payment. Access appears after payment verification.</p><a href="/#orders">View orders in this browser</a>')}
   if(p.startsWith('/api/admin/')){auth();if(!admin)fail(403,'Admin only')}
   if(p==='/api/admin/dashboard'&&!post){
    const page=Math.max(0,Math.min(100000,Number(url.searchParams.get('page'))||0)), offset=Math.floor(page)*50;
    return send({totals:{students:get('SELECT COUNT(*) n FROM users').n,verified:get('SELECT COUNT(*) n FROM users WHERE verified=1').n,courses:get('SELECT COUNT(*) n FROM courses').n,published:get('SELECT COUNT(*) n FROM courses WHERE published=1').n,paidOrders:get("SELECT COUNT(*) n FROM orders WHERE status='paid'").n,paidAmount:get("SELECT COALESCE(SUM(amount),0) n FROM orders WHERE status='paid'").n,pending:get("SELECT COUNT(*) n FROM orders WHERE status='pending'").n},students:all('SELECT id,name,email,verified FROM users ORDER BY rowid DESC LIMIT 50 OFFSET ?',offset).map(u=>({...u,enrollments:all('SELECT courses.id,courses.title FROM access JOIN courses ON courses.id=access.course WHERE user=?',u.id).map(c=>({...c,completed:get('SELECT COUNT(*) n FROM progress JOIN lessons ON lessons.id=progress.lesson WHERE user=? AND course=?',u.id,c.id).n,total:get('SELECT COUNT(*) n FROM lessons WHERE course=?',c.id).n}))})),orders:all('SELECT orders.ref,orders.course,orders.amount,orders.currency,orders.status,orders.created,orders.provider,orders.mode,users.name,users.email,courses.title FROM orders JOIN users ON users.id=orders.user JOIN courses ON courses.id=orders.course ORDER BY orders.created DESC LIMIT 50 OFFSET ?',offset),page:Math.floor(page)});
   }
   if(p==='/api/admin/course-save'&&post){
    const id=String(b.id||'');if(!/^[a-z0-9][a-z0-9-]{0,59}$/.test(id))fail(400,'Use a course ID with lowercase letters, numbers and hyphens');
    for(const [key,max] of [['title',160],['category',60],['description',2000]])if(typeof b[key]!=='string'||!b[key].trim()||b[key].length>max)fail(400,'Enter a valid '+key);
    if(!['project-web.jpg','course-javascript.jpg','course-python.png','project-ui.jpg','course-graphic-design.jpg','project-python.jpg'].includes(b.image))fail(400,'Choose an available cover image');
    const existing=get('SELECT id FROM courses WHERE id=?',id);if(b.create&&existing)fail(409,'Course ID already exists');if(!b.create&&!existing)fail(404,'Course not found');
    if(existing)run('UPDATE courses SET title=?,category=?,description=?,image=? WHERE id=?',b.title.trim(),b.category.trim(),b.description.trim(),b.image,id);
    else run('INSERT INTO courses(id,title,category,image,description) VALUES(?,?,?,?,?)',id,b.title.trim(),b.category.trim(),b.image,b.description.trim());
    return send({ok:true,id});
   }
   if(p==='/api/admin/lessons'&&!post)return send(all('SELECT * FROM lessons WHERE course=? ORDER BY position,id',url.searchParams.get('course')||''));
   if(p==='/api/admin/course'&&post){auth();if(!admin)fail(403,'Admin only');const c=get('SELECT id FROM courses WHERE id=?',String(b.course));if(!c)fail(404,'Course missing');if(b.published&&!get('SELECT 1 FROM lessons WHERE course=? AND sample=0',c.id))fail(400,'Add full teaching content before publishing');run('UPDATE courses SET published=? WHERE id=?',b.published?1:0,c.id);return send({ok:true})}
   if(p==='/api/admin/lesson'&&post){auth();if(!admin)fail(403,'Admin only');if(!get('SELECT id FROM courses WHERE id=?',String(b.course)))fail(404,'Course missing');if(typeof b.title!=='string'||!b.title.trim()||b.title.length>160||typeof b.body!=='string'||!b.body.trim()||b.body.length>100000)fail(400,'Provide a title and lesson text');const id=b.id?String(b.id):token();const existing=get('SELECT course FROM lessons WHERE id=?',id);if(existing&&existing.course!==b.course)fail(400,'Wrong course');run('INSERT INTO lessons VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,body=excluded.body,sample=excluded.sample,position=excluded.position',id,b.course,b.title,b.body,b.sample===true?1:0,Number.isInteger(b.position)?b.position:100);return send({ok:true,id})}
   if(p==='/api/admin/revoke'&&post){auth();if(!admin)fail(403,'Admin only');const o=get('SELECT * FROM orders WHERE ref=?',String(b.ref));if(!o)fail(404,'Order missing');db.exec('BEGIN');try{run("UPDATE orders SET status='revoked' WHERE ref=?",o.ref);run('DELETE FROM access WHERE user=? AND course=?',o.user,o.course);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return send({ok:true})}
   if(p.startsWith('/api/'))fail(404,'Not found');if(post)fail(405,'Method not allowed');
   const file=p==='/'?'index.html':p.slice(1);if(!/^(index\.html|app\.js|admin\.js|style\.css|assets\/[a-zA-Z0-9_.-]+)$/.test(file))fail(404,'Not found');let content;try{content=readFileSync(resolve(root,'web',file))}catch{fail(404,'Not found')}res.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.png':'image/png','.jpg':'image/jpeg'})[extname(file)]||'application/octet-stream'});res.end(content);
  }catch(e){send({error:e.status?e.message:'Service temporarily unavailable'},e.status||500)}
 });
 server.requestTimeout=20000;server.headersTimeout=10000;
 return {server,db,verify};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){const {server}=await createApp();server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Bright Tech server started'));}
