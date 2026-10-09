import {createHash} from 'node:crypto';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {createApp} from '../server/main.js';
test('registration, recovery, protected content and verified payments',async()=>{
 const dir=mkdtempSync(tmpdir()+'/bright-');let verified={},paymentBody;
 const app=await createApp({DATA_DIR:dir,APP_ORIGIN:'http://localhost:3000',ADMIN_EMAIL:'owner@example.com',PAYMENTS_ENABLED:'true',FLW_SECRET_KEY:'FLWSECK_TEST-mock',FLW_MODE:'test',FLW_WEBHOOK_SECRET:'test-webhook-secret-at-least-32-characters'},async(url,opt)=>{
 if(url.endsWith('/payments')){paymentBody=JSON.parse(opt.body);return Response.json({status:'success',data:{link:'https://checkout.flutterwave.com/v3/hosted/pay/test'}})}
 return Response.json({status:'success',data:verified});});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+app.server.address().port;let cookie='';
 const request=async(path,body,headers={})=>{const r=await fetch(base+'/api/'+path,{headers:{Origin:'http://localhost:3000',Cookie:cookie,'Content-Type':'application/json',...headers},...(body?{method:'POST',body:JSON.stringify(body)}:{})});return {status:r.status,data:await r.json(),cookie:r.headers.get('set-cookie')}};
 try{
 assert.equal((await request('register',{name:'Student',email:'student@example.com',password:'secure password 123'})).status,200);
 assert.equal((await request('login',{email:'student@example.com',password:'secure password 123'})).status,403);
 const t=readFileSync(dir+'/dev-mail.txt','utf8').match(/#verify\/([a-f0-9]+)/)[1];assert.equal((await request('verify',{token:t})).status,200);assert.equal((await request('verify',{token:t})).status,400);
 const login=await request('login',{email:'student@example.com',password:'secure password 123'});assert.equal(login.status,200);assert.match(login.cookie,/HttpOnly/);cookie=login.cookie.split(';')[0];
 assert.equal((await request('logout',{}, {Origin:'https://evil.example'})).status,403);
 assert.equal((await request('checkout',{course:'html',amount:1})).status,409);
 app.db.prepare("INSERT INTO lessons VALUES('paid','html','Full lesson','SECRET',0,10)").run();
 app.db.prepare("UPDATE courses SET published=1 WHERE id='html'").run();
 assert.equal((await request('lesson/paid')).status,403);
 assert.equal((await request('admin/course',{course:'html',published:false})).status,403);
 assert.equal((await request('checkout',{course:'html',amount:1})).status,200);assert.equal(paymentBody.amount,7000);assert.equal(paymentBody.currency,'NGN');
 const ref=paymentBody.tx_ref;verified={tx_ref:ref,status:'successful',amount:1,currency:'NGN',customer:{email:'student@example.com'},id:42};
 const payload={event:'charge.completed',data:{tx_ref:ref,status:'successful',id:42}};const webhook=()=>request('webhook',payload,{'verif-hash':'test-webhook-secret-at-least-32-characters'});
 assert.equal((await webhook()).status,409);assert.equal((await request('lesson/paid')).status,403);
 verified.amount=7000;verified.currency='USD';assert.equal((await webhook()).status,409);verified.currency='NGN';verified.customer.email='other@example.com';assert.equal((await webhook()).status,409);verified.customer.email='student@example.com';
 assert.equal((await request('webhook',payload)).status,401);
 verified.status='Pending';assert.equal((await webhook()).status,409);verified.status='successful';verified.tx_ref='wrong-reference';assert.equal((await webhook()).status,409);verified.tx_ref=ref;
 assert.equal((await request('webhook',payload,{'verif-hash':'wrong-secret'})).status,401);
 const digest=v=>createHash('sha256').update(v).digest('hex');
 assert.equal(paymentBody.payload_hash,digest('7000NGNstudent@example.com'+ref+digest('FLWSECK_TEST-mock')));
 assert.equal(paymentBody.redirect_url,'http://localhost:3000/payment-return');
 assert.equal(paymentBody.customer.email,'student@example.com');
 // A forged success redirect still requires a matching provider response.
 verified.amount=1;await fetch(base+'/payment-return?status=successful&tx_ref='+ref+'&transaction_id=42');assert.equal((await request('lesson/paid')).status,403);verified.amount=7000;
 verified.id=null;assert.equal((await webhook()).status,409);verified.id=42;
 assert.equal((await webhook()).status,200);assert.equal((await webhook()).status,200);assert.equal(app.db.prepare('SELECT COUNT(*) n FROM access').get().n,1);
 assert.equal((await request('lesson/paid')).data.body,'SECRET');assert.equal((await request('lesson/paid',{done:true})).status,200);assert.deepEqual((await request('me')).data.done,['paid']);
 assert.equal((await request('check-payment',{ref:'someone-elses-order'})).status,404);
 await request('forgot',{email:'student@example.com'});const reset=readFileSync(dir+'/dev-mail.txt','utf8').match(/#reset\/([a-f0-9]+)/)[1];assert.equal((await request('reset',{token:reset,password:'new secure password'})).status,200);assert.equal((await request('me')).data.user,null);assert.equal((await request('reset',{token:reset,password:'another password'})).status,400);
 }finally{await new Promise(r=>app.server.close(r));app.db.close();rmSync(dir,{recursive:true,force:true})}
});
test('production refuses incomplete deployment configuration',async()=>{await assert.rejects(createApp({NODE_ENV:'production'}),/Production requires/)});
test('admin course management and monitoring stay restricted to verified owner',async()=>{
 const dir=mkdtempSync(tmpdir()+'/bright-admin-');const app=await createApp({DATA_DIR:dir,APP_ORIGIN:'http://localhost:3000',ADMIN_EMAIL:'owner@example.com'});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+app.server.address().port;let cookie='';
 const req=async(path,body)=>{const r=await fetch(base+'/api/'+path,{headers:{Origin:'http://localhost:3000',Cookie:cookie,'Content-Type':'application/json'},...(body?{method:'POST',body:JSON.stringify(body)}:{})});return {status:r.status,data:await r.json(),cookie:r.headers.get('set-cookie')}};
 try{
 assert.equal((await req('admin/dashboard')).status,401);
 await req('register',{name:'Owner',email:'owner@example.com',password:'owner secure password'});
 const raw=readFileSync(dir+'/dev-mail.txt','utf8').match(/#verify\/([a-f0-9]+)/)[1];await req('verify',{token:raw});cookie=(await req('login',{email:'owner@example.com',password:'owner secure password'})).cookie.split(';')[0];
 assert.equal((await req('me')).data.user.admin,true);
 const c={id:'new-course',title:'New course',category:'Design',description:'Course description',image:'project-web.jpg',create:true};
 assert.equal((await req('admin/course-save',c)).status,200);assert.equal((await req('admin/course-save',c)).status,409);
 assert.equal((await req('admin/course',{course:c.id,published:true})).status,400);
 const lesson=(await req('admin/lesson',{course:c.id,title:'Lesson',body:'Full course text',position:0,sample:false})).data.id;
 assert.equal((await req('admin/course',{course:c.id,published:true})).status,200);
 assert.equal((await req('admin/course-save',{...c,create:false,title:'Updated course'})).status,200);
 assert.equal((await req('courses')).data.find(x=>x.id===c.id).title,'Updated course');assert.equal((await req('courses')).data.find(x=>x.id===c.id).price,7000);
 assert.equal((await req('admin/lesson',{course:c.id,id:lesson,title:'Edited lesson',body:'Updated content',position:1,sample:false})).status,200);
 assert.equal((await req('admin/lessons?course=new-course')).data[0].body,'Updated content');assert.equal((await req('admin/dashboard')).data.totals.courses,8);
 cookie='';assert.equal((await req('lesson/'+lesson)).status,401);
 await req('register',{name:'Student',email:'reader@example.com',password:'reader secure password'});const mails=readFileSync(dir+'/dev-mail.txt','utf8');const tokens=[...mails.matchAll(/#verify\/([a-f0-9]+)/g)];await req('verify',{token:tokens.at(-1)[1]});cookie=(await req('login',{email:'reader@example.com',password:'reader secure password'})).cookie.split(';')[0];
 assert.equal((await req('admin/dashboard')).status,403);assert.equal((await req('admin/course-save',{...c,id:'forbidden'})).status,403);assert.equal((await req('admin/lessons?course=new-course')).status,403);
 }finally{await new Promise(r=>app.server.close(r));app.db.close();rmSync(dir,{recursive:true,force:true})}
});

test('Flutterwave configuration rejects mismatched keys and local live payments',async()=>{
 const common={PAYMENTS_ENABLED:'true',FLW_WEBHOOK_SECRET:'test-webhook-secret-at-least-32-characters'};
 await assert.rejects(createApp({...common,FLW_MODE:'test',FLW_SECRET_KEY:'FLWSECK-live'}),/matching FLW_MODE/);
 await assert.rejects(createApp({...common,FLW_MODE:'live',FLW_SECRET_KEY:'FLWSECK_TEST-test'}),/matching FLW_MODE/);
 await assert.rejects(createApp({...common,FLW_MODE:'live',FLW_SECRET_KEY:'FLWSECK-live'}),/Live payments require/);
 await assert.rejects(createApp({...common,FLW_MODE:'test',FLW_SECRET_KEY:'FLWSECK_TEST-test',FLW_WEBHOOK_SECRET:''}),/FLW_WEBHOOK_SECRET/);
});

test('migration preserves content, isolates old orders and protects against test-to-live reuse',async()=>{
 const dir=mkdtempSync(tmpdir()+'/bright-migration-');
 let app=await createApp({DATA_DIR:dir});
 try{
 app.db.prepare("INSERT INTO users(id,email,name,password,verified) VALUES('u','student@example.com','Student','unused',1)").run();
 app.db.prepare("INSERT INTO orders(ref,user,course,amount,currency,created,link) VALUES('old','u','html',7000,'NGN',0,'https://sandbox-pay.squadco.com/old')").run();
 app.db.prepare("UPDATE courses SET description='Keep my edited content' WHERE id='html'").run();
 app.db.exec('ALTER TABLE orders DROP COLUMN provider; ALTER TABLE orders DROP COLUMN mode;');
 app.db.close();
 app=await createApp({DATA_DIR:dir,FLW_MODE:'test'},async()=>{throw Error('Old order must never reach Flutterwave')});
 assert.equal(app.db.prepare("SELECT description FROM courses WHERE id='html'").get().description,'Keep my edited content');
 await assert.rejects(app.verify('old'),/different payment provider/);
 app.db.prepare("INSERT INTO orders(ref,user,course,amount,currency,created,provider,mode) VALUES('test','u','html',7000,'NGN',1,'flutterwave','test')").run();
 app.db.close();
 await assert.rejects(createApp({DATA_DIR:dir,FLW_MODE:'live'}),/separate clean production DATA_DIR/);
 }finally{try{app.db.close()}catch{}rmSync(dir,{recursive:true,force:true})}
});

test('checkout rejects unexpected hosts and verification is idempotent under concurrent delivery',async()=>{
 const dir=mkdtempSync(tmpdir()+'/bright-checkout-');let calls=0,link='https://evil.example/pay',ref,txid=123;
 const app=await createApp({DATA_DIR:dir,APP_ORIGIN:'http://localhost:3000',PAYMENTS_ENABLED:'true',FLW_MODE:'test',FLW_SECRET_KEY:'FLWSECK_TEST-mock',FLW_WEBHOOK_SECRET:'test-webhook-secret-at-least-32-characters'},async(url,opt)=>{
  assert.equal(opt.headers.Authorization,'Bearer FLWSECK_TEST-mock');
  if(url==='https://api.flutterwave.com/v3/payments'){calls++;ref=JSON.parse(opt.body).tx_ref;return Response.json({status:'success',data:{link}})}
  assert.match(url,/^https:\/\/api\.flutterwave\.com\/v3\/transactions\/verify_by_reference\?tx_ref=/);
  await new Promise(r=>setTimeout(r,5));
  return Response.json({status:'success',data:{tx_ref:new URL(url).searchParams.get('tx_ref'),id:txid,status:'successful',amount:7000,currency:'NGN',customer:{email:'student@example.com'}}});
 });
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+app.server.address().port;
 const raw='a'.repeat(64),digest=createHash('sha256').update(raw).digest('hex');
 const req=async(path,body)=>fetch(base+'/api/'+path,{method:'POST',headers:{Origin:'http://localhost:3000',Cookie:'session='+raw,'Content-Type':'application/json'},body:JSON.stringify(body)});
 try{
 app.db.prepare("INSERT INTO users(id,email,name,password,verified) VALUES('u','student@example.com','Student','unused',1)").run();
 app.db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(digest,'u',Date.now()+600000);
 app.db.prepare("UPDATE courses SET published=1 WHERE id='html'").run();
 app.db.prepare("INSERT INTO orders(ref,user,course,amount,currency,created,link) VALUES('old','u','html',7000,'NGN',0,'https://sandbox-pay.squadco.com/old')").run();
 assert.equal((await req('checkout',{course:'html',amount:1})).status,502);assert.equal(calls,1);
 assert.equal(app.db.prepare('SELECT COUNT(*) n FROM access').get().n,0);
 app.db.prepare("UPDATE orders SET created=0 WHERE provider='flutterwave'").run();link='https://checkout.flutterwave.com/v3/hosted/pay/test';
 assert.equal((await req('checkout',{course:'html'})).status,200);assert.equal(calls,2);
 assert.equal((await req('checkout',{course:'html'})).status,200);assert.equal(calls,2);
 await Promise.all([app.verify(ref),app.verify(ref)]);assert.equal(app.db.prepare('SELECT COUNT(*) n FROM access').get().n,1);
 assert.equal((await req('checkout',{course:'html'})).status,409);
 // Provider transaction IDs cannot pay two different orders.
 app.db.prepare("INSERT INTO orders(ref,user,course,amount,currency,created,provider,mode) VALUES('duplicate','u','js',7000,'NGN',0,'flutterwave','test')").run();
 await assert.rejects(app.verify('duplicate'));assert.equal(app.db.prepare("SELECT COUNT(*) n FROM access WHERE course='js'").get().n,0);
 app.db.prepare("UPDATE orders SET status='revoked' WHERE ref=?").run(ref);app.db.prepare('DELETE FROM access').run();
 assert.equal(await app.verify(ref),'revoked');assert.equal(app.db.prepare('SELECT COUNT(*) n FROM access').get().n,0);
 }finally{await new Promise(r=>app.server.close(r));app.db.close();rmSync(dir,{recursive:true,force:true})}
});
