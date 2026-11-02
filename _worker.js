const json=(data,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
const idOK=id=>/^[0-9a-f-]{36}$/.test(id);
let keyCache;
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
async function authorized(request,env){
 if(!env.ADMIN_EMAIL||!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD)return false;
 const token=request.headers.get('Cf-Access-Jwt-Assertion');if(!token)return false;
 try{
 const [h,p,s]=token.split('.');const header=JSON.parse(new TextDecoder().decode(decode(h))),claims=JSON.parse(new TextDecoder().decode(decode(p)));
 const issuer='https://'+env.ACCESS_TEAM_DOMAIN;const now=Date.now()/1000;
 if(header.alg!=='RS256'||claims.iss!==issuer||!Number.isFinite(claims.exp)||claims.exp<=now||(claims.nbf&&claims.nbf>now)||!Array.isArray(claims.aud)||!claims.aud.includes(env.ACCESS_AUD)||claims.email?.toLowerCase()!==env.ADMIN_EMAIL.toLowerCase())return false;
 if(!keyCache||keyCache.issuer!==issuer||keyCache.until<Date.now()){const r=await fetch(issuer+'/cdn-cgi/access/certs');if(!r.ok)return false;keyCache={issuer,until:Date.now()+300000,keys:(await r.json()).keys};}
 const jwk=keyCache.keys.find(k=>k.kid===header.kid);if(!jwk)return false;
 const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 return crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decode(s),new TextEncoder().encode(h+'.'+p));
 }catch{return false;}
}
async function records(bucket){let cursor,all=[];do{const page=await bucket.list({prefix:'beats/',cursor,limit:100});const values=await Promise.all(page.objects.map(o=>bucket.get(o.key).then(o=>o?.json())));all.push(...values.filter(Boolean));cursor=page.truncated?page.cursor:undefined;}while(cursor);return all.sort((a,b)=>b.created.localeCompare(a.created));}

const ARTISTS=['Future','Travis Scott','Juice WRLD','XXXTentacion','Lil Peep','Other'];
async function objects(bucket,prefix){let cursor,all=[];do{const page=await bucket.list({prefix,cursor,limit:1000,include:['customMetadata']});all.push(...page.objects);cursor=page.truncated?page.cursor:undefined;}while(cursor);return all;}
async function stats(bucket,id,visitor){const list=await objects(bucket,'community/'+id+'/');return {likes:list.filter(o=>o.key.includes('/likes/')).length,views:list.filter(o=>o.key.includes('/views/')).length,comments:list.filter(o=>o.key.includes('/comments/')&&o.customMetadata?.status==='approved').length,liked:!!visitor&&list.some(o=>o.key.endsWith('/likes/'+visitor))};}
const visitorID=request=>{const id=request.headers.get('X-Visitor-ID');return idOK(id||'')?id:null;};
async function smallBody(request){const raw=await request.text();if(raw.length>2048)throw Error('Request too large');return JSON.parse(raw);}
async function community(request,env,url){
 const match=url.pathname.match(/^\/api\/beats\/([0-9a-f-]{36})\/(likes|views|comments)$/);if(!match)return json({error:'Not found'},404);
 if(!env.BEATS)return json({error:'Community is unavailable.'},503);
 const [,id,action]=match,object=await env.BEATS.get('beats/'+id+'.json');if(!object||!(await object.json()).published)return json({error:'Not found'},404);
 const prefix='community/'+id+'/',visitor=visitorID(request);
 if(action==='comments'&&request.method==='GET'){
 const list=(await objects(env.BEATS,prefix+'comments/')).filter(o=>o.customMetadata?.status==='approved').sort((a,b)=>b.key.localeCompare(a.key)).slice(0,100);
 const comments=await Promise.all(list.map(async o=>{const data=await (await env.BEATS.get(o.key)).json();return {id:data.id,name:data.name,text:data.text,created:data.created};}));return json({comments});
 }
 if(!['POST','DELETE'].includes(request.method)||(request.method==='DELETE'&&action!=='likes'))return json({error:'Method not allowed'},405);
 if(request.headers.get('Origin')!==url.origin)return json({error:'Invalid request origin'},403);
 if(!visitor)return json({error:'Please reload and try again.'},400);
 if(action==='comments'){
 let body;try{body=await smallBody(request);}catch{return json({error:'Invalid comment.'},400);}
 if(typeof body.name!=='string'||!body.name.trim()||body.name.length>40||typeof body.text!=='string'||!body.text.trim()||body.text.length>500||body.website)return json({error:'Use a name up to 40 characters and a comment up to 500 characters.'},400);
 if(/https?:\/\/|www\./i.test(body.text))return json({error:'Please leave links out of comments.'},400);
 const ip=request.headers.get('CF-Connecting-IP')||visitor;
 const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode((env.ADMIN_EMAIL||url.host)+ip)))).map(n=>n.toString(16).padStart(2,'0')).join('');
 const limitKey='community-limits/'+digest,prior=await env.BEATS.get(limitKey);
 if(prior&&Date.now()-Number(await prior.text())<300000)return json({error:'Please wait five minutes before commenting again.'},429);
 const claim=await env.BEATS.put(limitKey,String(Date.now()),{onlyIf:prior?{etagMatches:prior.etag}:{etagDoesNotMatch:'*'}});if(!claim)return json({error:'Please wait before commenting again.'},429);
 const created=new Date().toISOString(),commentId=created+'_'+crypto.randomUUID();
 await env.BEATS.put(prefix+'comments/'+commentId,JSON.stringify({id:commentId,beatId:id,name:body.name.trim(),text:body.text.trim(),created}),{customMetadata:{status:'pending'}});
 return json({message:'Thanks! Your comment will appear after approval.'},201);
 }
 const key=prefix+action+'/'+visitor;
 if(request.method==='DELETE')await env.BEATS.delete(key);else await env.BEATS.put(key,'1',{onlyIf:{etagDoesNotMatch:'*'}});
 return json(await stats(env.BEATS,id,visitor));
}

export default {async fetch(request,env){
 const url=new URL(request.url),path=url.pathname;try{
 if(path.startsWith('/admin')||path.startsWith('/api/admin')){
 if(!await authorized(request,env))return new Response('Admin sign-in is required. Dashboard access is not configured or your session has expired.',{status:403,headers:{'Cache-Control':'no-store'}});
 if(!['GET','HEAD'].includes(request.method)&&request.headers.get('Origin')!==url.origin)return json({error:'Invalid request origin'},403);
 }
 if(path==='/admin'||path==='/admin/')return env.ASSETS.fetch(request);
 if(path==='/admin.html')return new Response('Not found',{status:404});
 if(path.startsWith('/api/beats/'))return await community(request,env,url);
 if(path==='/api/beats'){
 if(request.method!=='GET')return json({error:'Method not allowed'},405);
 if(!env.BEATS)return json({beats:[]});
 return json({beats:await Promise.all((await records(env.BEATS)).filter(b=>b.published).map(async ({id,title,bpm,key,artwork,created,artists=[]})=>({id,title,bpm,key,artwork,created,artists,...await stats(env.BEATS,id,visitorID(request))})))});
 }
 if(path.startsWith('/media/')){
 if(!['GET','HEAD'].includes(request.method))return new Response('Method not allowed',{status:405});
 const [, ,id,kind]=path.split('/');if(!idOK(id)||!['wav','art'].includes(kind)||!env.BEATS)return new Response('Not found',{status:404});
 const record=await env.BEATS.get('beats/'+id+'.json');if(!record)return new Response('Not found',{status:404});const beat=await record.json();if(!beat.published)return new Response('Not found',{status:404});
 const object=await env.BEATS.get('files/'+id+'/'+kind,{range:request.headers});if(!object)return new Response('Not found',{status:404});
 const headers=new Headers({'Content-Type':kind==='wav'?'audio/wav':object.httpMetadata?.contentType||'image/jpeg','Accept-Ranges':'bytes','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff','ETag':object.httpEtag});
 let status=200;if(object.range){headers.set('Content-Range',`bytes ${object.range.offset}-${object.range.offset+object.range.length-1}/${object.size}`);headers.set('Content-Length',String(object.range.length));status=206;}else headers.set('Content-Length',String(object.size));
 if(url.searchParams.has('download'))headers.set('Content-Disposition',`attachment; filename="${beat.title.replace(/[^a-zA-Z0-9 _-]/g,'').slice(0,80)||'hellboy-mob-beat'}.wav"`);
 return new Response(request.method==='HEAD'?null:object.body,{status,headers});
 }
 if(path.startsWith('/api/admin/')){
 if(!env.BEATS)return json({error:'Beat storage is not connected yet.'},503);
 if(path==='/api/admin/comments'&&request.method==='GET'){
 const list=(await objects(env.BEATS,'community/')).filter(o=>o.key.includes('/comments/'));
 return json({comments:await Promise.all(list.map(async o=>({...await (await env.BEATS.get(o.key)).json(),status:o.customMetadata?.status||'pending'})))});
 }
 if(path==='/api/admin/comments'&&request.method==='PUT'){
 const body=await smallBody(request);if(!idOK(body.beatId)||typeof body.id!=='string'||!/^\d{4}-\d{2}-\d{2}T[\d:.]+Z_[0-9a-f-]{36}$/.test(body.id)||!['approved','hidden'].includes(body.status))return json({error:'Invalid comment update'},400);
 const key='community/'+body.beatId+'/comments/'+body.id,obj=await env.BEATS.get(key);if(!obj)return json({error:'Not found'},404);
 await env.BEATS.put(key,await obj.text(),{customMetadata:{status:body.status}});return json({ok:true});
 }
 if(path==='/api/admin/beats'&&request.method==='GET')return json({beats:await records(env.BEATS)});
 const match=path.match(/^\/api\/admin\/beats\/([0-9a-f-]{36})(?:\/(wav|art))?$/);if(!match)return json({error:'Not found'},404);const [,id,kind]=match;
 if(kind&&request.method==='PUT'){
 const type=request.headers.get('Content-Type')||'',size=Number(request.headers.get('Content-Length'));
 const limit=kind==='wav'?90*1024*1024:5*1024*1024;
 if(!Number.isFinite(size)||size<=0||size>limit)return json({error:'File exceeds the upload limit.'},413);
 if(kind==='art'&&!['image/jpeg','image/png','image/webp'].includes(type))return json({error:'Use JPG, PNG, or WebP artwork.'},400);
 if(kind==='wav'&&!['audio/wav','audio/x-wav','audio/wave'].includes(type))return json({error:'Use a WAV file.'},400);
 await env.BEATS.put('files/'+id+'/'+kind,request.body,{httpMetadata:{contentType:type}});return json({ok:true});
 }
 if(!kind&&request.method==='PUT'){
 const body=await request.json();if(typeof body.title!=='string'||!body.title.trim()||body.title.length>120)return json({error:'Enter a title (120 characters maximum).'},400);
 if(body.bpm!==''&&(!Number.isFinite(Number(body.bpm))||Number(body.bpm)<20||Number(body.bpm)>300))return json({error:'BPM must be 20–300, or blank.'},400);
 if(typeof body.key!=='string'||body.key.length>40)return json({error:'Invalid musical key'},400);
 if(!await env.BEATS.head('files/'+id+'/wav'))return json({error:'Upload the WAV before saving.'},400);
 const existing=await env.BEATS.get('beats/'+id+'.json');const previous=existing?await existing.json():null;
 if(body.artists!==undefined&&(!Array.isArray(body.artists)||body.artists.length>6||body.artists.some(a=>!ARTISTS.includes(a))))return json({error:'Invalid artist category'},400);
 const record={artists:body.artists===undefined?(previous?.artists||[]):[...new Set(body.artists)],id,title:body.title.trim(),bpm:body.bpm===''?'':Number(body.bpm),key:body.key.trim(),published:body.published===true,artwork:!!await env.BEATS.head('files/'+id+'/art'),created:previous?.created||new Date().toISOString()};
 await env.BEATS.put('beats/'+id+'.json',JSON.stringify(record),{httpMetadata:{contentType:'application/json'}});return json({beat:record});
 }
 return json({error:'Method not allowed'},405);
 }
 return env.ASSETS.fetch(request);
 }catch(error){console.error('Beat API failed',error.message);return json({error:'Something went wrong. Please retry.'},500);}
}};

