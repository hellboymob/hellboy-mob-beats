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
export default {async fetch(request,env){
 const url=new URL(request.url),path=url.pathname;try{
 if(path.startsWith('/admin')||path.startsWith('/api/admin')){
 if(!await authorized(request,env))return new Response('Admin sign-in is required. Dashboard access is not configured or your session has expired.',{status:403,headers:{'Cache-Control':'no-store'}});
 if(!['GET','HEAD'].includes(request.method)&&request.headers.get('Origin')!==url.origin)return json({error:'Invalid request origin'},403);
 }
 if(path==='/admin'||path==='/admin/')return env.ASSETS.fetch(new Request(new URL('/admin.html',url),request));
 if(path==='/admin.html')return new Response('Not found',{status:404});
 if(path==='/api/beats'){
 if(request.method!=='GET')return json({error:'Method not allowed'},405);
 if(!env.BEATS)return json({beats:[]});
 return json({beats:(await records(env.BEATS)).filter(b=>b.published).map(({id,title,bpm,key,artwork,created})=>({id,title,bpm,key,artwork,created}))});
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
 const record={id,title:body.title.trim(),bpm:body.bpm===''?'':Number(body.bpm),key:body.key.trim(),published:body.published===true,artwork:!!await env.BEATS.head('files/'+id+'/art'),created:previous?.created||new Date().toISOString()};
 await env.BEATS.put('beats/'+id+'.json',JSON.stringify(record),{httpMetadata:{contentType:'application/json'}});return json({beat:record});
 }
 return json({error:'Method not allowed'},405);
 }
 return env.ASSETS.fetch(request);
 }catch(error){console.error('Beat API failed',error.message);return json({error:'Something went wrong. Please retry.'},500);}
}};
