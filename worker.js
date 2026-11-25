const COOKIE = "codeysa_session";
const SESSION_DAYS = 7;
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const fail = (message, status = 400) => json({ error: message }, status);
const enc = new TextEncoder();
const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const randomToken = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
async function digest(value) { return b64url(await crypto.subtle.digest("SHA-256", enc.encode(value))); }
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return b64url(await crypto.subtle.deriveBits({ name:"PBKDF2", salt:enc.encode(salt), iterations:210000, hash:"SHA-256" }, key, 256));
}
const cookie = (value, maxAge) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
function getCookie(request) { return (request.headers.get("Cookie") || "").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1) || ""; }
async function userFor(request, env) {
  const token = getCookie(request); if (!token) return null;
  return await env.DB.prepare("SELECT u.id,u.name,u.email,u.role,u.status,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at > datetime('now') AND u.status='active'").bind(await digest(token)).first();
}
async function body(request) { try { return await request.json(); } catch { return null; } }
function validEmail(v) { return typeof v==="string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length<=190; }
function safeText(v,max=160) { return typeof v==="string" ? v.trim().slice(0,max) : ""; }
async function requireUser(request,env) { const u=await userFor(request,env); return u || null; }
async function route(request, env) {
  const url=new URL(request.url), path=url.pathname, method=request.method;
  if (path==="/api/health") {
    const result={ok:true,service:"CODEYSA marketplace API",databaseBinding:!!env.DB,assetsBinding:!!env.ASSETS};
    if(env.DB){try{await env.DB.prepare("SELECT 1 AS ok").first();result.database="connected";}catch(e){console.error("D1 health check failed:",e?.stack||e);result.database="error";}}
    else result.database="missing";
    return json(result,result.database==="connected"?200:503);
  }
  if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
  if (method==="OPTIONS") return new Response(null,{status:204,headers:{Allow:"GET,POST,PUT,DELETE,OPTIONS"}});
  if (["POST","PUT","DELETE"].includes(method)) {
    const origin=request.headers.get("Origin");
    if (origin && origin!==url.origin) return fail("Cross-origin request rejected.",403);
  }
  if (path==="/api/register" && method==="POST") {
    const b=await body(request); if (!b) return fail("Invalid request body.");
    const name=safeText(b.name,100), email=safeText(b.email,190).toLowerCase(), password=b.password, role=b.role;
    if (name.length<2 || !validEmail(email) || typeof password!=="string" || password.length<12 || password.length>128) return fail("Enter your name, a valid email and a password of at least 12 characters.");
    if (!["buyer","supplier"].includes(role)) return fail("Choose buyer or supplier account.");
    const id=crypto.randomUUID(), salt=randomToken(), hash=await passwordHash(password,salt), status=role==="supplier"?"pending":"active";
    try { await env.DB.prepare("INSERT INTO users (id,name,email,password_hash,password_salt,role,status) VALUES (?,?,?,?,?,?,?)").bind(id,name,email,hash,salt,role,status).run(); }
    catch { return fail("That email may already be registered.",409); }
    return json({message:role==="supplier"?"Supplier application received. Your account is pending administrator review.":"Buyer account created. You can now sign in.",status},201);
  }
  if (path==="/api/login" && method==="POST") {
    const b=await body(request); if (!b || !validEmail(b.email) || typeof b.password!=="string") return fail("Enter your email and password.");
    const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(b.email.toLowerCase()).first();
    if (!u || (await passwordHash(b.password,u.password_salt)) !== u.password_hash) return fail("Email or password is incorrect.",401);
    if (u.status!=="active") return fail(u.status==="pending"?"Supplier account awaiting approval.":"This account is not active.",403);
    const token=randomToken(), expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString().replace("T"," ").slice(0,19);
    await env.DB.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)").bind(crypto.randomUUID(),u.id,await digest(token),expires).run();
    return json({user:{id:u.id,name:u.name,email:u.email,role:u.role}},200,{ "set-cookie":cookie(token,SESSION_DAYS*86400) });
  }
  if (path==="/api/logout" && method==="POST") {
    const token=getCookie(request); if(token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return json({ok:true},200,{"set-cookie":cookie("",0)});
  }
  if (path==="/api/me" && method==="GET") { const u=await userFor(request,env); return u?json({user:u}):fail("Please sign in.",401); }
  const user=await requireUser(request,env); if(!user) return fail("Please sign in.",401);
  if(path==="/api/supplier/profile" && method==="GET") {
    if(user.role!=="supplier") return fail("Supplier account required.",403);
    const profile=await env.DB.prepare("SELECT * FROM supplier_profiles WHERE user_id=?").bind(user.id).first();
    return json({profile});
  }
  if(path==="/api/supplier/profile" && method==="PUT") {
    if(user.role!=="supplier") return fail("Supplier account required.",403);
    const b=await body(request); if(!b) return fail("Invalid request body.");
    await env.DB.prepare("INSERT INTO supplier_profiles (user_id,business_name,country,description,phone,website) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET business_name=excluded.business_name,country=excluded.country,description=excluded.description,phone=excluded.phone,website=excluded.website,updated_at=datetime('now')").bind(user.id,safeText(b.business_name,140),safeText(b.country,100),safeText(b.description,1200),safeText(b.phone,40),safeText(b.website,200)).run();
    return json({ok:true,message:"Supplier profile saved."});
  }
  if(path==="/api/products" && method==="GET") {
    const rows=await env.DB.prepare("SELECT p.id,p.supplier_id,p.name,p.category,p.description,p.unit,p.origin,p.status,p.created_at,sp.business_name FROM products p JOIN supplier_profiles sp ON sp.user_id=p.supplier_id WHERE p.status='published' ORDER BY p.created_at DESC LIMIT 100").all();
    return json({products:rows.results});
  }
  if(path==="/api/products" && method==="POST") {
    if(user.role!=="supplier") return fail("Supplier account required.",403);
    const b=await body(request); if(!b) return fail("Invalid request body.");
    const name=safeText(b.name,140), category=safeText(b.category,80), description=safeText(b.description,1200);
    if(name.length<2 || !category || description.length<10) return fail("Add a product name, category and description.");
    const id=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO products (id,supplier_id,name,category,description,unit,origin,status) VALUES (?,?,?,?,?,?,?,'pending')").bind(id,user.id,name,category,description,safeText(b.unit,40),safeText(b.origin,100)||"São Tomé and Príncipe").run();
    return json({ok:true,message:"Product submitted for review.",id},201);
  }
  if(path==="/api/admin/suppliers" && method==="GET") {
    if(user.role!=="admin") return fail("Administrator access required.",403);
    const rows=await env.DB.prepare("SELECT u.id,u.name,u.email,u.status,u.created_at,p.business_name,p.country FROM users u LEFT JOIN supplier_profiles p ON p.user_id=u.id WHERE u.role='supplier' ORDER BY u.created_at DESC").all();
    return json({suppliers:rows.results});
  }
  if(path.startsWith("/api/admin/suppliers/") && method==="POST") {
    if(user.role!=="admin") return fail("Administrator access required.",403);
    const id=path.split("/").pop(), b=await body(request);
    if(!["active","rejected","suspended"].includes(b?.status)) return fail("Invalid supplier status.");
    await env.DB.prepare("UPDATE users SET status=? WHERE id=? AND role='supplier'").bind(b.status,id).run();
    return json({ok:true});
  }
  return fail("API route not found.",404);
}
export default { async fetch(request,env) { try { return await route(request,env); } catch(e) { console.error("CODEYSA Worker error:",e?.stack||e); return json({error:"Service temporarily unavailable."},500); } } };
