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
  return b64url(await crypto.subtle.deriveBits({ name:"PBKDF2", salt:enc.encode(salt), iterations:100000, hash:"SHA-256" }, key, 256));
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
async function audit(env,actorId,action,targetType,targetId,details="") {
  try { await env.DB.prepare("INSERT INTO audit_logs (id,actor_id,action,target_type,target_id,details) VALUES (?,?,?,?,?,?)").bind(crypto.randomUUID(),actorId,action,targetType,targetId,safeText(details,500)).run(); }
  catch(e) { console.error("Audit log write failed:",e?.stack||e); }
}

async function notify(env,recipientId,type,title,message,orderId) {
  if(!recipientId) return;
  await env.DB.prepare("INSERT INTO notifications (id,recipient_id,type,title,message,order_id) VALUES (?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),recipientId,type,safeText(title,140),safeText(message,500),orderId||null).run();
}
async function notifyAdmins(env,type,title,message,orderId,excludeId=null) {
  const admins=await env.DB.prepare("SELECT id FROM users WHERE role='admin' AND status='active'").all();
  for(const admin of admins.results) if(admin.id!==excludeId) await notify(env,admin.id,type,title,message,orderId);
}

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
  if (path==="/api/admin/password-reset" && method==="POST") {
    const b=await body(request);
    if(!env.ADMIN_BOOTSTRAP_TOKEN || request.headers.get("x-admin-bootstrap-token")!==env.ADMIN_BOOTSTRAP_TOKEN) return fail("Invalid reset authorization.",403);
    const email=safeText(b?.email,190).toLowerCase(), password=b?.password;
    if(!validEmail(email) || typeof password!=="string" || password.length<16 || password.length>128) return fail("Enter the administrator email and a new password of at least 16 characters.");
    const admin=await env.DB.prepare("SELECT id FROM users WHERE email=? AND role='admin'").bind(email).first();
    if(!admin) return fail("No administrator account was found for that email.",404);
    const salt=randomToken(), hash=await passwordHash(password,salt);
    await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=? WHERE id=? AND role='admin'").bind(hash,salt,admin.id).run();
    const saved=await env.DB.prepare("SELECT password_hash,password_salt,name,email,role,status FROM users WHERE id=? AND role='admin'").bind(admin.id).first();
    const verified=saved && saved.password_salt===salt && saved.password_hash===await passwordHash(password,saved.password_salt);
    if(!verified) return fail("Password was saved but verification failed. Please contact support.",500);
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(admin.id).run();
    const token=randomToken(), expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString().replace("T"," ").slice(0,19);
    await env.DB.prepare("INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)").bind(crypto.randomUUID(),admin.id,await digest(token),expires).run();
    await audit(env,admin.id,"admin.password_reset","user",admin.id,"Administrator password reset; hash verified and old sessions revoked");
    return json({ok:true,verified:true,message:"Password reset and verified. You are now signed in.",user:{id:admin.id,name:saved.name,email:saved.email,role:saved.role}},200,{"set-cookie":cookie(token,SESSION_DAYS*86400)});
  }
  if (path==="/api/admin/bootstrap" && method==="POST") {
    const b=await body(request);
    if(!env.ADMIN_BOOTSTRAP_TOKEN || request.headers.get("x-admin-bootstrap-token")!==env.ADMIN_BOOTSTRAP_TOKEN) return fail("Invalid bootstrap authorization.",403);
    const existing=await env.DB.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").first();
    if(existing) return fail("An administrator already exists. Bootstrap is closed.",409);
    const name=safeText(b?.name,100), email=safeText(b?.email,190).toLowerCase(), password=b?.password;
    if(name.length<2 || !validEmail(email) || typeof password!=="string" || password.length<16 || password.length>128) return fail("Provide a name, valid email and password of at least 16 characters.");
    const id=crypto.randomUUID(), salt=randomToken(), hash=await passwordHash(password,salt);
    await env.DB.prepare("INSERT INTO users (id,name,email,password_hash,password_salt,role,status) VALUES (?,?,?,?,?,'admin','active')").bind(id,name,email,hash,salt).run();
    await audit(env,id,"admin.bootstrap","user",id,"Initial administrator account created");
    return json({ok:true,message:"Administrator created. Sign in through the account portal."},201);
  }
  if (path==="/api/register" && method==="POST") {
    const b=await body(request); if (!b) return fail("Invalid request body.");
    const name=safeText(b.name,100), email=safeText(b.email,190).toLowerCase(), password=b.password, role=b.role;
    if (name.length<2 || !validEmail(email) || typeof password!=="string" || password.length<12 || password.length>128) return fail("Enter your name, a valid email and a password of at least 12 characters.");
    if (!["buyer","supplier"].includes(role)) return fail("Choose buyer or supplier account.");
    const businessName=safeText(b.business_name,140), country=safeText(b.country,100)||"São Tomé and Príncipe", description=safeText(b.description,1200), phone=safeText(b.phone,40), website=safeText(b.website,200);
    if(role==="supplier" && (businessName.length<2 || description.length<10 || (website && !/^https:\/\//i.test(website)))) return fail("Complete your business name and description. Website must use HTTPS.");
    const id=crypto.randomUUID(), salt=randomToken(), hash=await passwordHash(password,salt), status=role==="supplier"?"pending":"active";
    try {
      await env.DB.prepare("INSERT INTO users (id,name,email,password_hash,password_salt,role,status) VALUES (?,?,?,?,?,?,?)").bind(id,name,email,hash,salt,role,status).run();
      if(role==="supplier") await env.DB.prepare("INSERT INTO supplier_profiles (user_id,business_name,country,description,phone,website) VALUES (?,?,?,?,?,?)").bind(id,businessName,country,description,phone,website).run();
    } catch {
      if(role==="supplier") { try { await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run(); } catch {} }
      return fail("Application could not be saved. Check the details and try again. That email may already be registered.",409);
    }
    return json({message:role==="supplier"?"Supplier application received with your business profile. Your account is pending administrator review.":"Buyer account created. You can now sign in.",status},201);
  }
  if (path==="/api/login" && method==="POST") {
    const b=await body(request); if (!b || !validEmail(b.email) || typeof b.password!=="string") return fail("Enter your email and password.");
    const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(b.email.trim().toLowerCase()).first();
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
  if (path==="/api/rfqs" && method==="POST") {
    const b=await body(request); if(!b) return fail("Invalid request body.");
    if(safeText(b.website,180)) return fail("Request could not be accepted.",400);
    const product=safeText(b.product,180), destination=safeText(b.destination,100), buyerName=safeText(b.buyer_name,120), buyerContact=safeText(b.buyer_contact,180);
    const quantity=safeText(b.quantity,100), requirements=safeText(b.requirements,1800);
    if(product.length<2 || destination.length<2 || buyerName.length<2 || buyerContact.length<5) return fail("Complete the product, destination, name and contact fields.");
    const id=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO rfqs (id,product,quantity,destination,requirements,buyer_name,buyer_contact,status) VALUES (?,?,?,?,?,?,?,'new')").bind(id,product,quantity,destination,requirements,buyerName,buyerContact).run();
    return json({ok:true,message:"Your sourcing request has been received. Our team will review it and contact you.",id},201);
  }
  if (path==="/api/products" && method==="GET") {
    const rows=await env.DB.prepare("SELECT p.id,p.supplier_id,p.name,p.category,p.description,p.unit,p.origin,p.image_url,p.created_at,sp.business_name,sp.country,COALESCE((SELECT ROUND(AVG(r.rating),1) FROM product_reviews r WHERE r.product_id=p.id AND r.status='published'),0) AS average_rating,(SELECT COUNT(*) FROM product_reviews r WHERE r.product_id=p.id AND r.status='published') AS review_count FROM products p JOIN supplier_profiles sp ON sp.user_id=p.supplier_id JOIN users u ON u.id=p.supplier_id WHERE p.status='published' AND u.status='active' AND sp.business_name<>'' ORDER BY p.created_at DESC LIMIT 100").all();
    return json({products:rows.results});
  }
  if (path.startsWith("/api/suppliers/") && method==="GET") {
    const id=decodeURIComponent(path.split("/").pop()||"");
    const supplier=await env.DB.prepare("SELECT u.id,u.status,sp.business_name,sp.country,sp.description,sp.phone,sp.website,sp.verified_at,COALESCE((SELECT ROUND(AVG(r.rating),1) FROM product_reviews r JOIN products p ON p.id=r.product_id WHERE p.supplier_id=u.id AND r.status='published'),0) AS average_rating,(SELECT COUNT(*) FROM product_reviews r JOIN products p ON p.id=r.product_id WHERE p.supplier_id=u.id AND r.status='published') AS review_count FROM users u JOIN supplier_profiles sp ON sp.user_id=u.id WHERE u.id=? AND u.role='supplier' AND u.status='active' AND sp.business_name<>''").bind(id).first();
    if(!supplier) return fail("Supplier storefront not found.",404);
    const products=await env.DB.prepare("SELECT p.id,p.name,p.category,p.description,p.unit,p.origin,p.image_url,p.created_at,COALESCE((SELECT ROUND(AVG(r.rating),1) FROM product_reviews r WHERE r.product_id=p.id AND r.status='published'),0) AS average_rating,(SELECT COUNT(*) FROM product_reviews r WHERE r.product_id=p.id AND r.status='published') AS review_count FROM products p WHERE p.supplier_id=? AND p.status='published' ORDER BY p.created_at DESC LIMIT 100").bind(id).all();
    return json({supplier,products:products.results});
  }
  if(path.startsWith("/api/products/") && path.endsWith("/reviews") && method==="GET") {
    const productId=decodeURIComponent(path.split("/")[3]||"");
    const product=await env.DB.prepare("SELECT id FROM products WHERE id=? AND status='published'").bind(productId).first();
    if(!product) return fail("Product not found.",404);
    const rows=await env.DB.prepare("SELECT r.id,r.rating,r.comment,r.created_at,u.name AS buyer_name FROM product_reviews r JOIN users u ON u.id=r.buyer_id WHERE r.product_id=? AND r.status='published' ORDER BY r.created_at DESC LIMIT 50").bind(productId).all();
    const summary=await env.DB.prepare("SELECT ROUND(AVG(rating),1) AS average_rating,COUNT(*) AS review_count FROM product_reviews WHERE product_id=? AND status='published'").bind(productId).first();
    return json({reviews:rows.results,average_rating:summary.average_rating||0,review_count:summary.review_count||0});
  }
  const user=await requireUser(request,env); if(!user) return fail("Please sign in.",401);
  if(path==="/api/notifications" && method==="GET") {
    const rows=await env.DB.prepare("SELECT id,type,title,message,order_id,read_at,created_at FROM notifications WHERE recipient_id=? ORDER BY created_at DESC LIMIT 50").bind(user.id).all();
    const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM notifications WHERE recipient_id=? AND read_at IS NULL").bind(user.id).first();
    return json({notifications:rows.results,unread:count.n});
  }
  if(path==="/api/notifications/read" && method==="POST") {
    const b=await body(request), ids=Array.isArray(b?.ids)?b.ids.filter(x=>typeof x==="string").slice(0,50):[];
    if(b?.all===true) await env.DB.prepare("UPDATE notifications SET read_at=datetime('now') WHERE recipient_id=? AND read_at IS NULL").bind(user.id).run();
    else if(ids.length) { const marks=ids.map(()=>"?").join(","); await env.DB.prepare("UPDATE notifications SET read_at=datetime('now') WHERE recipient_id=? AND read_at IS NULL AND id IN ("+marks+")").bind(user.id,...ids).run(); }
    else return fail("Choose notifications to mark as read.");
    return json({ok:true,message:"Notifications updated."});
  }
    if(path.startsWith("/api/orders/") && path.endsWith("/tracking") && method==="GET") {
    if(user.role!=="buyer" && user.role!=="supplier") return fail("Buyer or supplier account required.",403);
    const orderId=decodeURIComponent(path.split("/")[3]||"");
    const order=await env.DB.prepare("SELECT id,reference,buyer_user_id,buyer_email,supplier_id,status,carrier_name,tracking_number,tracking_url,shipped_at,delivered_at FROM orders WHERE id=?").bind(orderId).first();
    if(!order) return fail("Order not found.",404);
    const allowed=(user.role==="buyer" && (order.buyer_user_id===user.id || (order.buyer_email||"").toLowerCase()===user.email.toLowerCase())) || (user.role==="supplier" && order.supplier_id===user.id);
    if(!allowed) return fail("You do not have access to this shipment.",403);
    const events=await env.DB.prepare("SELECT status,note,actor_role,created_at FROM order_status_events WHERE order_id=? ORDER BY created_at ASC LIMIT 100").bind(orderId).all();
    return json({order,events:events.results});
  }
  if(path==="/api/reviews/eligible" && method==="GET") {
    if(user.role!=="buyer") return fail("Buyer account required.",403);
    const rows=await env.DB.prepare("SELECT o.id AS order_id,o.reference,o.product,o.delivered_at,p.id AS product_id,p.name AS product_name FROM orders o JOIN products p ON p.name=o.product AND p.supplier_id=o.supplier_id WHERE o.status='delivered' AND (o.buyer_user_id=? OR lower(o.buyer_email)=?) AND NOT EXISTS (SELECT 1 FROM product_reviews r WHERE r.order_id=o.id) ORDER BY o.delivered_at DESC LIMIT 100").bind(user.id,user.email.toLowerCase()).all();
    return json({eligible_orders:rows.results});
  }
  if(path==="/api/reviews" && method==="POST") {
    if(user.role!=="buyer") return fail("Buyer account required.",403);
    const b=await body(request),orderId=safeText(b?.order_id,80),rating=Number(b?.rating),comment=safeText(b?.comment,1500);
    if(!orderId || !Number.isInteger(rating) || rating<1 || rating>5) return fail("Choose a delivered order and a rating from 1 to 5.");
    const order=await env.DB.prepare("SELECT o.id,o.reference,o.product,o.supplier_id,o.status,o.buyer_user_id,o.buyer_email,p.id AS product_id FROM orders o JOIN products p ON p.name=o.product AND p.supplier_id=o.supplier_id WHERE o.id=? AND (o.buyer_user_id=? OR lower(o.buyer_email)=?)").bind(orderId,user.id,user.email.toLowerCase()).first();
    if(!order) return fail("A matching purchased product could not be found for this order.",404);
    if(order.status!=="delivered") return fail("You can review a product only after its order is delivered.",403);
    const id=crypto.randomUUID();
    try {
      await env.DB.prepare("INSERT INTO product_reviews (id,product_id,order_id,buyer_id,rating,comment) VALUES (?,?,?,?,?,?)").bind(id,order.product_id,orderId,user.id,rating,comment).run();
    } catch(e) {
      const existing=await env.DB.prepare("SELECT id FROM product_reviews WHERE order_id=?").bind(orderId).first();
      if(existing) return fail("This delivered order has already been reviewed.",409);
      throw e;
    }
    await audit(env,user.id,"review.submitted","product",order.product_id,"Verified purchase review submitted for "+order.reference);
    await notifyAdmins(env,"message","New product review","A verified-purchase review is awaiting moderation for "+order.product+".",null);
    return json({ok:true,message:"Review submitted and awaiting administrator approval.",id},201);
  }
  if(path==="/api/orders" && method==="GET") {
    if(user.role!=="buyer") return fail("Buyer account required.",403);
    const rows=await env.DB.prepare("SELECT id,reference,product,quantity,destination,status,carrier_name,tracking_number,tracking_url,shipped_at,delivered_at,created_at,updated_at FROM orders WHERE buyer_email=? ORDER BY created_at DESC LIMIT 100").bind(user.email.toLowerCase()).all();
    return json({orders:rows.results});
  }
  if(path.startsWith("/api/orders/") && path.endsWith("/messages") && (method==="GET" || method==="POST")) {
    if(user.role!=="buyer" && user.role!=="supplier") return fail("Buyer or supplier account required.",403);
    const parts=path.split("/"), orderId=decodeURIComponent(parts[3]||"");
    const order=await env.DB.prepare("SELECT id,reference,buyer_user_id,buyer_email,supplier_id FROM orders WHERE id=?").bind(orderId).first();
    if(!order) return fail("Order not found.",404);
    const isBuyer=user.role==="buyer" && (order.buyer_user_id===user.id || (order.buyer_email||"").toLowerCase()===user.email.toLowerCase());
    const isSupplier=user.role==="supplier" && order.supplier_id===user.id;
    if(!isBuyer && !isSupplier) return fail("You do not have access to this order conversation.",403);
    if(method==="GET") {
      const rows=await env.DB.prepare("SELECT m.id,m.sender_id,m.sender_role,m.message,m.created_at,u.name AS sender_name FROM order_messages m JOIN users u ON u.id=m.sender_id WHERE m.order_id=? ORDER BY m.created_at ASC LIMIT 300").bind(orderId).all();
      return json({messages:rows.results});
    }
    const b=await body(request), message=safeText(b?.message,2000);
    if(message.length<1) return fail("Write a message before sending.");
    const id=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO order_messages (id,order_id,sender_id,sender_role,message) VALUES (?,?,?,?,?)").bind(id,orderId,user.id,user.role,message).run();
    if(order.buyer_user_id && order.buyer_user_id!==user.id) await notify(env,order.buyer_user_id,"message","New order message","A new message was added to order "+order.reference+".",orderId);
    if(order.supplier_id && order.supplier_id!==user.id) await notify(env,order.supplier_id,"message","New order message","A new message was added to order "+order.reference+".",orderId);
    await notifyAdmins(env,"message","New order message","A participant sent a message for order "+order.reference+".",orderId,user.role==="admin"?user.id:null);
    await audit(env,user.id,"order.message.sent","order",orderId,"Message sent by "+user.role);
    return json({ok:true,message:"Message sent.",id},201);
  }
  if(path==="/api/support/cases" && method==="GET") {
    if(user.role!=="buyer" && user.role!=="supplier") return fail("Buyer or supplier account required.",403);
    const rows=await env.DB.prepare("SELECT c.id,c.reference,c.order_id,c.reporter_role,c.category,c.subject,c.description,c.status,c.resolution_note,c.created_at,c.updated_at,o.reference AS order_reference FROM support_cases c JOIN orders o ON o.id=c.order_id WHERE c.opened_by=? OR EXISTS (SELECT 1 FROM orders x WHERE x.id=c.order_id AND (x.buyer_user_id=? OR lower(x.buyer_email)=? OR x.supplier_id=?)) ORDER BY c.updated_at DESC LIMIT 100").bind(user.id,user.id,user.email.toLowerCase(),user.id).all();
    return json({cases:rows.results});
  }
  if(path==="/api/support/cases" && method==="POST") {
    if(user.role!=="buyer" && user.role!=="supplier") return fail("Buyer or supplier account required.",403);
    const b=await body(request),orderId=safeText(b?.order_id,80),category=safeText(b?.category,40),subject=safeText(b?.subject,160),description=safeText(b?.description,3000);
    if(!["order_issue","delivery_delay","damaged_goods","missing_items","product_quality","other"].includes(category)) return fail("Choose a valid support category.");
    if(subject.length<4 || description.length<10) return fail("Enter a subject and a description of at least 10 characters.");
    const order=await env.DB.prepare("SELECT id,reference,buyer_user_id,buyer_email,supplier_id FROM orders WHERE id=?").bind(orderId).first();
    if(!order) return fail("Order not found.",404);
    const isBuyer=user.role==="buyer" && (order.buyer_user_id===user.id || (order.buyer_email||"").toLowerCase()===user.email.toLowerCase());
    const isSupplier=user.role==="supplier" && order.supplier_id===user.id;
    if(!isBuyer && !isSupplier) return fail("You do not have access to this order.",403);
    const id=crypto.randomUUID(),reference="SUP-"+new Date().toISOString().slice(0,10).replace(/-/g,"")+"-"+crypto.randomUUID().slice(0,6).toUpperCase();
    await env.DB.prepare("INSERT INTO support_cases (id,reference,order_id,opened_by,reporter_role,category,subject,description) VALUES (?,?,?,?,?,?,?,?)").bind(id,reference,orderId,user.id,user.role,category,subject,description).run();
    await env.DB.prepare("INSERT INTO support_case_messages (id,case_id,sender_id,sender_role,message) VALUES (?,?,?,? ,?)").bind(crypto.randomUUID(),id,user.id,user.role,description).run();
    if(order.buyer_user_id && order.buyer_user_id!==user.id) await notify(env,order.buyer_user_id,"message","Support case opened","A support case was opened for order "+order.reference+".",orderId);
    if(order.supplier_id && order.supplier_id!==user.id) await notify(env,order.supplier_id,"message","Support case opened","A support case was opened for order "+order.reference+".",orderId);
    await notifyAdmins(env,"message","New support case",reference+" — "+subject,orderId);
    await audit(env,user.id,"support_case.opened","support_case",id,reference+" for order "+order.reference);
    return json({ok:true,id,reference,message:"Support case opened."},201);
  }
  if(path.startsWith("/api/support/cases/") && path.endsWith("/messages") && (method==="GET" || method==="POST")) {
    if(user.role!=="buyer" && user.role!=="supplier") return fail("Buyer or supplier account required.",403);
    const parts=path.split("/"),caseId=decodeURIComponent(parts[4]||"");
    const item=await env.DB.prepare("SELECT c.id,c.reference,c.order_id,c.status,o.buyer_user_id,o.buyer_email,o.supplier_id FROM support_cases c JOIN orders o ON o.id=c.order_id WHERE c.id=?").bind(caseId).first();
    if(!item) return fail("Support case not found.",404);
    const allowed=(user.role==="buyer" && (item.opened_by===user.id || item.buyer_user_id===user.id || (item.buyer_email||"").toLowerCase()===user.email.toLowerCase())) || (user.role==="supplier" && item.supplier_id===user.id);
    if(!allowed) return fail("You do not have access to this support case.",403);
    if(method==="GET") {
      const rows=await env.DB.prepare("SELECT m.id,m.sender_id,m.sender_role,m.message,m.created_at,u.name AS sender_name FROM support_case_messages m JOIN users u ON u.id=m.sender_id WHERE m.case_id=? ORDER BY m.created_at ASC LIMIT 300").bind(caseId).all();
      return json({case:item,messages:rows.results});
    }
    if(["resolved","closed"].includes(item.status)) return fail("This support case is closed to new messages.",409);
    const b=await body(request),message=safeText(b?.message,2000);
    if(!message) return fail("Write a message before sending.");
    await env.DB.prepare("INSERT INTO support_case_messages (id,case_id,sender_id,sender_role,message) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(),caseId,user.id,user.role,message).run();
    await env.DB.prepare("UPDATE support_cases SET updated_at=datetime('now') WHERE id=?").bind(caseId).run();
    if(item.buyer_user_id && item.buyer_user_id!==user.id) await notify(env,item.buyer_user_id,"message","Support case update","A new message was added to "+item.reference+".",item.order_id);
    if(item.supplier_id && item.supplier_id!==user.id) await notify(env,item.supplier_id,"message","Support case update","A new message was added to "+item.reference+".",item.order_id);
    await notifyAdmins(env,"message","Support case message","A participant replied to "+item.reference+".",item.order_id);
    await audit(env,user.id,"support_case.message","support_case",caseId,"Message sent by "+user.role);
    return json({ok:true,message:"Support case message sent."},201);
  }
  if(path.startsWith("/api/admin/")) {
    if(user.role!=="admin") return fail("Administrator access required.",403);
    if(path==="/api/admin/support-cases" && method==="GET") {
      const status=url.searchParams.get("status")||"all";
      const base="SELECT c.id,c.reference,c.order_id,c.opened_by,c.reporter_role,c.category,c.subject,c.description,c.status,c.resolution_note,c.resolved_at,c.created_at,c.updated_at,o.reference AS order_reference,o.product,o.buyer_name,o.supplier_id,bu.name AS reporter_name,sp.business_name AS supplier_name FROM support_cases c JOIN orders o ON o.id=c.order_id JOIN users bu ON bu.id=c.opened_by LEFT JOIN supplier_profiles sp ON sp.user_id=o.supplier_id";
      const rows=status==="all"?await env.DB.prepare(base+" ORDER BY c.updated_at DESC LIMIT 300").all():await env.DB.prepare(base+" WHERE c.status=? ORDER BY c.updated_at DESC LIMIT 300").bind(status).all();
      return json({cases:rows.results});
    }
    if(path.startsWith("/api/admin/support-cases/") && path.endsWith("/messages") && (method==="GET" || method==="POST")) {
      const parts=path.split("/"),caseId=decodeURIComponent(parts[4]||"");
      const item=await env.DB.prepare("SELECT id,reference,order_id,status FROM support_cases WHERE id=?").bind(caseId).first();
      if(!item) return fail("Support case not found.",404);
      if(method==="GET") {
        const rows=await env.DB.prepare("SELECT m.id,m.sender_id,m.sender_role,m.message,m.created_at,u.name AS sender_name FROM support_case_messages m JOIN users u ON u.id=m.sender_id WHERE m.case_id=? ORDER BY m.created_at ASC LIMIT 300").bind(caseId).all();
        return json({case:item,messages:rows.results});
      }
      const b=await body(request),message=safeText(b?.message,2000);
      if(!message) return fail("Write a message before sending.");
      await env.DB.prepare("INSERT INTO support_case_messages (id,case_id,sender_id,sender_role,message) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(),caseId,user.id,"admin",message).run();
      await env.DB.prepare("UPDATE support_cases SET updated_at=datetime('now') WHERE id=?").bind(caseId).run();
      const participants=await env.DB.prepare("SELECT o.buyer_user_id,o.supplier_id,o.id AS order_id FROM orders o JOIN support_cases c ON c.order_id=o.id WHERE c.id=?").bind(caseId).first();
      if(participants?.buyer_user_id) await notify(env,participants.buyer_user_id,"message","Support case update","The marketplace team replied to "+item.reference+".",item.order_id);
      if(participants?.supplier_id) await notify(env,participants.supplier_id,"message","Support case update","The marketplace team replied to "+item.reference+".",item.order_id);
      await audit(env,user.id,"support_case.admin_message","support_case",caseId,"Administrator sent a message");
      return json({ok:true,message:"Support case message sent."},201);
    }
    if(path.startsWith("/api/admin/support-cases/") && method==="POST") {
      const caseId=decodeURIComponent(path.split("/").pop()||""),b=await body(request);
      if(!["open","in_review","waiting_supplier","waiting_buyer","resolved","closed"].includes(b?.status)) return fail("Choose a valid support case status.");
      const note=safeText(b.resolution_note,1200),item=await env.DB.prepare("SELECT id,reference,order_id,status FROM support_cases WHERE id=?").bind(caseId).first();
      if(!item) return fail("Support case not found.",404);
      await env.DB.prepare("UPDATE support_cases SET status=?,resolution_note=?,resolved_by=CASE WHEN ? IN ('resolved','closed') THEN ? ELSE NULL END,resolved_at=CASE WHEN ? IN ('resolved','closed') THEN datetime('now') ELSE NULL END,updated_at=datetime('now') WHERE id=?").bind(b.status,note,b.status,user.id,b.status,caseId).run();
      const participants=await env.DB.prepare("SELECT o.buyer_user_id,o.supplier_id,o.id AS order_id FROM orders o JOIN support_cases c ON c.order_id=o.id WHERE c.id=?").bind(caseId).first();
      const alert="Support case "+item.reference+" status changed to "+b.status+".";
      if(participants?.buyer_user_id) await notify(env,participants.buyer_user_id,"message","Support case updated",alert,item.order_id);
      if(participants?.supplier_id) await notify(env,participants.supplier_id,"message","Support case updated",alert,item.order_id);
      await audit(env,user.id,"support_case."+b.status,"support_case",caseId,note||"Support case status updated");
      return json({ok:true,message:"Support case updated."});
    }
    if(path==="/api/admin/overview" && method==="GET") {
      const keys=["users","suppliers","pendingSuppliers","pendingProducts","publishedProducts","rejectedProducts","newRfqs"];
      const sql=["SELECT COUNT(*) AS n FROM users","SELECT COUNT(*) AS n FROM users WHERE role='supplier'","SELECT COUNT(*) AS n FROM users WHERE role='supplier' AND status='pending'","SELECT COUNT(*) AS n FROM products WHERE status='pending'","SELECT COUNT(*) AS n FROM products WHERE status='published'","SELECT COUNT(*) AS n FROM products WHERE status='rejected'","SELECT COUNT(*) AS n FROM rfqs WHERE status='new'"];
      const values=await Promise.all(sql.map(q=>env.DB.prepare(q).first()));
      return json({stats:Object.fromEntries(keys.map((k,i)=>[k,values[i].n]))});
    }
    if(path==="/api/admin/reports" && method==="GET") {
      const from=url.searchParams.get("from")||"";
      const to=url.searchParams.get("to")||"";
      const validDate=v=>!v||/^\d{4}-\d{2}-\d{2}$/.test(v);
      if(!validDate(from)||!validDate(to)||(from&&to&&from>to)) return fail("Use a valid report date range.");
      const start=from?from+" 00:00:00":"1970-01-01 00:00:00";
      const end=to?to+" 23:59:59":"9999-12-31 23:59:59";
      const range="created_at>=? AND created_at<=?";
      const [orders,rfqs,products,suppliers,monthly,orderStatuses,rfqStatuses,topSuppliers]=await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END) AS delivered, SUM(CASE WHEN status='shipped' THEN 1 ELSE 0 END) AS shipped, SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) AS cancelled FROM orders WHERE "+range).bind(start,end).first(),
        env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status='quoted' THEN 1 ELSE 0 END) AS quoted, SUM(CASE WHEN status='closed' THEN 1 ELSE 0 END) AS closed FROM rfqs WHERE "+range).bind(start,end).first(),
        env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status='published' THEN 1 ELSE 0 END) AS published, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending, SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rejected FROM products WHERE "+range).bind(start,end).first(),
        env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending FROM users WHERE role='supplier' AND "+range).bind(start,end).first(),
        env.DB.prepare("SELECT substr(created_at,1,7) AS month,COUNT(*) AS total FROM orders WHERE "+range+" GROUP BY substr(created_at,1,7) ORDER BY month ASC LIMIT 24").bind(start,end).all(),
        env.DB.prepare("SELECT status,COUNT(*) AS total FROM orders WHERE "+range+" GROUP BY status ORDER BY total DESC").bind(start,end).all(),
        env.DB.prepare("SELECT status,COUNT(*) AS total FROM rfqs WHERE "+range+" GROUP BY status ORDER BY total DESC").bind(start,end).all(),
        env.DB.prepare("SELECT sp.business_name,COUNT(o.id) AS order_count FROM orders o JOIN supplier_profiles sp ON sp.user_id=o.supplier_id WHERE o.created_at>=? AND o.created_at<=? GROUP BY o.supplier_id,sp.business_name ORDER BY order_count DESC LIMIT 8").bind(start,end).all()
      ]);
      return json({from,to,orders,rfqs,products,suppliers,monthlyOrders:monthly.results,orderStatuses:orderStatuses.results,rfqStatuses:rfqStatuses.results,topSuppliers:topSuppliers.results});
    }
    if(path==="/api/admin/reviews" && method==="GET") {
      const status=url.searchParams.get("status")||"pending";
      const base="SELECT r.id,r.product_id,r.order_id,r.buyer_id,r.rating,r.comment,r.status,r.created_at,r.moderated_at,p.name AS product_name,u.name AS buyer_name,u.email AS buyer_email,o.reference AS order_reference FROM product_reviews r JOIN products p ON p.id=r.product_id JOIN users u ON u.id=r.buyer_id JOIN orders o ON o.id=r.order_id";
      const rows=status==="all"?await env.DB.prepare(base+" ORDER BY r.created_at DESC LIMIT 300").all():await env.DB.prepare(base+" WHERE r.status=? ORDER BY r.created_at DESC LIMIT 300").bind(status).all();
      return json({reviews:rows.results});
    }
    if(path.startsWith("/api/admin/reviews/") && method==="POST") {
      const id=decodeURIComponent(path.split("/").pop()||""),b=await body(request);
      if(!["published","hidden","pending"].includes(b?.status)) return fail("Choose a valid review moderation status.");
      const review=await env.DB.prepare("SELECT id,product_id,status FROM product_reviews WHERE id=?").bind(id).first();
      if(!review) return fail("Review not found.",404);
      await env.DB.prepare("UPDATE product_reviews SET status=?,moderated_by=?,moderated_at=datetime('now'),updated_at=datetime('now') WHERE id=?").bind(b.status,user.id,id).run();
      await audit(env,user.id,"review."+b.status,"product_review",id,"Review moderation status changed from "+review.status+" to "+b.status);
      return json({ok:true,message:"Review moderation updated."});
    }
    if(path==="/api/admin/rfqs" && method==="GET") {
      const status=url.searchParams.get("status")||"all";
      const base="SELECT id,product,quantity,destination,requirements,buyer_name,buyer_contact,status,admin_note,created_at,updated_at FROM rfqs";
      const rows=status==="all"?await env.DB.prepare(base+" ORDER BY created_at DESC LIMIT 300").all():await env.DB.prepare(base+" WHERE status=? ORDER BY created_at DESC LIMIT 300").bind(status).all();
      return json({rfqs:rows.results});
    }
    if(path.startsWith("/api/admin/rfqs/") && method==="POST") {
      const id=decodeURIComponent(path.split("/").pop()||""), b=await body(request);
      if(!["new","in_review","contacted","quoted","closed"].includes(b?.status)) return fail("Invalid enquiry status.");
      const note=safeText(b.admin_note,1200);
      const result=await env.DB.prepare("UPDATE rfqs SET status=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(b.status,note,id).run();
      if(!result.meta?.changes) return fail("Sourcing request not found.",404);
      await audit(env,user.id,"rfq."+b.status,"rfq",id,note||"Status updated");
      return json({ok:true,message:"Sourcing request updated."});
    }
    if(path.startsWith("/api/admin/orders/") && path.endsWith("/messages") && (method==="GET" || method==="POST")) {
      const parts=path.split("/"), orderId=decodeURIComponent(parts[4]||"");
      const order=await env.DB.prepare("SELECT id,reference,buyer_user_id,supplier_id FROM orders WHERE id=?").bind(orderId).first();
      if(!order) return fail("Order not found.",404);
      if(method==="GET") {
        const rows=await env.DB.prepare("SELECT m.id,m.sender_id,m.sender_role,m.message,m.created_at,u.name AS sender_name FROM order_messages m JOIN users u ON u.id=m.sender_id WHERE m.order_id=? ORDER BY m.created_at ASC LIMIT 300").bind(orderId).all();
        return json({messages:rows.results});
      }
      const b=await body(request), message=safeText(b?.message,2000);
      if(message.length<1) return fail("Write a message before sending.");
      const id=crypto.randomUUID();
      await env.DB.prepare("INSERT INTO order_messages (id,order_id,sender_id,sender_role,message) VALUES (?,?,?,?,?)").bind(id,orderId,user.id,"admin",message).run();
      if(order.buyer_user_id) await notify(env,order.buyer_user_id,"message","New order message","The marketplace team sent a message about order "+order.reference+".",orderId);
      if(order.supplier_id) await notify(env,order.supplier_id,"message","New order message","The marketplace team sent a message about order "+order.reference+".",orderId);
      await audit(env,user.id,"order.message.sent","order",orderId,"Message sent by administrator");
      return json({ok:true,message:"Message sent.",id},201);
    }
    if(path==="/api/admin/orders" && method==="GET") {
      const status=url.searchParams.get("status")||"all";
      const base="SELECT o.id,o.reference,o.rfq_id,o.buyer_name,o.buyer_email,o.product,o.quantity,o.destination,o.status,o.admin_note,o.supplier_id,o.carrier_name,o.tracking_number,o.tracking_url,o.shipped_at,o.delivered_at,o.created_at,o.updated_at,sp.business_name AS supplier_name FROM orders o LEFT JOIN supplier_profiles sp ON sp.user_id=o.supplier_id";
      const rows=status==="all"?await env.DB.prepare(base+" ORDER BY o.created_at DESC LIMIT 300").all():await env.DB.prepare(base+" WHERE o.status=? ORDER BY o.created_at DESC LIMIT 300").bind(status).all();
      return json({orders:rows.results});
    }
    if(path.startsWith("/api/admin/orders/") && path.endsWith("/assign") && method==="POST") {
      const parts=path.split("/"), id=decodeURIComponent(parts[parts.length-2]||""), b=await body(request);
      const supplierId=safeText(b?.supplier_id,80);
      if(!supplierId) return fail("Choose a supplier.");
      const supplier=await env.DB.prepare("SELECT u.id FROM users u JOIN supplier_profiles sp ON sp.user_id=u.id WHERE u.id=? AND u.role='supplier' AND u.status='active' AND sp.business_name<>''").bind(supplierId).first();
      if(!supplier) return fail("Choose an approved supplier with a completed business profile.",404);
      const order=await env.DB.prepare("SELECT id,status FROM orders WHERE id=?").bind(id).first();
      if(!order) return fail("Order not found.",404);
      if(["delivered","cancelled"].includes(order.status)) return fail("Closed orders cannot be reassigned.");
      await env.DB.prepare("UPDATE orders SET supplier_id=?,status=CASE WHEN status='pending' THEN 'confirmed' ELSE status END,updated_at=datetime('now') WHERE id=?").bind(supplierId,id).run();
      await audit(env,user.id,"order.assigned","order",id,"Assigned to supplier "+supplierId);
      return json({ok:true,message:"Order assigned to supplier."});
    }
    if(path==="/api/admin/orders" && method==="POST") {
      const b=await body(request), rfqId=safeText(b?.rfq_id,80);
      if(!rfqId) return fail("A buyer enquiry is required.");
      const rfq=await env.DB.prepare("SELECT * FROM rfqs WHERE id=?").bind(rfqId).first();
      if(!rfq) return fail("Buyer enquiry not found.",404);
      const existing=await env.DB.prepare("SELECT reference FROM orders WHERE rfq_id=?").bind(rfqId).first();
      if(existing) return fail("An order already exists for this enquiry: "+existing.reference,409);
      if(rfq.status!=="quoted") return fail("Set the buyer enquiry status to quoted before creating an order.");
      const reference="CDS-"+new Date().toISOString().slice(0,10).replace(/-/g,"")+"-"+crypto.randomUUID().slice(0,8).toUpperCase();
      const buyerEmail=rfq.buyer_contact.includes("@")?rfq.buyer_contact.trim().toLowerCase():"";
      const buyer=buyerEmail?await env.DB.prepare("SELECT id FROM users WHERE email=? AND role='buyer'").bind(buyerEmail).first():null;
      const id=crypto.randomUUID();
      await env.DB.prepare("INSERT INTO orders (id,reference,rfq_id,buyer_user_id,buyer_name,buyer_email,product,quantity,destination,status) VALUES (?,?,?,?,?,?,?,?,?,'pending')").bind(id,reference,rfq.id,buyer?.id||null,rfq.buyer_name,buyerEmail,rfq.product,rfq.quantity,rfq.destination).run();
      await audit(env,user.id,"order.created","order",id,"Created from enquiry "+rfq.id+"; "+reference);
      return json({ok:true,reference,message:"Order created."},201);
    }
    if(path.startsWith("/api/admin/orders/") && method==="POST") {
      const id=decodeURIComponent(path.split("/").pop()||""), b=await body(request);
      if(!["pending","confirmed","processing","shipped","delivered","cancelled"].includes(b?.status)) return fail("Invalid order status.");
      const note=safeText(b.admin_note,1200),carrier=safeText(b.carrier_name,100),tracking=safeText(b.tracking_number,120),trackingUrl=safeText(b.tracking_url,500);
      if(trackingUrl && !/^https:\/\//i.test(trackingUrl)) return fail("Tracking link must use HTTPS.");
      const before=await env.DB.prepare("SELECT reference,status,buyer_user_id,supplier_id FROM orders WHERE id=?").bind(id).first();
      if(!before) return fail("Order not found.",404);
      const result=await env.DB.prepare("UPDATE orders SET status=?,admin_note=?,carrier_name=?,tracking_number=?,tracking_url=?,shipped_at=CASE WHEN ?='shipped' AND shipped_at IS NULL THEN datetime('now') ELSE shipped_at END,delivered_at=CASE WHEN ?='delivered' AND delivered_at IS NULL THEN datetime('now') ELSE delivered_at END,updated_at=datetime('now') WHERE id=?").bind(b.status,note,carrier,tracking,trackingUrl,b.status,b.status,id).run();
      if(!result.meta?.changes) return fail("Order not found.",404);
      if(before.status!==b.status) {
        const alert="Order "+before.reference+" status changed to "+b.status+".";
        if(before.buyer_user_id) await notify(env,before.buyer_user_id,"order_status","Order status updated",alert,id);
        if(before.supplier_id) await notify(env,before.supplier_id,"order_status","Order status updated",alert,id);
      }
      if(before.status!==b.status) await env.DB.prepare("INSERT INTO order_status_events (id,order_id,actor_id,actor_role,status,note) VALUES (?,?,?,'admin',?,?)").bind(crypto.randomUUID(),id,user.id,b.status,note).run();
      await audit(env,user.id,"order."+b.status,"order",id,note||"Order status updated");
      return json({ok:true,message:"Order updated."});
    }
    if(path==="/api/admin/products" && method==="GET") {
      const status=url.searchParams.get("status")||"all";
      const base="SELECT p.*,u.name AS supplier_name,u.email AS supplier_email,sp.business_name FROM products p JOIN users u ON u.id=p.supplier_id LEFT JOIN supplier_profiles sp ON sp.user_id=p.supplier_id";
      const rows=status==="all"?await env.DB.prepare(base+" ORDER BY p.created_at DESC LIMIT 200").all():await env.DB.prepare(base+" WHERE p.status=? ORDER BY p.created_at DESC LIMIT 200").bind(status).all();
      return json({products:rows.results});
    }
    if(path.startsWith("/api/admin/products/") && method==="POST") {
      const id=path.split("/").pop(), b=await body(request);
      if(!["published","rejected","pending"].includes(b?.status)) return fail("Invalid product status.");
      await env.DB.prepare("UPDATE products SET status=? WHERE id=?").bind(b.status,id).run();
      await audit(env,user.id,"product."+b.status,"product",id,b.note||"");
      return json({ok:true,message:"Product status updated."});
    }
    if(path==="/api/admin/suppliers" && method==="GET") {
      const rows=await env.DB.prepare("SELECT u.id,u.name,u.email,u.status,u.created_at,p.business_name,p.country,p.description,p.phone,p.website,p.verification_note,p.verified_at FROM users u LEFT JOIN supplier_profiles p ON p.user_id=u.id WHERE u.role='supplier' ORDER BY u.created_at DESC").all();
      return json({suppliers:rows.results});
    }
    if(path.startsWith("/api/admin/suppliers/") && method==="POST") {
      const id=decodeURIComponent(path.split("/").pop()||""), b=await body(request);
      if(!["active","rejected","suspended","pending"].includes(b?.status)) return fail("Invalid supplier status.");
      const note=safeText(b.verification_note,1200);
      const account=await env.DB.prepare("SELECT id FROM users WHERE id=? AND role='supplier'").bind(id).first();
      if(!account) return fail("Supplier account not found.",404);
      const businessName=safeText(b.business_name,140), country=safeText(b.country,100);
      const description=safeText(b.description,1200), phone=safeText(b.phone,40), website=safeText(b.website,200);
      const current=await env.DB.prepare("SELECT user_id FROM supplier_profiles WHERE user_id=?").bind(id).first();
      if(!current && (businessName.length<2 || description.length<10 || phone.length<5 || country.length<2)) return fail("Complete the business name, description and business phone before saving or approving this supplier.");
      if(website && !/^https:\/\//i.test(website)) return fail("Business website must use HTTPS.");
      if(current && (businessName || description || phone || website || country)) {
        await env.DB.prepare("UPDATE supplier_profiles SET business_name=CASE WHEN ?<>'' THEN ? ELSE business_name END,country=CASE WHEN ?<>'' THEN ? ELSE country END,description=CASE WHEN ?<>'' THEN ? ELSE description END,phone=CASE WHEN ?<>'' THEN ? ELSE phone END,website=CASE WHEN ?<>'' THEN ? ELSE website END,verification_note=?,verified_at=CASE WHEN ?='active' THEN ? ELSE NULL END,updated_at=datetime('now') WHERE user_id=?") .bind(businessName,businessName,country,country,description,description,phone,phone,website,website,note,b.status,b.status==="active"?new Date().toISOString():null,id).run();
      } else {
        await env.DB.prepare("INSERT INTO supplier_profiles (user_id,business_name,country,description,phone,website,verification_note,verified_at) VALUES (?,?,?,?,?,?,?,?)").bind(id,businessName,country,description,phone,website,note,b.status==="active"?new Date().toISOString():null).run();
      }
      const verifiedAt=b.status==="active"?new Date().toISOString():null;
      await env.DB.prepare("UPDATE users SET status=? WHERE id=? AND role='supplier'").bind(b.status,id).run();
      await audit(env,user.id,"supplier."+b.status,"user",id,note||"Supplier verification status updated");
      return json({ok:true,message:"Supplier status and verification record updated.",verified_at:verifiedAt});
    }
    if(path==="/api/admin/audit" && method==="GET") {
      const rows=await env.DB.prepare("SELECT a.id,a.action,a.target_type,a.target_id,a.details,a.created_at,u.name AS actor_name FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 100").all();
      return json({logs:rows.results});
    }
    if(path==="/api/admin/users" && method==="GET") {
      const rows=await env.DB.prepare("SELECT id,name,email,role,status,created_at FROM users ORDER BY created_at DESC LIMIT 200").all();
      return json({users:rows.results});
    }
    return fail("Admin route not found.",404);
  }
  if(path==="/api/supplier/orders" && method==="GET") {
    if(user.role!=="supplier") return fail("Supplier account required.",403);
    const rows=await env.DB.prepare("SELECT id,reference,buyer_name,product,quantity,destination,status,supplier_note,carrier_name,tracking_number,tracking_url,shipped_at,delivered_at,created_at,updated_at FROM orders WHERE supplier_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
    return json({orders:rows.results});
  }
  if(path.startsWith("/api/supplier/orders/") && method==="POST") {
    if(user.role!=="supplier") return fail("Supplier account required.",403);
    const id=decodeURIComponent(path.split("/").pop()||""), b=await body(request);
    if(!["confirmed","processing","shipped"].includes(b?.status)) return fail("Suppliers may update orders to confirmed, processing or shipped.");
    const note=safeText(b.supplier_note,1000),carrier=safeText(b.carrier_name,100),tracking=safeText(b.tracking_number,120),trackingUrl=safeText(b.tracking_url,500);
    if(trackingUrl && !/^https:\/\//i.test(trackingUrl)) return fail("Tracking link must use HTTPS.");
    const before=await env.DB.prepare("SELECT reference,status,buyer_user_id FROM orders WHERE id=? AND supplier_id=?").bind(id,user.id).first();
    const result=await env.DB.prepare("UPDATE orders SET status=?,supplier_note=?,carrier_name=?,tracking_number=?,tracking_url=?,shipped_at=CASE WHEN ?='shipped' AND shipped_at IS NULL THEN datetime('now') ELSE shipped_at END,updated_at=datetime('now') WHERE id=? AND supplier_id=? AND status NOT IN ('delivered','cancelled')").bind(b.status,note,carrier,tracking,trackingUrl,b.status,id,user.id).run();
    if(!result.meta?.changes) return fail("Assigned order not found or already closed.",404);
    if(before && before.status!==b.status) {
      const alert="Order "+before.reference+" status changed to "+b.status+".";
      if(before.buyer_user_id) await notify(env,before.buyer_user_id,"order_status","Order status updated",alert,id);
      await notifyAdmins(env,"order_status","Supplier updated an order",alert,id);
    }
    if(before && before.status!==b.status) await env.DB.prepare("INSERT INTO order_status_events (id,order_id,actor_id,actor_role,status,note) VALUES (?,?,?,'supplier',?,?)").bind(crypto.randomUUID(),id,user.id,b.status,note).run();
    await audit(env,user.id,"supplier.order."+b.status,"order",id,note||"Supplier updated fulfilment status");
    return json({ok:true,message:"Order fulfilment updated."});
  }
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
    const name=safeText(b.name,140), category=safeText(b.category,80), description=safeText(b.description,1200), imageUrl=safeText(b.image_url,500);
    if(name.length<2 || !category || description.length<10) return fail("Add a product name, category and description.");
    if(imageUrl && (!/^https:\/\//i.test(imageUrl) || imageUrl.length>500)) return fail("Product image must use a valid HTTPS URL.");
    const id=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO products (id,supplier_id,name,category,description,unit,origin,image_url,status) VALUES (?,?,?,?,?,?,?,?,'pending')").bind(id,user.id,name,category,description,safeText(b.unit,40),safeText(b.origin,100)||"São Tomé and Príncipe",imageUrl).run();
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
