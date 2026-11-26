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
    const rows=await env.DB.prepare("SELECT p.id,p.supplier_id,p.name,p.category,p.description,p.unit,p.origin,p.image_url,p.created_at,sp.business_name,sp.country FROM products p JOIN supplier_profiles sp ON sp.user_id=p.supplier_id JOIN users u ON u.id=p.supplier_id WHERE p.status='published' AND u.status='active' AND sp.business_name<>'' ORDER BY p.created_at DESC LIMIT 100").all();
    return json({products:rows.results});
  }
  if (path.startsWith("/api/suppliers/") && method==="GET") {
    const id=decodeURIComponent(path.split("/").pop()||"");
    const supplier=await env.DB.prepare("SELECT u.id,sp.business_name,sp.country,sp.description,sp.phone,sp.website FROM users u JOIN supplier_profiles sp ON sp.user_id=u.id WHERE u.id=? AND u.role='supplier' AND u.status='active' AND sp.business_name<>''").bind(id).first();
    if(!supplier) return fail("Supplier storefront not found.",404);
    const products=await env.DB.prepare("SELECT id,name,category,description,unit,origin,image_url,created_at FROM products WHERE supplier_id=? AND status='published' ORDER BY created_at DESC LIMIT 100").bind(id).all();
    return json({supplier,products:products.results});
  }
  const user=await requireUser(request,env); if(!user) return fail("Please sign in.",401);
  if(path==="/api/orders" && method==="GET") {
    if(user.role!=="buyer") return fail("Buyer account required.",403);
    const rows=await env.DB.prepare("SELECT reference,product,quantity,destination,status,created_at,updated_at FROM orders WHERE buyer_email=? ORDER BY created_at DESC LIMIT 100").bind(user.email.toLowerCase()).all();
    return json({orders:rows.results});
  }
  if(path.startsWith("/api/admin/")) {
    if(user.role!=="admin") return fail("Administrator access required.",403);
    if(path==="/api/admin/overview" && method==="GET") {
      const keys=["users","suppliers","pendingSuppliers","pendingProducts","publishedProducts","rejectedProducts","newRfqs"];
      const sql=["SELECT COUNT(*) AS n FROM users","SELECT COUNT(*) AS n FROM users WHERE role='supplier'","SELECT COUNT(*) AS n FROM users WHERE role='supplier' AND status='pending'","SELECT COUNT(*) AS n FROM products WHERE status='pending'","SELECT COUNT(*) AS n FROM products WHERE status='published'","SELECT COUNT(*) AS n FROM products WHERE status='rejected'","SELECT COUNT(*) AS n FROM rfqs WHERE status='new'"];
      const values=await Promise.all(sql.map(q=>env.DB.prepare(q).first()));
      return json({stats:Object.fromEntries(keys.map((k,i)=>[k,values[i].n]))});
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
    if(path==="/api/admin/orders" && method==="GET") {
      const status=url.searchParams.get("status")||"all";
      const base="SELECT o.id,o.reference,o.rfq_id,o.buyer_name,o.buyer_email,o.product,o.quantity,o.destination,o.status,o.admin_note,o.supplier_id,o.created_at,o.updated_at,sp.business_name AS supplier_name FROM orders o LEFT JOIN supplier_profiles sp ON sp.user_id=o.supplier_id";
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
      const note=safeText(b.admin_note,1200);
      const result=await env.DB.prepare("UPDATE orders SET status=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(b.status,note,id).run();
      if(!result.meta?.changes) return fail("Order not found.",404);
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
      const rows=await env.DB.prepare("SELECT u.id,u.name,u.email,u.status,u.created_at,p.business_name,p.country FROM users u LEFT JOIN supplier_profiles p ON p.user_id=u.id WHERE u.role='supplier' ORDER BY u.created_at DESC").all();
      return json({suppliers:rows.results});
    }
    if(path.startsWith("/api/admin/suppliers/") && method==="POST") {
      const id=path.split("/").pop(), b=await body(request);
      if(!["active","rejected","suspended","pending"].includes(b?.status)) return fail("Invalid supplier status.");
      await env.DB.prepare("UPDATE users SET status=? WHERE id=? AND role='supplier'").bind(b.status,id).run();
      await audit(env,user.id,"supplier."+b.status,"user",id,b.note||"");
      return json({ok:true,message:"Supplier status updated."});
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
    const rows=await env.DB.prepare("SELECT id,reference,buyer_name,product,quantity,destination,status,supplier_note,created_at,updated_at FROM orders WHERE supplier_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
    return json({orders:rows.results});
  }
  if(path.startsWith("/api/supplier/orders/") && method==="POST") {
    if(user.role!=="supplier") return fail("Supplier account required.",403);
    const id=decodeURIComponent(path.split("/").pop()||""), b=await body(request);
    if(!["confirmed","processing","shipped"].includes(b?.status)) return fail("Suppliers may update orders to confirmed, processing or shipped.");
    const note=safeText(b.supplier_note,1000);
    const result=await env.DB.prepare("UPDATE orders SET status=?,supplier_note=?,updated_at=datetime('now') WHERE id=? AND supplier_id=? AND status NOT IN ('delivered','cancelled')").bind(b.status,note,id,user.id).run();
    if(!result.meta?.changes) return fail("Assigned order not found or already closed.",404);
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
