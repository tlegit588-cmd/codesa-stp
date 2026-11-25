# CODEYSA-STP Marketplace API — Sprint 2

This sprint adds buyer/supplier account UI and a Cloudflare Worker API backed by D1.

## Files
- `worker.js`: same-origin API, password hashing with PBKDF2-SHA-256, opaque random sessions stored as SHA-256 hashes, HttpOnly/Secure/SameSite cookies, role checks.
- `schema.sql`: D1 tables for users, sessions, supplier profiles and products.
- `account.html` / `account.js`: sign-in, registration, supplier profile and product submission UI.

## Required Cloudflare setup before accounts can work
1. Create a Cloudflare D1 database named `codesa-marketplace`.
2. In D1 Console, run the complete contents of `schema.sql`.
3. Configure the existing Worker to use `worker.js` as its entry point and bind the D1 database as `DB`.
4. Bind the existing static asset service as `ASSETS` (or adapt the final fallback in `worker.js` to your current static hosting setup).
5. Deploy and test `/api/health`, then register a buyer and a supplier.

Do not expose an admin registration option. The first administrator must be provisioned directly in D1 by a trusted operator after deployment; do not promote a public account through a browser form.

## Important production hardening before public launch
Add email verification and password reset, rate limiting / abuse protection, audit logging, admin bootstrap procedure, and backups. Supplier accounts are pending until an administrator activates them. Product submissions are pending; the admin product-review screen and publish endpoint are Sprint 3.

The static marketplace remains a showcase until real suppliers and approved product records exist. Never advertise unverified listings as live inventory.
