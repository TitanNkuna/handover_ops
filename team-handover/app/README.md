# Team Handover

Shift handover app: burgundy/white UI, Vercel serverless API, Postgres database. Multiple staff can use it at the same time from any computer, and every change is audited.

```
public/index.html   front end (static)
api/index.js        serverless API  (POST /api)
db/schema.sql       tables (also created automatically on first request)
vercel.json         function + security header config
.env.example        environment variables you need to set
```

## 1. Put it on GitHub

```bash
cd team-handover
git init -b main
git add .
git commit -m "Team Handover"
# create an empty repo on github.com first, then:
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```
`.env` is git-ignored, so secrets never get committed.

## 2. Create the database (any Postgres)

Easiest: in Vercel, open your project → **Storage** → **Create Database** → **Neon** (Postgres). This adds `DATABASE_URL` / `POSTGRES_URL` to the project automatically.
Alternatives: Supabase, Railway, AWS RDS, your own server. Just copy its connection string into `DATABASE_URL`.

Tables are created automatically the first time the app runs. To create them yourself:
`DATABASE_URL=... npm run db:init` (or run `db/schema.sql`).

## 3. Deploy on Vercel

1. vercel.com → **Add New… → Project** → import your GitHub repo (framework preset: *Other*, no build command).
2. Add environment variables (Settings → Environment Variables):
   - `DATABASE_URL` (skip if the Neon integration already added it)
   - `SESSION_SECRET` — generate: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
3. **Deploy**. Every `git push` to `main` redeploys automatically.
4. Open the site. The first visit asks you to create the administrator account, then add staff on the **Staff** page.

## Run locally

```bash
npm install
cp .env.example .env      # fill in values
npx vercel dev            # serves public/ and /api together
```

## Notes
- Login: PIN hashed with scrypt on the server; sessions are signed tokens valid 12 hours; deactivated staff lose access immediately.
- The sign-in dropdown lists active staff names (as before). Consider adding rate limiting / SSO if exposed to the public internet.
- Editing uses revision checks, so two people saving the same handover can't silently overwrite each other.
- Backups page exports/imports the whole database as JSON (admin only; the file includes PIN hashes — store it securely).
- Customise colours in the `:root` block at the top of `public/index.html` (`--burgundy-*`).
