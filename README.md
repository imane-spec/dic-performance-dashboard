# DIC Performance Dashboard — Netlify deployment

This is your dashboard and login backend, restructured to run on Netlify's
free tier instead of Replit. The only real change from your Replit version
is storage: account records and password-reset codes now live in Netlify
Blobs (Netlify's own persistent key-value store) instead of Replit's
database. Every login/signup/reset rule you already had — allowed email
domains, password hashing, rate limits, session cookies — is untouched.

Netlify's free tier does not expire and does not require a card: 100GB
bandwidth and 125,000 function calls a month, which is far more than an
internal team dashboard needs.

## What's included

- `site/` — your dashboard (`index.html`) and login page. Published as-is.
- `netlify/functions/` — one function per API endpoint (login, signup,
  session check, password reset, admin account creation, logout).
- `lib/` — the shared auth logic, the new Blobs-based store, and the
  mail placeholder (password reset codes are logged, not emailed, until you
  configure a provider — same as your Replit setup).
- `netlify.toml` — tells Netlify where the site and functions live, and
  routes `/api/*` to the functions.

Microsoft organization sign-in isn't included in this version — your current
login page only exposes email/password anyway. If you want it back later,
say so and I'll port the two Microsoft OAuth routes over as functions too.

## 1. Put this in a GitHub repository

1. Create a new, empty repository on GitHub (public or private — private is
   fine on Netlify's free tier).
2. From this folder:
   ```
   git init
   git add .
   git commit -m "Initial Netlify deployment"
   git branch -M main
   git remote add origin <your-repo-url>
   git push -u origin main
   ```

## 2. Connect it to Netlify

1. Go to [app.netlify.com](https://app.netlify.com) and sign up or log in
   (GitHub sign-in is the fastest option).
2. **Add new site → Import an existing project → Deploy with GitHub**, then
   pick this repository.
3. Netlify will read `netlify.toml` automatically — leave the build settings
   as detected and click **Deploy**.

## 3. Set your environment variables

In your new site: **Site configuration → Environment variables → Add a
variable**, add:

| Key | Value |
|---|---|
| `SESSION_SECRET` | a long random string (32+ characters) |
| `ADMIN_SECRET` | a different long random string |
| `BLOBS_TOKEN` | a Netlify personal access token (see below) |

Generate `SESSION_SECRET` and `ADMIN_SECRET` locally with:
```
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Keep `ADMIN_SECRET` somewhere private — you'll use it once to create your
first account, and never need to share it with end users.

For `BLOBS_TOKEN`: go to your Netlify **avatar (top right) → User settings
→ Applications → Personal access tokens → New access token**, give it any
name, and copy the token it shows you (you won't be able to see it again).
Paste that as the value of `BLOBS_TOKEN`. This is needed because Netlify's
automatic setup for account storage doesn't always attach correctly to a
deploy — passing this token makes storage work reliably regardless.

After adding the variables, trigger a redeploy (**Deploys → Trigger deploy
→ Deploy site**) so the functions pick them up.

## 4. Create your first account

Once deployed, create your own account by calling the admin endpoint once
(replace `<your-site>` and the two placeholder values):

```
curl -X POST https://<your-site>.netlify.app/api/admin-create-user \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: <your ADMIN_SECRET value>" \
  -d '{"email":"you@mcit.gov.qa","password":"a-strong-password"}'
```

Only `@consultant.mcit.gov.qa`, `@mcit.gov.qa`, and `@ibtechar.com`
addresses are accepted — same restriction as before. After that, sign in
normally at your site's URL, or teammates can create their own accounts
through the "Create an account" link on the login page.

## 5. Custom domain (optional)

Your site works immediately at `https://<your-site>.netlify.app`. If you
own `DIC-Dashboard.com` (or another domain), add it under **Domain
management** in Netlify — it's free to attach, you just need to own the
domain itself. If you do this, update the two `canonical`/`og:url` tags in
`site/index.html` and `site/public-login.html` to match.

## Notes

- Password reset codes are only logged to the function's Netlify logs
  (**Logs → Functions**), not emailed, until you wire up a provider — the
  ready-to-uncomment blocks for Resend, SendGrid, and SMTP are still in
  `lib/mail.js`, unchanged from before.
- `site/public-login.html` is a static fallback; `site/index.html` actually
  handles the whole login/signup/reset flow client-side, so most people will
  never see the fallback page.
