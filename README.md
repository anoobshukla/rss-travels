# RSS Travels

Email/password booking application with owner-created accounts and MongoDB storage. No registration or outgoing email service is enabled.

## Deployment

Deploy this repository as a **Render Python Web Service**, Free plan:

- Build: `pip install -r requirements.txt`
- Start: `uvicorn server:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*'`
- Health check: `/api/health`
- `APP_ORIGIN`: the exact HTTPS address of this web service, without a trailing slash
- `MONGODB_URI`: enter the rotated Atlas connection string privately in Render
- `MONGODB_DB`: `rss_travels`
- `OWNER_EMAIL`: first owner's email, entered privately in Render
- `OWNER_PASSWORD`: unique temporary password of 12–128 characters, entered privately in Render
- `OWNER_NAME`: first owner's display name

Allow Render's documented outbound IP ranges in Atlas Network Access. Use a database user restricted to read/write on `rss_travels`. Do not use the exposed original password or commit any credentials.

Startup creates the first owner only when the configured email does not already exist. Sign in and replace the temporary password. Then remove `OWNER_PASSWORD` from Render's environment settings. Keep two owner accounts to support password recovery. Existing owner passwords are never reset by restarting the server.

Collections: `users`, `sessions`, `bookings`, `audit_logs`, `login_limits`. Payments are embedded in booking documents so concurrent balance updates are atomic. Currency is stored as integer paise. Customer account links are explicit, not matched automatically by names or phone numbers.

Owners can create owners, employees and customers, reset other accounts' passwords, and disable employees/customers. Employees can view all trip details, but only see finances, edit, and record payments for bookings they created. Owners retain full access. Drivers see assigned trips only. Start/end trip actions are restricted to the scheduled date in India time. New bookings and changed travel dates must be tomorrow or later. Existing dates may be preserved during edits. Customers see only linked bookings. Disabled accounts and password resets revoke existing sessions. Temporary passwords require a change before data access.

Open booking screens refresh every 15 seconds, except while a dialog is open. This is polling, not instant push updates. Account management is owner-only. Booking edits preserve creator attribution and payment history. Owner-only soft deletion preserves payments and supports restoration. Owner edits and trip/deletion changes create recipient-scoped in-app notifications, with persistent read markers. Profile contains password settings. Overview contains outstanding balances and recent payments; Calendar shades days by booking count. Booking source is optional. Terms & conditions display the provided business declarations; they do not automatically enforce a 50% advance. Public registration, email recovery, customer-link reassignment, receipt generation, and Android packaging remain future work. Free Render services can sleep when idle.

## Local development and tests

Install requirements in a virtual environment; add `httpx` for tests. Run `python -m unittest test_server -v`.

For local-only development set `RSS_LOCAL_DB` to a local SQLite file, `APP_ORIGIN=http://127.0.0.1:4174`, and owner variables privately; run `uvicorn server:app --host 127.0.0.1 --port 4174`. SQLite is refused when Render/production mode is enabled. Never deploy SQLite storage on Render's ephemeral filesystem.

The server serves only explicitly listed public assets. It never serves `.env`, database files or backend source. Passwords use salted PBKDF2-SHA256 (600,000 iterations); sessions use random tokens stored hashed, HttpOnly/SameSite cookies and a 12-hour lifetime. Production cookies require HTTPS. Mutating requests require the exact configured Origin.

## Existing prototype

The old static preview is https://rss-travels.onrender.com and has no backend. Its browser-only sample records are not imported into MongoDB. Keep its previous deployment running until the authenticated web service is verified. Do not deploy backend files as a static-site update.

Source: https://github.com/anoobshukla/rss-travels
