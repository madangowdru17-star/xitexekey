# XIT-EXE Key Server Deployment

This bundle contains the upgraded Flask server with a scalable SQLite key store, APK-compatible verification endpoints, VPLINK callback support, and the professional admin dashboard.

## Files

| File | Purpose |
|---|---|
| `app.py` | Main Flask server |
| `requirements.txt` | Python dependencies |
| `.env.example` | Environment-variable template |

The bundle intentionally does not include the live SQLite database, passwords, VPLINK token, or Flask secret. Configure those in the panel environment instead.

## Installation

1. Upload and extract the ZIP in the panel application directory.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables from `.env.example`. At minimum, set:

   ```text
   ADMIN_PASSWORD=your-long-random-admin-password
   FLASK_SECRET_KEY=your-long-random-secret
   VPLINK_TOKEN=your-vplink-token
   PUBLIC_BASE_URL=https://xitexe.jo3.org
   PORT=5555
   SESSION_COOKIE_SECURE=0
   ```

   `SESSION_COOKIE_SECURE=0` is required when using the direct HTTP address
   `http://45.196.196.241:5555/admin`. If the panel is HTTPS-only, set it to
   `1` instead. Never use a plain HTTP admin panel on an untrusted network;
   prefer the HTTPS domain whenever possible.

4. Start the server with:

   ```bash
   python app.py
   ```

   The server binds to `0.0.0.0` and uses the `PORT` value supplied by the panel.

5. Confirm health:

   ```text
   https://xitexe.jo3.org/health
   ```

6. Open the dashboard:

   ```text
   https://xitexe.jo3.org/admin
   ```

## Existing APK compatibility

These endpoints are preserved:

- `/s.php`
- `/l.php`
- `/api/check.php`
- `/api/v1/verify-key`

Successful `/api/check.php` responses include normalized UTC expiry and a numeric `expires_unix` field for the edited APKs.

## Key management

Generated keys use the format:

```text
XIT-EXE-XXXXX-XXXXX-XXXXX
```

The dashboard supports custom expiry hours, device limits, custom keys, notes, renew, revoke, individual delete, revoke-all, delete-all, search, filtering, pagination, and maintenance mode.

## Important deployment note

Do not commit `.env`, the SQLite database, or real credentials to a public repository. Back up `xitexe.sqlite3` before upgrades. The server enables SQLite WAL mode and a busy timeout for concurrent admin/API traffic.
