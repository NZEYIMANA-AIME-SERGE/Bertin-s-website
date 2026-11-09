# WISD Science Academy website

This project is a small Python standard-library web application. SQLite holds accounts, enrollment requests, payment references, membership discussions, and library metadata. Uploaded PDFs and UTF-8 text files are stored privately under `wisd_data/library/` and are served only through the application.

## Start locally on Windows

Open PowerShell in this folder and set a strong administrator password before the first start:

```powershell
$env:WISD_ADMIN_PASSWORD = "choose-a-long-unique-password"
python server.py
```

Open `http://127.0.0.1:8000`. The public site has separate Home, Programs, Library, Community, and Join pages. The administrator workspace is available privately at `/admin` and is intentionally not linked from public navigation. The first start creates the administrator account for MASENGESHO Bertin, using phone number `0727650086`. Keep the password and workspace address private. If no administrator is created on the first start, set `WISD_ADMIN_PASSWORD` and restart; an administrator is added when the database has none.

To use another port, set `$env:PORT`. The first start creates `wisd_data/`; back up this folder securely because it contains the database and uploaded library files. Do not publish it as a static website directory.

## Deploy to Render

The included `render.yaml` defines a Frankfurt web service and a 1 GB persistent disk for the SQLite database and library uploads. It uses the paid Starter web plan because Render requires a paid service for persistent disks. Current listed prices are about $7/month for Starter compute plus $0.25/month for a 1 GB disk. Render will prompt for `WISD_ADMIN_PASSWORD` when the Blueprint is first created; use a new, unique password of at least 12 characters, not the password previously used locally. Keep the disk attached after deployment so account, discussion, and library data survive restarts.

After pushing this project to a GitHub repository, create a Blueprint in Render from that repository and select `render.yaml`. Review the paid plan and disk before confirming creation. Render auto-deploys later commits from the connected Git branch.

Signed-in users can change their password from the sign-in panel. The administrator can recover a forgotten password locally: stop the server with `Ctrl+C`, run `python server.py --reset-admin-password`, enter and confirm a new password at the prompts, then restart with `python server.py`. This invalidates all existing sign-in sessions.

## Payments and access

Membership, student enrollment, and each resource download cost 100 RWF and are paid to `0727650086`, registered to MASENGESHO Bertin. Applicants create an account and submit the mobile money transaction reference. The administrator must check the transaction and approve or reject it in the control panel. Approval grants membership or the requested download. The site does not connect to a mobile money provider, so it cannot verify payments automatically.

Anyone can browse and read published PDFs or text files without signing in. Only the administrator can publish or remove library items. Member discussions require a signed-in, approved member account.

Visitors create member or student accounts from **Join** and choose and confirm their own password. The administrator can create an approved member or student account after checking the person's 100 RWF payment record; the person then sets their own password with the one-time setup code that the administrator shares privately. Setup codes expire after 30 days and can only be used once. The administrator can issue a replacement code from the request card if needed.

## Before public deployment

Run the app behind a maintained HTTPS reverse proxy, set `WISD_HTTPS=1` so session cookies use the `Secure` flag, use a private strong administrator password, and restrict access to the database and upload backups. The included server is intended as a compact starting point; it does not provide automated mobile money callbacks, password recovery, email delivery, or account verification. Automatic payment confirmation requires credentials and callback setup from a supported payment provider.
