# Step 2 — Install Splunk Enterprise (free tier) on your Mac

This needs your hands because it requires a Splunk account and a direct download — I
can't sign up for accounts or download files on your behalf.

1. Go to splunk.com and sign up for a free account (email + password — this is the
   trial/free tier, not a paid plan; it caps at 500MB of indexed data per day, which is
   far more than a home lab produces).
2. Download **Splunk Enterprise for macOS (Apple Silicon / ARM64), .dmg**.
3. Open the .dmg and run the installer.
4. During setup it'll ask you to create an admin username/password for the Splunk web
   console — write these down.
5. Once installed, Splunk runs as a local web app at:
   ```
   http://localhost:8000
   ```
6. Log in with the admin credentials you just set.

That's it for this step — just get it installed and confirm you can log into the web
console. Tell me once you're in and I'll walk you through configuring it to receive
forwarded logs from the Ubuntu VM.
