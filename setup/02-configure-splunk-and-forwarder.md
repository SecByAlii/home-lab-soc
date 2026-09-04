# Step 2 — Splunk on the host, forwarder on the VM

## Splunk Enterprise (macOS host)

1. Sign up for a free account at splunk.com and download **Splunk Enterprise for macOS
   (Apple Silicon/ARM64), .dmg**. This is the 60-day full trial — after that it
   auto-downgrades to the perpetual **Splunk Free** license (500MB/day indexing, no
   scheduled alerts/multi-user auth). No action needed when that happens, and nothing
   we're doing here depends on the enterprise-only features.
2. Run the installer, set an admin username/password when prompted.
3. First launch triggers a macOS keychain prompt (`mongod-8.0 wants to sign using
   key...`) — this is Splunk's bundled KV store asking to use a cert in your login
   keychain. Normal, allow it.
4. Log into `http://localhost:8000`.
5. Enable receiving so the forwarder has somewhere to send data: **Settings (gear icon)
   → Data → Forwarding and receiving → Configure receiving → New Receiving Port → 9997
   → Save**.

## Splunk Universal Forwarder (victim01)

Everything below runs over SSH from the Mac — no VM console needed once step 1's SSH
key is in place.

1. Download the **Linux ARM .deb** Universal Forwarder from
   splunk.com/en_us/download/universal-forwarder.html to the Mac, then push it to the VM:
   ```
   scp splunkforwarder-*.deb victim01:/tmp/splunkforwarder.deb
   ```
2. Install and start it, seeding a local admin password non-interactively (the
   forwarder's own admin account is just for local CLI management — never logged into
   day to day):
   ```
   sudo dpkg -i /tmp/splunkforwarder.deb
   sudo /opt/splunkforwarder/bin/splunk start --accept-license --no-prompt --answer-yes \
     --seed-passwd '<random password>'
   ```
3. Enable boot-start (requires stopping first) and point it at the Mac's forwarder
   receiving port. The shared-network gateway IP (`192.168.64.1`) is how the VM reaches
   the Mac:
   ```
   sudo /opt/splunkforwarder/bin/splunk stop
   sudo /opt/splunkforwarder/bin/splunk enable boot-start -user root --accept-license \
     --answer-yes --no-prompt
   sudo /opt/splunkforwarder/bin/splunk start --accept-license --no-prompt --answer-yes \
     --seed-passwd '<random password>'
   sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.64.1:9997 \
     -auth admin:'<random password>'
   ```
4. Install `auditd` (not present on a minimal Ubuntu Server install, and needed for the
   privilege-escalation/persistence techniques planned in `attack-simulations/`), then
   tell the forwarder what to monitor:
   ```
   sudo apt-get install -y auditd audispd-plugins
   sudo systemctl enable --now auditd
   ```
   `/opt/splunkforwarder/etc/system/local/inputs.conf`:
   ```
   [monitor:///var/log/auth.log]
   disabled = false
   sourcetype = linux_secure
   index = main

   [monitor:///var/log/audit/audit.log]
   disabled = false
   sourcetype = linux_audit
   index = main

   [monitor:///var/log/syslog]
   disabled = false
   sourcetype = syslog
   index = main
   ```
5. Restart the forwarder to pick up the new inputs: `sudo /opt/splunkforwarder/bin/splunk restart`

## Verifying it's actually working

- From the Mac: `lsof -i :9997` should show an `ESTABLISHED` connection from the VM's IP.
- In Splunk Web: `index=main host=victim01`, time range **All time** — events should show
  up with `sourcetype=linux_audit` and `sourcetype=syslog`.

Confirmed working on this build: 1,781 events indexed on first check.
