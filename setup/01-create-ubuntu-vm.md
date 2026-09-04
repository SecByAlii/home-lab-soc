# Step 1 — Create the victim VM in UTM

UTM is installed at `/Applications/UTM.app`. This step is GUI-driven, so it's on you —
here's the exact path.

1. Open UTM.
2. Click **Create a New Virtual Machine**.
3. Choose **Virtualize** (not Emulate — we're staying native ARM, no x86 translation
   overhead).
4. Operating system: **Linux**.
5. Download the **Ubuntu Server 22.04 LTS (ARM64)** ISO — UTM will offer to fetch it
   directly (`ubuntu-22.04-live-server-arm64.iso`). Server edition, not Desktop — we don't
   need a GUI on the victim box and it keeps resource usage low.
6. Hardware: **4GB RAM, 2 CPU cores, 40GB disk** is plenty for this lab and leaves your
   Mac's 24GB comfortable.
7. Networking: leave on the default **Shared Network** mode. This puts the VM on its own
   NAT'd subnet behind your Mac, reachable from the Mac, isolated from your home LAN.
8. Finish the wizard, boot the VM, and run through the Ubuntu Server installer:
   - Hostname: `victim01`
   - Username: pick anything (e.g. `analyst`) — write down the password, we'll need it
   - **Check "Install OpenSSH server"** when the installer offers it — we'll want SSH
     access from the Mac rather than working inside the UTM console window
   - Skip the optional snap packages (Docker, etc.) — we don't need them here
9. Once it boots to a login prompt, find its IP address by logging in and running:
   ```
   ip a
   ```
   Look for the address under the `enp0s1` (or similar) interface — usually something
   like `192.168.64.x`.
10. From your Mac terminal, confirm you can reach it:
    ```
    ssh analyst@192.168.64.x
    ```

Tell me the IP once it's up and I'll take it from there — installing the Splunk
forwarder and Atomic Red Team on it is something I can do over SSH without you touching
the UTM console again.
