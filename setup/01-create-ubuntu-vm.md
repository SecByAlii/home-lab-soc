# Step 1 — Create the victim VM in UTM

UTM is installed at `/Applications/UTM.app`. This step is GUI-driven, so it's on you —
here's the exact path.

1. Open UTM.
2. Click **Create a New Virtual Machine**.
3. Choose **Virtualize** (not Emulate — we're staying native ARM, no x86 translation
   overhead).
4. Operating system: **Linux**.
5. Download the **Ubuntu Server LTS (ARM64)** ISO from ubuntu.com/download/server/arm
   (26.04.1 LTS as of this build — grab whatever the current LTS is). Server edition,
   not Desktop — no GUI needed on the victim box, keeps resource usage low.
6. Hardware: **4GB RAM, default CPU cores, 64GB disk** is plenty for this lab and leaves
   the Mac's 24GB / 650GB comfortable.
7. Networking: leave on the default **Shared Network** mode. This puts the VM on its own
   NAT'd subnet behind the Mac (gateway `192.168.64.1`), reachable from the Mac, isolated
   from the home LAN.
8. Finish the wizard, boot the VM, and run through the Ubuntu Server installer:
   - Hostname: `victim01`
   - Username: pick anything (e.g. `analyst`) — remember the password, needed for `sudo`
   - **Check "Install OpenSSH server"** when the installer offers it
   - Skip the optional snap packages — not needed here
9. **Eject the install ISO before the first real boot.** UTM/QEMU boots the virtual
   CD/DVD before the disk by default — if the ISO's still attached, GRUB re-launches the
   installer instead of booting the installed system. In UTM, stop the VM, open its
   settings, and Clear the CD/DVD entry before starting it again.
10. Log in and find the IP:
    ```
    ip a
    ```
    Look under `enp0s1` — typically `192.168.64.x`.

## SSH access without typing a password every time

The UTM console window doesn't support clipboard paste into a headless Linux guest, so
getting a public key onto the box means either typing it by hand (error-prone — a long
base64 string) or serving it over the local network and pulling it with `curl`. The
second way is faster and avoids typos:

1. On the Mac, generate a key and serve the `.pub` file over the shared-network gateway:
   ```
   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_victim01 -N "" -C "jarvis-home-lab-soc"
   python3 -m http.server 8765 --bind 192.168.64.1
   ```
2. In the VM:
   ```
   mkdir -p ~/.ssh && chmod 700 ~/.ssh
   curl -s http://192.168.64.1:8765/key.pub >> ~/.ssh/authorized_keys
   chmod 600 ~/.ssh/authorized_keys
   ```
3. From the Mac:
   ```
   ssh -i ~/.ssh/id_ed25519_victim01 analyst@192.168.64.2
   ```

**Gotcha hit during this build:** Subiquity's guided install created the user's home
directory with broken ownership/permissions — login dropped to `home = "/"` instead of
`/home/analyst`, and every `~/...` command failed with `Permission denied`, not because
of a typo but because `/home/analyst` itself couldn't be entered. Fixed with:
```
sudo chown -R analyst:analyst /home/analyst
sudo chmod 750 /home/analyst
```
then logging out and back in. Worth checking `pwd` right after first login — if it says
`/` instead of `/home/<user>`, this is why.

Once SSH access works, installing the Splunk forwarder and Atomic Red Team is doable
entirely over SSH without touching the UTM console again.
