# Install PAAT

PAAT runs on a Linux server (Ubuntu 22.04/24.04 or Rocky/RHEL 9) or as a container (Docker or Podman).
Both start as a **blank system**.

## Your data is not included

PAAT ships with **no customers, no devices, no Panorama or firewall targets, no EDL lists, no site codes and no users**
(other than the first admin you create during the install). "Our data" (the authors' own devices and customer setups) is not part of this
repository; you add your own:

1. **First admin.** The installer prompts for the admin name and password. For an unattended install you can give a password file
   (`--admin-password-file`, or `PAAT_ADMIN_PASSWORD_FILE` for the container); otherwise a random one-time password is generated and
   written to `/etc/paat/INITIAL_ADMIN_PASSWORD` (mode 600; two lines, `user: ...` and `password: ...`). It is never printed in a log.
   Read it once, sign in, change it, and delete the file.
2. **Customers.** Copy `customers/profile.example.yaml` to `/etc/paat/customers/<name>/profile.yaml` (server) or into the
   config volume at `/etc/paat/customers/<name>/profile.yaml` (container). Profiles hold only *names* of environment
   variables; put host names and API keys in the env file the profile points to (mode 600). See `customers/README.md`.
3. **Users.** Sign in as the admin and open **Users**, or run `sudo paat users add NAME --role viewer|prep|engineer|admin --password-file FILE`.
4. **Lists, destinations, site codes.** Create them in the GUI (EDLs, backup destinations) or in the customer profile (site codes).

The repository's `tests/` folder has synthetic customers and configurations for the unit tests only; they are not installed
into a running system (the container image leaves `tests/` out).

> **Before you install:** read [`../LEGAL.md`](../LEGAL.md). In particular: use only legally licensed Palo Alto Networks
> products, do not use PAAT to violate any vendor terms, and have your organization's security team approve it before
> you install or use it.

## Server install (Ubuntu / Rocky / RHEL)

Tested releases: **Ubuntu 22.04 and 24.04**, **Rocky Linux 9** (RHEL 9 and AlmaLinux 9 use the same path).

### Before you start

You need:

| Item | Detail |
|---|---|
| A server | A virtual machine is fine. 2 CPU, 2 GB memory and 10 GB of disk are plenty to start. |
| An account that can use `sudo` | The installer must run as root. |
| Internet access during the install | It downloads packages, Python libraries and (if the server has no Node.js 18+) the official Node.js build from nodejs.org, checked against its published checksum. After that PAAT itself needs no internet. |
| Network reach to your firewalls | Only needed for live reads and pushes: the PAAT server must reach Panorama and the firewalls on HTTPS (443). |
| `systemd` | Present on every supported release. (A container has none; use the container guide.) |

### Quick start (about three minutes)

```bash
# 1. get the code onto the server (a git checkout or a release archive)
cd paat            # the folder that contains install.sh (this folder)

# 2. install (HTTP, for a private management network)
sudo ./install.sh

# ...or with HTTPS and a self-signed certificate
sudo ./install.sh --tls
```

The installer asks for the **first admin's** name and password. The password is not shown while you type it, is never put on a command line, and is never written to a log. When it finishes it prints the address to open, for example `https://10.0.0.20/`.

Then sign in, open **Users** to add your team, add your own customer profiles (see [Your data](#your-data-is-not-included)), and read **Help**.

### What the installer does

| Step | Result |
|---|---|
| Checks the operating system and `systemd`. | Stops with a clear message on an unsupported system. |
| Installs what is missing. | Python 3.10 or newer, `venv`, `pip`, `openssl`, nginx, time-zone data. Nothing is upgraded that is already there. |
| Creates a service user. | `paat`, no login shell, owns only its own config and data. |
| Copies the code to `/opt/paat/app` and builds a Python virtual environment at `/opt/paat/venv`. | The code is owned by root, so the service cannot change its own program. |
| Writes the settings. | `/etc/paat/paat.env` and a secret session key. **No customers, devices or EDL lists are created.** |
| Creates the first admin. | Only if there are no users yet. This is the only account that exists after the install. |
| Installs the `paat` service. | A hardened systemd unit (`paat.service`) that listens on `127.0.0.1:8080` only. |
| Configures nginx. | Port 80 (HTTP) or, with `--tls`, port 443 with HTTP redirected to it. |
| Checks it works. | Calls `/healthz` on the service and through nginx, and stops with the log if either fails. |
| Tells you about the host firewall. | See [Firewall](#firewall). |

### Where things live

| Path | What it holds |
|---|---|
| `/opt/paat/app` | The program (read-only to the service). The previous version is kept in `/opt/paat/app.prev` after an upgrade. |
| `/opt/paat/venv` | The Python environment. |
| `/etc/paat/` | Settings (`paat.env`), users, the session key, customer profiles, backup destination secrets. Owned by `paat`, mode 700. |
| `/var/lib/paat/data` | Change sets, uploaded backups, approvals, audit records. **Back this up.** |
| `/var/lib/paat/backups` | Configuration exports made by the CLI. |
| `/etc/paat-tls/` | The TLS certificate and key (only with `--tls`). |
| `/etc/nginx/sites-available/paat` (Ubuntu) or `/etc/nginx/conf.d/paat.conf` (Rocky) | The web proxy settings. |
| `/usr/local/bin/paat` | The command line. Run it with `sudo paat ...`; it always runs as the `paat` user. |

### Options

Run `./install.sh --help` for the full list. The common ones:

| Option | Meaning |
|---|---|
| `--tls` | HTTPS with a self-signed certificate (valid 825 days). Your browser warns once. |
| `--tls-cert FILE --tls-key FILE` | Use your own certificate (for example from your internal CA). |
| `--server-name NAME` | The name in the certificate and nginx (default: the server's own name). |
| `--http-port N`, `--https-port N`, `--app-port N` | Change the ports. |
| `--no-nginx` | Do not install nginx; point your own proxy at `127.0.0.1:8080`. |
| `--admin NAME` | First admin's name (default `admin`). |
| `--admin-password-file FILE` | Read the first admin's password from the first line of FILE (for automated installs). |
| `-y` | Ask nothing. With no terminal and no password file, a random password is written to `/etc/paat/INITIAL_ADMIN_PASSWORD` (mode 600) and never printed. |
| `--open-firewall` | Open the web port in `ufw` or `firewalld` for you. |
| `--skip-node` | Do not install Node.js (flow tracing will not work until you do). |

### Firewall

The installer does not open ports unless you pass `--open-firewall`; it prints the exact command instead.

- **Ubuntu (ufw):** `sudo ufw allow 443/tcp` (or 80/tcp for plain HTTP).
- **Rocky/RHEL (firewalld):** `sudo firewall-cmd --permanent --add-port=443/tcp && sudo firewall-cmd --reload`.
- Only the web port needs to be reachable by your users. Port 8080 is local to the server.
- On Rocky/RHEL with SELinux enforcing, the installer allows nginx to reach the local service (`httpd_can_network_connect`).

### Upgrade

Get the newer PAAT folder onto the server, then:

```bash
sudo ./install.sh --upgrade
```

Config, users and data are untouched; the TLS and port choices from the first install are remembered. If an OS upgrade step or a push is running, the installer waits instead of restarting (re-run when idle, or `FORCE_RESTART=1`). To go back, stop the service and swap `/opt/paat/app.prev` back in.

### Uninstall

```bash
sudo ./install.sh --uninstall            # removes the service, nginx site and program; KEEPS config, users and data
sudo ./install.sh --uninstall --purge    # also deletes /etc/paat, /var/lib/paat and the paat user
```

`--purge` cannot be undone. nginx itself is left installed. If you used a port other than 80, the stock nginx default site may still be listening on port 80 with the welcome page; stop nginx only if you do not need it for anything else: `sudo systemctl disable --now nginx`.

### Running it again

Running `sudo ./install.sh` on a server that already has PAAT is safe: it re-checks everything, never replaces existing users, and only rewrites files it owns.

### Troubleshooting

| You see | Do this |
|---|---|
| `unsupported OS` | Use Ubuntu 22.04/24.04 or RHEL/Rocky/Alma 9, or the container. |
| The page does not load | `systemctl status paat nginx`, then `journalctl -u paat -n 50`. Check the firewall note above. |
| Browser warns about the certificate | Expected with a self-signed certificate. Use `--tls-cert/--tls-key` to remove the warning. |
| 502 Bad Gateway | The `paat` service is down: `journalctl -u paat -n 50`. On Rocky, check `getsebool httpd_can_network_connect`. |
| Forgot the admin password | `printf '%s\n' 'a-new-long-password' \| sudo paat users add admin --role admin --password-stdin` resets it. |
| Flow tracing fails | Node.js 18+ is missing: `PAAT_NODE` in `/etc/paat/paat.env` must point to it. Re-run the installer without `--skip-node`. |




## Container install (Docker or Podman)

PAAT ships a `Dockerfile` and a `docker-compose.yml`. They work the same with **Docker** and **Podman**. The image is small (about 320 MB), runs as a normal user (uid 10001), never as root, and has Node.js 22 inside for flow tracing.

### Quick start with Docker Compose

```bash
# 1. the first admin's password goes in a file, not on a command line.
#    Put your own password in the file, or leave the file empty (zero bytes)
#    to have PAAT generate a one-time password into /etc/paat/INITIAL_ADMIN_PASSWORD
#    inside the config volume (read it with: docker compose exec paat cat /etc/paat/INITIAL_ADMIN_PASSWORD).
mkdir -p docker/secrets
( umask 077; printf '%s\n' 'choose-a-long-password' > docker/secrets/admin_password.txt )
sudo chown 10001 docker/secrets/admin_password.txt     # the container user must be able to read it
sudo chmod 400 docker/secrets/admin_password.txt
# rootless Podman: use `podman unshare chown 10001 ...` instead of `sudo chown 10001 ...`

# 2. build and start
docker compose up -d --build

# 3. open http://SERVER:8080 and sign in as "admin"
#    To bind a high port on localhost only, put this in a .env file next to docker-compose.yml:
#      PAAT_HTTP_PORT=18080
#      PAAT_BIND=127.0.0.1
```

The admin is created only on the **first** start, while there are no users. After that the password file is no longer used.

### What you get

| Piece | Detail |
|---|---|
| Image | `localhost/paat:latest`, built from `Dockerfile` (Python 3.12 slim + Node 22 binary). |
| Port | 8080 inside; published as `${PAAT_HTTP_PORT:-8080}`. |
| Health | `HEALTHCHECK` calls `/healthz`. `docker compose ps` shows `healthy`. |
| Volumes | `paat-config` (`/etc/paat`: users, session key, customers), `paat-data` (`/var/lib/paat/data`: change sets, uploads, audit), `paat-backups`. **Back these up.** |
| Secrets | The admin password comes from a file secret (`PAAT_ADMIN_PASSWORD_FILE`). `PAAT_ADMIN_PASSWORD` also works but shows up in `docker inspect`, so prefer the file. Customer API keys go in `/etc/paat/customers/*.env` inside the config volume, or as environment values you add under `environment:`. |
| Hardening | Read-only root file system, all Linux capabilities dropped, `no-new-privileges`. |

### HTTPS (optional nginx)

```bash
docker/make-self-signed-cert.sh paat.example.com        # or put your own paat.crt and paat.key in docker/tls/
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
# open https://SERVER:8443
```

The TLS override adds an nginx container. It is a second compose file, not a Compose profile, so `podman-compose` (which on Ubuntu 24.04 ignores profiles) will not start nginx on a default `up`. Set `PAAT_BIND=127.0.0.1` if only nginx should be reachable from outside.

### Settings you may want

Set these in a `.env` file next to `docker-compose.yml` (never commit it):

| Setting | Default | Meaning |
|---|---|---|
| `PAAT_HTTP_PORT` | `8080` | Published web port. |
| `PAAT_HTTPS_PORT` | `8443` | Published HTTPS port (TLS override file). |
| `PAAT_BIND` | `0.0.0.0` | Address the ports bind to. |
| `PAAT_ADMIN_USER` | `admin` | Name of the first admin. |
| `TZ` | `UTC` | Time zone for the container. |
| `PAAT_UPGRADE_EXECUTE` | off | Uncomment in the compose file to allow live OS upgrade steps. |

### Everyday commands

```bash
docker compose logs -f paat                         # watch the log
docker compose exec paat paat users list            # run any PAAT command
docker compose exec paat paat --help
docker compose down                                 # stop (volumes are kept)
docker compose down -v                              # stop AND delete all PAAT data (cannot be undone)
```

**Upgrade:** pull or copy the new PAAT folder, then `docker compose up -d --build`. The volumes keep users and data.

### Plain `docker run`

```bash
docker build -t paat .
docker run -d --name paat -p 8080:8080 \
  -e PAAT_ADMIN_PASSWORD_FILE=/run/admin_pw -v "$PWD/docker/secrets/admin_password.txt:/run/admin_pw:ro" \
  -v paat-config:/etc/paat -v paat-data:/var/lib/paat/data -v paat-backups:/var/lib/paat/backups \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges paat
```

### Podman

Everything above works with `podman` in place of `docker`, and with `podman compose` (or `podman-compose`).

```bash
podman build --format docker -t localhost/paat:latest .
podman compose up -d          # or: podman-compose up -d
```

Notes for Podman:

- **Rootless Podman.** The container's uid 10001 maps to a sub-uid on the host, so `sudo chown 10001` on the secret file is not enough (the container cannot read it and will refuse to start). Use a Podman secret instead:
  `printf '%s\n' 'choose-a-long-password' | podman secret create paat_admin_password -`
  and run with `--secret paat_admin_password -e PAAT_ADMIN_PASSWORD_FILE=/run/secrets/paat_admin_password`. Or run `podman unshare chown 10001 docker/secrets/admin_password.txt`.
- Build with `--format docker` (or `BUILDAH_FORMAT=docker`) so the image health check is recorded. `podman-compose up --build` rebuilds without that flag unless you export `BUILDAH_FORMAT=docker` first.
- Ubuntu 24.04's `podman-compose` 1.0.6 ignores Compose profiles. That is why TLS nginx lives in `docker-compose.tls.yml` rather than a profile: a default `up` starts only PAAT.
- **Run as a service.** `podman generate systemd --new --name paat` (or a Quadlet `.container` file) turns the container into a systemd service that starts at boot.
- **SELinux hosts** (Rocky/RHEL): add `:Z` to bind mounts, for example `-v ./docker/tls:/etc/nginx/tls:ro,Z`.

### Check that it works

```bash
curl -fsS http://localhost:8080/healthz          # prints: ok
docker compose ps                                # paat should be "healthy"
```

Sign in as the first admin. The system is empty: there are no customers, devices or lists yet. Add your own (see [Your data](#your-data-is-not-included)).

### Troubleshooting

| You see | Do this |
|---|---|
| `cannot read /run/secrets/paat_admin_password` in the log | The container user cannot read the secret file. See the `chown 10001` step, or the rootless Podman note. |
| `502` or a timeout through nginx on a host with other firewall rules | Check that the two containers can reach each other on the compose network; some hosts need bridge traffic allowed in their firewall. |
| Browser warns about the certificate | Expected with a self-signed one; use your own `paat.crt` and `paat.key`. |
| Lost the admin password | `docker compose exec paat sh -c "printf '%s\n' 'a-new-long-password' \| paat users add admin --role admin --password-stdin"` |


## Verify a blank install

```bash
curl -fsS http://localhost:8080/healthz              # container: prints "ok" (server install: use http://127.0.0.1:8080/healthz)
sudo paat customers                                  # server: lists no customers
sudo paat users list                                 # server: lists only the first admin
```
