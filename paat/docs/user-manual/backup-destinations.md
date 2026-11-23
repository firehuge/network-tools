# Backup destinations (off-box copies)

Every backup the tool takes is always written to this server first, and that
local copy is always kept:

- OS upgrade **Back up** steps: running config, plus device state on firewalls.
- The running config saved by push **Prepare**, before a change.

An admin can add **extra copies** of those files for a customer, on another
system. This is opt-in per customer. With nothing set up (the default), backups
stay on this server only.

Destinations belong to the **customer**, not to a user. Every upgrade or push
for that customer lands in the same place, whoever runs it.

## What you see during a run

- On the upgrade run page, under the **Back up** step:
  - "Off-box copy OK: *name* (*type*), N file(s) verified", or
  - a yellow **CHECK: off-box copy to *name* failed** box with the reason.
- The push session page shows the same lines under the backup file name.
- A failed copy **never fails or blocks** the upgrade or the push: the backup
  is already safe on this server. Tell an admin, who can fix the destination
  with **Test connection**. The local copy is in the customer's data folder:
  `upgrade-backups/<hostname>_<serial>/<YYYY>/<MM>/<DD>/` for upgrades (the
  same layout as off-box), or `backups/` for push. Upgrade backups taken before
  an earlier date stay in their old `upgrade-backups/<plan-id>/`
  folders.
- report.md, the push report and the audit log record every copy.

## Where the files go

Every destination (git, SFTP, FTPS, S3) uses the same layout under its base
folder or prefix (for git, the repo itself):
**customer > device (hostname and serial) > year > month > day > files**.

```
<customer>/<hostname>_<serial>/<YYYY>/<MM>/<DD>/<HHMMSS>_<run-id>_<type>.xml
<customer>/<hostname>_<serial>/<YYYY>/<MM>/<DD>/<HHMMSS>_<run-id>_device-state.tgz
<customer>/<hostname>_<serial>/<YYYY>/<MM>/<DD>/<HHMMSS>_<run-id>_manifest.json
```

For example:

```
example/
  EXAMPLE-PANO_SN-EXAMPLE-1/
    2026/
      11/
        18/
          223744_upg-20260101-120000-abc123_running-config.xml
          223744_upg-20260101-120000-abc123_manifest.json
```

Open the customer to see one folder per device. Open a device, then the
year, month and day, to reach that day's backups.

- **customer:** the customer profile name (`example`). Even if two customers
  share a bucket or server, their folders never mix.

- **hostname and serial:** what the device reports, not the profile name.
- **run-id:** the upgrade plan id (`upg-...`) or the push session id (`push-...`).
- **type:** `running-config`, `device-state` or `pre-change-running-config`.
- **Time:** America/Chicago.
- **manifest.json:** customer, run id, CR, the user who ran the step, the
  device (hostname, serial, model), versions (running and target, content),
  and each file's name, size and SHA-256.

## Destination types

| Type | Use it for | Credential | How the copy is verified |
|---|---|---|---|
| **git** | A separate **private** repo for this customer. The tool's own source repository is refused. | SSH deploy key with **write access** (recommended), or an https token | The pushed commit is the remote branch head, and every file's blob hash matches |
| **SFTP** | Any SSH server | Private key (recommended) or password. The server's host key must be **pinned** | Size, and SHA-256 of the file read back |
| **FTPS** | FTP servers with TLS (explicit). Certificate checked by default | Password | SIZE, and SHA-256 of the file read back |
| **S3** | AWS S3 or S3-compatible (MinIO, VersityGW, Wasabi...). Leave the endpoint blank for AWS; turn on path-style for most self-hosted stores | Access key and secret | HEAD: size, and the SHA-256 stored with the object |

Plain FTP is not offered. It sends the password and the configs in clear text.

## Setting one up (admin)

The page starts with **Customer: <name>**, then lists the customer's devices
as they last reported themselves (`HOSTNAME · SN serial`, profile name in
grey) with the folder each one's backups go to.


1. Open **Backup destinations** in the left sidebar (Administration). You only see it with the
   admin role.
2. Pick the customer, then **Add** a type and fill in the form.
   - Secrets (password, token, key) are saved to
     `/etc/paat/backup-destinations/<customer>.env`, mode 600, readable only
     by the service user. They are never shown again. The page only says
     "set" or "not set". Leave a secret blank when editing to keep it.
   - The other settings go to `/etc/paat/backup-destinations/<customer>.json`
     (also 600). Neither file is ever in git.
3. **SFTP, or git over SSH:** click **Fetch host key**. Compare it with the
   real key, then **Pin this host key**. Uploads refuse an unpinned or changed
   host key.
   - Real key on a Linux server: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
   - GitHub's published ED25519 fingerprint:
     `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`.
4. Click **Test connection**.
   - S3, SFTP, FTPS: writes, reads back and deletes a small test file.
   - git: confirms read access and **write permission** with a dry-run push.
     Nothing is written.
5. Tick **Enabled**. From now on, every backup for that customer is also
   copied there.

Saving, testing, pinning and deleting are all written to the customer's audit
log. Secrets never are.

### git with a deploy key (GitHub)

1. Generate a key pair on the PAAT server:
   `ssh-keygen -t ed25519 -N '' -C panlab-<customer>-backups -f <file>`.
2. In the repo, go to **Settings > Deploy keys > Add deploy key**, paste the
   `.pub` file, and tick **Allow write access**.
3. In **Backup destinations**:
   - URL: `git@github.com:<owner>/<repo>.git`, or
     `ssh://git@ssh.github.com:443/<owner>/<repo>.git` if the network blocks or
     drops outbound SSH on port 22 (GitHub serves SSH on 443 with the same
     host key; the tool pins it as `[ssh.github.com]:443`).
   - Branch: usually `main`
   - Private key: paste the private key.
   - Then pin the host key, Test, and Enable.
4. Delete the key files you generated once the key is saved.

## Troubleshooting

| You see | Meaning | Fix (admin) |
|---|---|---|
| `host key is not pinned` | SFTP/git over SSH has no pinned host key | Fetch host key, check it, Pin |
| `Permission denied (publickey)` or `marked as read only` (git) | The key is wrong, or the deploy key has no write access | Re-add the deploy key with **Allow write access** |
| `timed out` / `Connection timed out` on port 22 (git) | Outbound SSH to the git server on port 22 is blocked or flaky | For GitHub, use `ssh://git@ssh.github.com:443/<owner>/<repo>.git`, pin the host key again, Test |
| `own repo` | Someone tried to use the tool's repo | Use a separate private repo |
| `verification failed` | Uploaded, but the size or hash read back differs | Check the destination's disk and quota; Test again |
| `No module named 'boto3'` / `'paramiko'` | The server's Python is missing the off-box extras | `pip install -e .[web,offsite]` in the venv (deploy/install-web.sh does this) |
