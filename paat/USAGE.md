# Using PAAT

PAAT has three front ends: the **web GUI**, the **`paat` command line** and a read-only **API**. The full, page-by-page manual is
in [`docs/user-manual/`](docs/user-manual/index.md) and is also available inside the GUI under **Help**.

## 1. Sign in and look around

Open the address the installer printed (server: `http://SERVER/` or `https://SERVER/`; container: `http://SERVER:8080/`) and
sign in as the first admin. A new system is empty: add a customer profile first (see [INSTALL.md](INSTALL.md), "Your data is not included").

Roles: `viewer` (read only), `prep` (prepare plans), `engineer` (approve and push when allowed), `admin`
(users, backup destinations, settings). See [users and permissions](docs/user-manual/users-and-permissions.md).

## 2. The usual workflow

1. **Upload an FCR** (the Excel request form; download the blank form from the upload page, or see
   [the request form](docs/user-manual/fcr-request-form.md)). PAAT places each row on the right firewall and device group and
   produces a change set. ([FCR upload and change plans](docs/user-manual/fcr-upload-and-change-plans.md))
2. **Review the plan**: already-permitted flows are marked, similar requests are
   [combined](docs/user-manual/combine-rules.md), and the [change plan](docs/user-manual/plan-only-and-live-push.md) lists the GUI
   steps, `set` commands, rollback and verification.
3. **Approve** (optionally two-person) and either **apply the plan by hand** or, if an admin has opted the customer in, **push** it.
   Dry run is the default.
4. **Verify** with the read-back and log checks.

No device? Use a saved or uploaded backup: [backup-file plans](docs/user-manual/backup-file-plans.md).

## 3. Other tools in the GUI

| Page | Manual |
|---|---|
| Trace a flow | [trace-a-flow.md](docs/user-manual/trace-a-flow.md) |
| Decommission | [decommission.md](docs/user-manual/decommission.md) |
| Port to App-ID advisor | [app-id-advisor.md](docs/user-manual/app-id-advisor.md) |
| External dynamic lists | [edl.md](docs/user-manual/edl.md) |
| URL filter self-service | [url-filtering.md](docs/user-manual/url-filtering.md) |
| OS upgrades (plan; live steps off by default) | [os-upgrades.md](docs/user-manual/os-upgrades.md) |
| Backup destinations | [backup-destinations.md](docs/user-manual/backup-destinations.md) |
| API | [api.md](docs/user-manual/api.md) |

## 4. Command line

Run `paat --help`. On a server install use `sudo paat ...` (it runs as the `paat` user with `/etc/paat/paat.env` loaded).

```bash
paat customers                                   # list customer profiles
paat users add alice --role prep --password-file pw.txt
paat import --customer example FCR.xlsx          # read-only: build a change set
paat plan --customer example --changeset FILE.json
paat changeplan --customer example --changeset FILE.json     # Markdown change plan
paat flowtrace --customer example ...            # path trace with the FlowMapper engine
paat decom --customer example --items 'OLD-HOST,OLD-RULE'
paat uploads add --customer example backup.xml   # plan against a file, no live device
paat push ...                                    # dry run by default; --apply writes candidate config; --commit commits
```

`example` stands for a customer profile you create from `customers/profile.example.yaml`.

## 5. Safety defaults

- `paat push` is a **dry run**; writes need `--apply`, a commit needs `--commit`, and a backup is taken first.
- Live Panorama pushes are off for every customer until an admin sets `allow_live_panorama_push: true` in that profile.
- Live OS upgrade steps are off until the server setting `PAAT_UPGRADE_EXECUTE=1` is set.
- Credentials live in env files outside the repository (mode 600); profiles hold only variable names.

Remember: you are responsible for what you run against your devices. See [`../LEGAL.md`](../LEGAL.md).
