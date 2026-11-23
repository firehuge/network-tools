# OS upgrades (reference)


Upgrade PAN-OS on a standalone firewall, or on a Panorama and the firewalls
behind it, without having to remember the order or the commands. The tool
picks a safe target, puts the steps in the right order, refuses anything
unsafe, and does one step at a time while you watch.

**Who can do what**

| Permission | Can |
|---|---|
| `view` | Download change plans and reports |
| `upgrade_plan` | Run discovery (read-only) and build dry-run plans |
| `upgrade_exec` | Arm a plan with an approved CR and run it |
| `upgrade_panorama` | Include Panorama itself (otherwise Panorama is shown read-only) |

Each user only sees the customers and devices in their scope (for example,
one customer's `dg:<device group>`). See [Users and permissions](users-and-permissions.md).

Live runs also need the server switch `PAAT_UPGRADE_EXECUTE=1` in the
`paat` service. Without it, the tool only builds plans and change plans.
It is **off** until an admin turns it on. Permissions, CR,
yellow acknowledgement and per-step typed confirmation still apply.

### Turning the live switch on or off (admin, on the PAAT server)

The switch is a systemd drop-in,
`/etc/systemd/system/paat.service.d/upgrade-execute.conf`:

```
[Service]
Environment=PAAT_UPGRADE_EXECUTE=1
```

- **Disable:** `sudo rm /etc/systemd/system/paat.service.d/upgrade-execute.conf`
  (or set the value to `0`), then `sudo systemctl daemon-reload && sudo systemctl restart paat`.
- **Enable:** recreate the file above, then the same reload and restart.
- **Check:** `curl -s http://127.0.0.1:8080/healthz` says `ok`; the plan page
  shows the **Arm for live upgrade** form without the "switched off" note.

The switch applies to every customer on the server (including standalone firewalls),
so turn it off if only dry-run plans should be possible.

## Before you start

- You have an approved CR and you are inside its window.
- You know whether the customer's firewalls are managed by Panorama (the tool
  will tell you, but you should not be surprised).
- Nobody else is mid-change on Panorama. The tool checks this before it reboots
  Panorama and waits if someone is committing or pushing.

## How the tool reaches each device: through Panorama, or direct

If a Panorama in the customer manages a firewall, **everything for that
firewall goes through Panorama**: discovery, backup, content, download,
install, reboot and checks. Every job is in Panorama's Task Manager and logs,
and the tool does not need the firewall's own address or API key. Only a
standalone firewall (no Panorama) is upgraded on its own API.

You can see the path on every page:

- Discovery card: `upgrade path: via Panorama <HOSTNAME · SN serial>` (or
  `direct to the firewall's own API (standalone firewall)`).
- Plan: an "Upgrade path" line under each firewall and a green **Upgrade
  path** check.
- Run page: next to each device, and in "This step touches ...".
- CR change plan: "Upgrade path for ...".



| What the tool does | Firewall managed by Panorama | Standalone firewall |
|---|---|---|
| Find it and read its version, hostname, serial, HA | Panorama's managed-device list (`show devices all`) and reads through Panorama (`target=<serial>`) | its own API |
| Versions on offer | the `PanOS_<platform>` images Panorama can deploy (Panorama > Device Deployment > Software) | the firewall's own software check |
| Back up | the firewall's running config (read through Panorama) **and** Panorama's running config | running config and device state |
| Content, download, install | Panorama Device Deployment (`request batch ...`) | the firewall's own Dynamic Updates / Software |
| Reboot | Panorama (`request batch reboot devices <serial>`), only when Panorama is not pushing | the firewall itself |
| Wait and post-check | Panorama shows it connected on the new version; checks read through Panorama | its own API |

If the plan says **"Panorama-managed firewall: direct upgrade refused"**
(red), the customer profile forces the firewall's own API (`access: direct`)
or the firewall is managed by a Panorama that is not in the profile. Ask an
admin to remove `access: direct`, or to add that Panorama to the customer.
An admin can allow the direct path for an emergency only
(`allow_direct_managed: true`); the plan then shows a yellow "override" item
and the tool audits it.

The same rule applies to rule pushes: a change set aimed directly at a
Panorama-managed firewall is blocked at Prepare; build it for the Panorama
target (device group) instead.

## Which device is this? Hostname and serial

Profile names such as `pano-1` are labels someone typed into the customer
profile. They are not proof of what you are about to change. So the tool reads
each device's **own hostname and serial number** over the API and shows them
next to the profile name everywhere a device is named:

**`<HOSTNAME> · SN <serial>`**, with the profile name (`pano-1`) after it in
small grey text, or in [brackets] in reports, CR change plans and the audit
log. Example (fake device): `EXAMPLE-PANO · SN SN-EXAMPLE-1 [pano-1]`.

The profile name only leads when the device could not be read; then you see
`pano-1 · hostname unknown · SN unknown` and a yellow box. Every page also
starts with the heading **Customer: <name>**.


- **Where it comes from:** `show system info` on Panorama and standalone
  firewalls. For a firewall behind Panorama, `show system info` through
  Panorama, or Panorama's managed-device list if the firewall does not answer.
- **Where you see it:** discovery cards, the plan, every step title, the
  confirmation box, the run page, report.md and report.json, the CR change
  plan's "Devices in scope" table, and every audit-log line.
- **What you type to confirm a step:** the **hostname the device reports**,
  not the profile name. If two devices in the plan report the same hostname
  (for example two factory-default `PA-VM`s), or the hostname could not be
  read, you type the **serial number** instead. The box tells you which.
- **Hostname unknown:** if the hostname or serial cannot be read, the plan
  shows a yellow **Hostname unknown** (or **Serial number unknown**) item, and
  the device is named by its profile name instead.
  Check the device itself (Dashboard > General Information) before you arm.
- **Different device:** each pre-check reads the identity again. If the serial
  is not the one the plan was built for, the step fails red ("A different
  device answered") and nothing else runs. A changed hostname on the same
  serial is yellow.
- The tool shows what the device reports; it never renames anything. The device PA-VM still reports the factory hostname `PA-VM`, so that is what you see
  and type.

The FCR push pages do the same: the target list shows the hostname and serial
the device last reported, **Prepare** reads them again, Apply and Rollback ask
for the reported hostname and refuse if a different serial answers, and the
push report and audit log record them. See
[plan-only-and-live-push.md](plan-only-and-live-push.md).

## Step 1: Discover (read-only)

1. Open **OS upgrades** in the left sidebar (Operations).
2. Pick the customer and leave **Ask the update server for the newest list**
   ticked.
3. Click **Discover devices (read-only)**. It takes 20 to 40 seconds per device.

What you will see: one card per device, including every firewall a Panorama
reports as connected. Each card starts with the profile name and the
hostname and serial the device reports. It also shows the running version, content version,
HA state, uncommitted changes, free disk, the newest hotfix of the release it
runs, and the newest release in its train, with a one-line "why" under it.

Nothing is changed on any device in this step.

If a yellow banner says the device **is not registered or has no valid support
license**, it cannot download software from Palo Alto Networks. You will only
be able to pick versions that are already on the device. (Some devices show: the update server answers "The device is not found or not
registered" and lists only local images.)

## Step 2: Pick versions and build the plan


1. Tick each device to upgrade. The **recommended** version is already
   selected: the newest release in the train the device runs today (for
   example 11.1.x). Pick a different one only if the CR says so.
2. Click **Build the plan (dry run)**.

What you will see:

- An overall light: **GOOD** (green), **CHECK** (yellow) or **STOP** (red).
- Each device with its checks. Red means the tool will not let you run the
  plan. Read the sentence next to it; it says what to fix.
- The steps in order. Panorama always comes first. HA pairs go passive first.
- A **CR change plan (.md)** link: implementation steps (GUI and CLI), impact,
  backout, validation and communications, ready to paste into the CR.

Checks that block the plan (red):

| Check | What it means | What to do |
|---|---|---|
| Firewall newer than Panorama | A firewall target is above Panorama's version | Add Panorama to the plan with the same or newer target, or pick a lower firewall target |
| HA peer not in plan / not in sync | Only one HA unit picked, or config not synchronized | Pick both peers; sync them; discover again |
| Uncommitted changes (firewall) | Someone left candidate changes | Commit or revert them, discover again |
| Not enough disk | `/opt/panrepo` too full | Delete old images (Device > Software), discover again |
| No content installed | No Apps/Threats content | Install content first |
| Cannot download | Not registered / no support license / no internet | Fix registration or pick a version already downloaded |
| Downgrade or version not offered | Target older than running, or not in the device's list | Pick another version |

Yellow items (for example "Minimum content not verified", or "Uncommitted
changes on Panorama") do not block, but you must tick **I have read every
yellow item** to arm the plan.

## Step 3: Arm and run (red bar)


1. Enter the approved CR number, tick **This CR is approved...**, tick the
   yellow acknowledgement, and click **Arm for live upgrade**.
2. The page turns red. It lists every device as `HOSTNAME · SN serial`
   (profile name in small grey).
   The next step says which device it touches; type the **hostname the device
   reports** (or the serial, when the box asks for it) exactly as shown and
   click **Run step N**. The profile name is refused.
3. Long steps (content, download, install, waiting for a reboot) show a job
   number and percent; the page refreshes every 15 seconds. When a step turns
   green the next one appears.

Steps for each device, in order:

| Step | What it does | Typical time |
|---|---|---|
| Pre-check | Re-reads the device; stops on anything red. For a firewall, re-reads Panorama's live version | under 15 s |
| Back up | Saves the running config (standalone firewall: plus device state; Panorama-managed firewall: plus Panorama's running config) on this server, and copies it to every [backup destination](backup-destinations.md) an admin set up for the customer, then verifies (a failed copy is a yellow CHECK, never a stop). The step says **Backed up to:** this server and each destination by name and type (for example "Lab S3 (S3)"). If the customer has no off-box destination, the step says so; use **Download backup** on that step | 2 s (+ copy) |
| Update content | Panorama: `request content upgrade` download + install of the latest. Managed firewall: Panorama downloads the newest Apps+Threats package and upload-installs it on the firewall | 4 to 18 min |
| Download | Downloads the image (managed firewall: Panorama downloads `PanOS_<platform>-<version>`) | 4 to 6 min |
| Install | Installs it (managed firewall: Panorama upload-installs it on that serial). No reboot yet | 4 to 6 min |
| Reboot | Panorama: refused while Panorama has running/queued jobs or uncommitted changes. Managed firewall: refused while Panorama is pushing; then `request batch reboot devices <serial>` | seconds |
| Wait | Polls until the device answers on the new version (managed firewall: until Panorama shows it connected on the new version) | 5 to 6 min |
| Post-check | Version, HA state and sync, Panorama connection, interfaces, sessions, last commit | 10 s |

If any step fails, the plan **stops**. Nothing after it can run. The step
shows the device's error and a **What to do** line in plain English.

When everything is green, download **report.md** and attach it to the CR.

### Downloading the backup

Once a Back up step has run, it shows a **Download backup** button: a zip of
that device's backup files from this run. When the run is done, the page also
offers **Download backups (zip)** for every device in the run. Anyone who can
plan or run upgrades for that customer and device can download it; other
customers' users get "not in your scope". Every download is in the audit log
(`upgrade-backup-download`). Keep the zip with the CR when the customer has no
off-box backup destination.

## Rolling back

Besides the commands below, the wizard can **downgrade a firewall** to an earlier version in the train it runs (for example `11.1.13-h17` back to `11.1.13-h9`): pick it under **Older versions: DOWNGRADE** on the discovery page, acknowledge the yellow item and run the plan like any other. Panorama is never downgraded from the tool, and a cross-train downgrade is refused with a reason.

The change plan's Backout section has the exact commands. In short, on the
device that misbehaves: `debug swm revert` then `request restart system`
(GUI: Software > previous version > Revert). Roll back firewalls before their
Panorama, never Panorama below its firewalls. The pre-upgrade config is in the
customer's backup folder on the PAAT server, in any configured backup
destination, and in the run's **Download backup** zip.

## Troubleshooting

| You see | Do this |
|---|---|
| "not registered or has no valid support license" | Register/activate support in the Customer Support Portal; until then only images already on the box can be installed |
| "could not reach the Palo Alto Networks update server" | Check the device's DNS, default gateway and outbound access |
| "content is too old for this PAN-OS version" | Run the content step (or Dynamic Updates) and retry with a new plan |
| "Panorama is busy" on the reboot step | Wait for the other engineer's commit/push to finish, then click Run again |
| "Live upgrades are switched off on this server" | Use the change plan by hand, or ask an admin to set `PAAT_UPGRADE_EXECUTE=1` |
| A step shows FAILED | Read the error and What to do; the plan is stopped. Fix, discover again, build a new plan. Use the backout if a device is unhealthy |
| Content download sits at one percent for a long time | Normal on a slow update server; the step times out after 90 minutes |

## CLI equivalent

The same code runs from the PAAT server:

```
python -m panlab.upgrade discover <customer>
python -m panlab.upgrade plan <customer> <disc-id> t:<target>=<version> ...
PAAT_UPGRADE_EXECUTE=1 python -m panlab.upgrade arm <customer> <plan-id> --cr <CR> --approved --ack-yellow
PAAT_UPGRADE_EXECUTE=1 python -m panlab.upgrade step <customer> <plan-id> --confirm <device-name> --wait
python -m panlab.upgrade changeplan <customer> <plan-id>
```
