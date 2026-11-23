# External dynamic lists (EDLs)

An **external dynamic list** is a plain text file of IP addresses, domains or URLs, one per line. A firewall downloads
it on a schedule and uses it in policy: for example a deny rule whose destination is "everything on the Blocked IPs
list". PAAT keeps these lists for you. You add or remove an entry here, and every firewall that points at the list picks
the change up on its next refresh. **Nobody logs in to a firewall to block an address.**

This page has two parts:

- **Part A, for everyone:** customers, SOC analysts, ISSOs and admins. What to click, what you will see, and what the
  tool refuses to do.
- **Part B, technical:** how lists are published (PAAT-hosted or S3), the firewall object, certificates, limits,
  storage, the API and command line.

Then [Troubleshooting](#troubleshooting) and the [FAQ](#faq).

---

## Part A: using the lists

### A.1 Who can do what

Each person gets the permission checkboxes they need (see [Users and permissions](users-and-permissions.md)). Four are
for EDLs. The **layer presets** on the Users page tick the right boxes for you.

| Preset (layer) | See lists | Add / remove entries | Approve other people's changes | List settings, S3, firewall objects, *Refresh now* |
|---|---|---|---|---|
| **EDL editor (customer)** | yes, own customer only | yes | no | no |
| **SOC analyst** | yes | yes | no | no |
| **ISSO / security reviewer** | yes | no | **yes** | no |
| **EDL admin** | yes | yes | yes | **yes** |
| Platform admin | everything | | | |

The permissions are `edl_view`, `edl_edit`, `edl_approve` and `edl_admin`. A user only sees the customers in their scope:
a customer's editor can never see or change another customer's lists, and the list's download address only serves that
one list.

Nobody can approve their own change. Pushing a firewall object (Part B) also needs the normal **Push** permission.

### A.2 Quick start: block an address (customer or SOC)


1. In the sidebar open **Operations > External dynamic lists**.
2. Click the list, for example **Blocked IPs**.
3. In **Add entries**, type one entry per line. Text after a space is kept as a comment:
   `203.0.113.7 phishing C2`.
4. Fill in **Reason** (required: it goes in the history) and, if you have one, a **Ticket**.
5. Optional: **Expires**, for example `30d`, `12h` or `2026-12-31`. The entry drops off the list by itself then.
6. Click **Add**.

What happens next:

- **A normal entry** is added straight away. The page says *Added. Version N is live.* Firewalls pick it up on their next
  refresh (5 minutes when the firewall object uses the five-minute setting).
- **A risky entry** (see A.4), or **any entry on a list with two-person approval**, waits for an ISSO. The page says
  *Waiting for approval*, and the list shows it under **Waiting for a second person**. Firewalls do not see it yet.
- **A refused entry** (see A.4) is not added at all. The preview says why.
- **A typo** (not a valid IP, domain or URL) is shown as an *invalid line* and skipped.

If anything in your paste is refused, invalid or already covered by a broader entry, you get a **preview** first and
nothing changes until you click **Apply now** (or **Stage for approval** when it needs an ISSO).


### A.3 Remove an entry

Tick the entries in the **Entries** table, type a reason under the table and click **Remove selected**. On a list with
two-person approval, removals wait for an ISSO too.

When you remove the last entry, PAAT serves a harmless placeholder (`192.0.2.1` for IP lists, `paat-empty-list.invalid`
for domain and URL lists) instead of an empty file. This matters: a firewall that downloads an *empty* list keeps using
the last list it had, so the entry you removed would stay blocked. The placeholder addresses are reserved for
documentation and never match real traffic.

### A.4 What needs a second person, and what is refused

PAAT checks every entry before it is saved.

| Entry | Result | Why |
|---|---|---|
| `0.0.0.0/0`, `::/0`, `*`, a bare top-level domain like `com` | **Refused** | Blocks everything. |
| A network shorter than `/8` (IPv4) or `/16` (IPv6) | **Refused** | Far too broad. The admin can change the limit. |
| Loopback (`127.0.0.1`, `::1`) | **Refused** | Never meaningful on a firewall. |
| Anything that covers an address or domain on the **never-block** list (DNS servers, management IPs, update servers) | **Refused** | Would break the network. |
| `*.com`, `*.net`, `*.co.uk` and other public suffixes | **Refused** | Matches a large part of the internet. |
| A network shorter than `/16` (IPv4) or `/32` (IPv6) | **Needs approval** | Very broad. |
| Private ranges: RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT `100.64/10`, IPv6 ULA `fc00::/7` | **Needs approval** | Usually your own hosts. |
| Your own public ranges and domains (the admin lists them as *protected*) | **Needs approval** | Blocking yourself by mistake is the most common EDL outage. |
| A wildcard over a smaller top-level domain, like `*.click` | **Needs approval** | Broad. |
| Link-local or multicast | **Needs approval** | Rarely intended. |

The admin edits these settings under **External dynamic lists > Safety settings**. The approver sees the reason for each
flagged entry before approving, and PAAT checks again at approval time, so an entry that has become refused in the
meantime cannot be approved.

### A.5 Entry formats

| List type | Good entries | Notes |
|---|---|---|
| **IP** | `203.0.113.7`, `198.51.100.0/24`, `192.0.2.10-192.0.2.20`, `2001:db8::/48` | Host bits are cleared (`203.0.113.9/24` becomes `203.0.113.0/24`). |
| **Domain** | `bad.example`, `*.bad.example`, `^exact.example` | `*.` matches every subdomain; `^` means exactly that name. Case is ignored; a trailing dot or `https://` is removed. No paths or ports. |
| **URL** | `bad.example/login`, `*.bad.example/*`, `bad.example/path?x=1` | No `http://` (PAAT removes it). `*` and `^` must be a whole part between dots or slashes. |

These follow the Palo Alto *Formatting Guidelines for an External Dynamic List* (PAN-OS 11.1). Duplicates are dropped,
and the preview tells you when a new entry is already covered by a broader one (for example `203.0.113.70` inside
`203.0.113.64/27`); both are kept.

### A.6 Approve or reject (ISSO)

1. **Home** shows *EDL changes waiting*. Or open the list: **Waiting for a second person**.
2. Click the change. You see who asked, the reason and ticket, every add and remove, and **why it waits**.
3. Click **Approve** (with an optional comment) or **Reject** (a comment is required; the requester sees it).


Approved changes go live straight away and are published. The requester can **Withdraw** their own pending change.

### A.7 Bulk import and export

**Bulk import** (on the list page) takes a paste or a file:

- `.txt`: one entry per line, comments after a space, `#` lines ignored.
- `.csv`: columns `value, comment, expires_at, ticket` (a header row is optional).

Choose **Add these** (keep what is there) or **Replace the list** (anything not in the file is removed). You always get a
preview with counts: adds, removes, already in the list, duplicates, invalid, refused, needs approval. Nothing changes
until you click **Apply now** (or **Stage for approval**).

**Download .txt** gives exactly what firewalls see. **Download .csv** includes who added each entry, when, and the
ticket.

### A.8 History, revert and audit

- **History** lists every version: who, when, why, what was added and removed, and who approved it.
- **Revert to vN** makes the list equal to that version again. It is a new change: it gets a preview, needs a
  reason, and goes through approval if the list or an entry needs it. Nothing is deleted from history.
- **Audit log** records every action on the list, including publishes, settings changes, firewall refreshes and failed
  attempts.

---

## Part B: technical

### B.1 How a list reaches the firewalls

```
 people ──edit──▶  PAAT  ──publish──▶  PAAT-hosted URL   ◀──fetch every 5 min──  firewall EDL object
                    │                  and/or S3 object  ◀──────────────────────  (pushed via Panorama)
                    └─ versions, approvals, audit
```

Each list can be published in one or both ways:

1. **PAAT-hosted** (on by default). PAAT serves the list at
   `http(s)://<paat-address>/edl/<token>.txt`. The token is a long random string; anyone who knows the URL can read the
   list, so treat it like a password. Optional protections, in **List settings**:
   - **Allowed source IPs**: only these addresses or subnets may fetch it (others get 403). Use the firewalls'
     management or service-route addresses.
   - **Basic auth**: a username and password. PAN-OS only sends them to an `https://` source that has a certificate
     profile (see B.3).
   - **Issue a new URL**: the old one stops working at once. Update the firewall objects first.

   The feed is `text/plain`, has an ETag (unchanged lists return 304) and records the last 20 fetches (time, address,
   result), which the list page shows under *Last fetches*.

2. **S3 or S3-compatible (MinIO)**. After every change PAAT writes the list to a bucket. Set the bucket, key, region and,
   for MinIO, the endpoint URL and path-style addressing in **List settings**. See B.2.

Set the address firewalls use to reach PAAT under **Safety settings > Public base URL** (for example
`https://paat.example.net`), so the URL PAAT shows and generates is the right one.

### B.2 S3 publishing

**Credentials never go in the GUI.** Put them on the PAAT server in `/etc/paat/edl/<customer>.env` (owner `paat`, mode
600):

```
# per list (list id upper-cased, dashes to underscores)
PAAT_EDL_S3_BLOCKED_IPS_ACCESS_KEY=...
PAAT_EDL_S3_BLOCKED_IPS_SECRET_KEY=...
# or one pair for every list of this customer
PAAT_EDL_S3_ACCESS_KEY=...
PAAT_EDL_S3_SECRET_KEY=...
```

With no keys, PAAT uses the server's default AWS credentials (environment or instance role). The settings page only says
whether keys are set, never shows them, and error messages have them removed.

Minimum IAM permissions on the object (and its temp keys):

```json
{"Effect": "Allow",
 "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
 "Resource": "arn:aws:s3:::BUCKET/edl/*"}
```

**How a publish works.** PAAT writes the new list to a temporary key, reads it back and checks its SHA-256, copies it
over the real key (so a firewall never reads a half-written file), deletes the temp key, and (when *Verify* is on) reads
the real key back and checks the SHA-256 again. The list page shows the last publish: time, who, version, SHA-256, and
the result.

**Edits made outside PAAT.** Before writing, PAAT compares the live object with what it last published. If someone
changed the object in the S3 console or with a script, PAAT **does not overwrite it**: the publish is marked
*conflict* and the list page says so. Click **Check S3 now** to see the differences, then either:

- **Import**: *merge* (add what only S3 has) or *replace* (make PAAT equal S3). This is a normal change with a preview and
  a reason; after it, publishing works again.
- **Overwrite S3** (EDL admin only): PAAT's version wins and the outside edit is lost, unless bucket versioning is on.

**The firewall URL for S3** is shown on the list page:
`https://<bucket>.s3.<region>.amazonaws.com/<key>` on AWS, or `<endpoint>/<bucket>/<key>` for MinIO. The firewall must be
able to read it: a bucket policy that allows `s3:GetObject` from the firewalls' public addresses, or a pre-signed or
proxy URL. A private bucket with no such policy returns 403 to the firewall.

### B.3 TLS, certificate profile and basic auth

- **HTTP** works (fine for a test) but anyone on the path can read or change the list. Use **HTTPS** in production.
- For an `https://` source, give the firewall EDL object a **certificate profile** that contains the root and intermediate
  CA of the PAAT (or S3) server certificate. Without it the firewall does not authenticate the server.
- **Client authentication (basic auth)** only appears in PAN-OS when the source is `https://` **and** a certificate
  profile is set. PAAT's object generator refuses a username otherwise. The password is never generated by PAAT: type
  it on Panorama.
- Use the same certificate profile for lists from the same source URL; different profiles make the firewall count them
  as separate lists.
- If authentication fails, PAN-OS logs a critical system log (`eventid eq tls-edl-auth-failure` or
  `eventid eq edl-cli-auth-failure`). Check what the firewall then enforces in *Firewalls using this list*.

Sources: PAN-OS 11.1 Admin Guide, *Configure the Firewall to Access an External Dynamic List* and *Find External Dynamic
Lists That Failed Authentication*; Palo Alto KB *The Client Authentication Field Does Not Appear While Creating an
External Dynamic List*.

### B.4 Which interface the firewall uses

By default a firewall fetches EDLs through the **Palo Alto Networks Services** service route (normally the management
interface). To use another interface, set **Device > Setup > Services > Service Route Configuration > Customize >
External Dynamic Lists**. The PAAT server (or S3) must be reachable from that interface, and an **Allowed source IPs**
list must contain that interface's address.

### B.5 The firewall object (Panorama only)

Open the list and click **Make the firewall object** (EDL admin):

1. Enter the object name (for example `EDL-BLOCKED-IPS`), the device group (from the customer profile's `edl:` block, or
   its `url_filter:` block), the source URL (pre-filled), refresh interval (five-minute is the fastest PAN-OS allows),
   and optional certificate profile and username.
2. **Preview** shows the CLI `set` commands and the XML API element, to copy into a CR or apply by hand.
3. **Request this object** files a request. A second person with *EDL approve* (or *Approve*) approves it **with a CR
   number**; the requester cannot.
4. An operator with **Push** opens the request, types the target name and clicks **Push**. PAAT takes a full Panorama
   running-config backup first (refusing to push if it cannot), writes the object to the device group, commits Panorama,
   pushes the device group, and reads the object back.
5. **Rollback** (Push permission) restores what was there before, with its own backup first.

The object is created **on Panorama in the device group, never locally on a firewall**. A customer without
`allow_live_panorama_push` gets the commands only.

After that, reference the object in policy as usual (for example as the destination of a deny rule, in a URL Filtering
profile, or in an Anti-Spyware profile's DNS policy for domain lists).

### B.6 Which firewalls use a list, and Refresh now

**Which firewalls use it (live)** reads Panorama's running config with the read-only key and finds every EDL object whose
source URL is this list's PAAT URL or S3 object, in shared, any device group, or a firewall vsys. For each one it shows
the device group's firewalls, the refresh interval, and what uses it (security rules, URL Filtering profiles,
Anti-Spyware DNS lists).

For each firewall it runs `request system external-list show type <ip|domain|url> name <object>` and shows the valid and
invalid entry counts, last update and next update. **Refresh now** (EDL admin only) runs
`request system external-list refresh` on that firewall so you do not wait for the schedule. Every refresh is in the
audit log. (`request` commands need an admin API key; PAAT tries the read-only key first for the show command.)

### B.7 Limits

PAN-OS 11.1 (Admin Guide, *External Dynamic List*):

- Up to **30 custom EDLs with unique sources** per firewall (not counted on Panorama).
- **IP entries:** 150,000 total on PA-3200, PA-5200 and PA-7000 Series; 50,000 on every other model.
- **Domain and URL entries:** by model, from 50,000 (PA-220, PA-410, VM-50, VM-100) up to 4,000,000 domains and 250,000
  URLs (PA-5200, PA-5400, PA-7000 with high-end NPCs).
- Entries only count when the list is used in policy. Over the limit, the firewall **skips the extra entries** and logs
  it. *Expand domain* doubles the entries a domain list uses.
- The shortest refresh interval is five minutes.

Pick the model family under **Safety settings > Firewall model**. The list index shows totals per type against that
limit and warns at 80% and 100%. PAAT also warns above 30 lists for one customer.

### B.8 Storage and audit

Everything is under the customer's data directory, `PAAT_DATA_DIR/<customer>/edl/`, never in git:

| Path | What |
|---|---|
| `<list>/meta.json` | Name, type, settings, hosted token, basic-auth hash (never the password), last publish. |
| `<list>/entries.json` | Current entries with comment, ticket, who added them, expiry. |
| `<list>/versions/NNNNNN.json` | Every version, full content, for diff and revert. |
| `<list>/changes/chg-*.json` | Pending, approved, rejected and withdrawn changes. |
| `<list>/audit.jsonl` | Audit log (append only). |
| `<list>/fetches.json` | The last 20 hosted-feed fetches. |
| `_settings.json` | The customer's safety settings. |
| `_objects/obj-*.json` | Firewall object requests and their results. |
| `_deleted/` | Deleted lists, kept for the record. |

Files are mode 600 and writes are locked, so two people saving at once cannot lose an edit.

### B.9 Expiry timer

Expired entries are left out of the feed at once. To also drop them from the list as a new version (and republish to
S3), run `python -m panlab.edl sweep`. A sample systemd timer (`deploy/paat-edl-sweep.timer`) runs it every 15 minutes. `python -m panlab.edl status` prints one line per list.

### B.10 Customer profile

Optional `edl:` block in the customer profile, for the firewall object target:

```yaml
edl:
  target: pano            # a Panorama target of this profile (or a firewall)
  device_group: DG-EDGE   # where objects go (or "shared")
```

Without it PAAT uses the `url_filter:` block, then the first Panorama.

---

## Troubleshooting

| What you see | Likely cause | What to do |
|---|---|---|
| *needs the 'edl_edit' permission* | Your account can only view, or approve. | Ask an admin for the right preset (A.1). |
| *customer X is not in your scope* | The list belongs to another customer. | Ask an admin to add the customer to your scope. |
| Entry shown as **Refused** | It is too broad, or covers a never-block address. | Use a narrower entry. Ask the EDL admin if the safety settings are wrong. |
| Entry **waits for approval** | Private or protected range, very broad, or the list needs two people. | Ask an ISSO to review it. |
| S3 publish says **conflict** | Someone edited the object outside PAAT. | **Check S3 now**, then import or (admin) overwrite. |
| S3 publish says **error ... AccessDenied** | Keys missing or the IAM policy is too narrow. | Check `/etc/paat/edl/<customer>.env` and B.2. |
| Firewall still blocks after you removed an entry | It has not refreshed yet. | Wait for the interval, or **Refresh now** (EDL admin). |
| Firewall shows **0 valid entries** or an old *last update* | It cannot reach the URL (route, allowlist, TLS). | Check *Last fetches* on the list page; check B.3 and B.4; on the firewall run `request system external-list show`. |
| Feed returns **403** | The fetching address is not in **Allowed source IPs**. | Add the firewall's service-route address. |
| Feed returns **401** | Basic auth is on and the firewall sends no or wrong credentials. | PAN-OS needs `https://` plus a certificate profile to send them (B.3). |
| Object push refused: *backup failed* | PAAT could not export Panorama's config. | Check the Panorama credentials; nothing was changed. |
| Object push refused: *uncommitted changes* | Someone else has pending changes on Panorama. | Commit or revert them first. |

## FAQ

**How long until firewalls pick up my change?**
For a PAAT-hosted list: the change is live in PAAT at once, and each firewall fetches on its schedule, so up to 5 minutes
with the five-minute setting (up to an hour with hourly). An EDL admin can click **Refresh now** to make one firewall fetch
straight away. For S3, add the few seconds the publish takes.

**Do I need to commit or push on the firewall?**
No. The firewall reads the new list contents without a commit. Only creating the EDL object (once) needs a Panorama push.

**Can I break the network with this?**
PAAT refuses entries that block everything or cover never-block addresses, and sends private, protected and very broad
entries to a second person. Still, a wrong public IP is blocked within minutes, so check the preview and use expiry for
temporary blocks.

**I removed the last entry. Why is there still one line in the file?**
That is the placeholder (A.3). An empty file would make the firewall keep the old list.

**Can I edit the file in S3 directly?**
You can, but PAAT will flag it as *changed outside* and not overwrite it until someone imports it or an admin overwrites
it. Editing in PAAT keeps the history, approvals and audit.

**Where is the password for basic auth?**
PAAT stores only a hash. Type the password into the firewall object on Panorama.

**Can a customer see another customer's lists?**
No. Lists, history, feeds and objects are per customer, and every page checks the customer scope.

**What happens if PAAT is down?**
Firewalls keep enforcing the last list they downloaded. With S3 publishing, firewalls that read from S3 are not affected
at all.

**Is real data in git?**
No. Lists live on the server under the data directory. The repository, tests and screenshots use documentation
addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example` domains only.

## Related pages

- [Users and permissions](users-and-permissions.md)
- [Layers, Home, and the change workflow](layers-and-home.md)
- [Plan-only vs live push](plan-only-and-live-push.md)
