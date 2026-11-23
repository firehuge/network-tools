# URL filter self-service

Each customer gets **one URL Filtering profile** (default name `URL-<customer>`) in its
device group (Panorama) or vsys (standalone firewall), plus two optional lists:

- an **allow list** (custom URL category `URL-<customer>-ALLOW`): these sites are always allowed,
- a **block list** (custom URL category `URL-<customer>-BLOCK`): these sites are always blocked.

A **requester** chooses an action per URL category and adds or removes sites. An **approver**
reviews the request against what is live and against the Palo Alto Networks recommendation,
approves it with a CR, and pushes it. Nothing on a device changes until an approver pushes.

Attaching the profile to security rules is **not** done by this page: administrators add it to
the customer's security profile group once (see [Attach the profile](#attach-the-profile-to-rules-administrators-once-per-customer)).
The page warns while no rule uses the profile.

## Who can do what

Two checkboxes on the [Users](users-and-permissions.md) page. Any user can be given either or both;
both honor the user's customer scope, and a device scope must include the URL filter target
(its profile target name or `dg:<device group>`).

| Checkbox | What it allows |
|---|---|
| **URL filter: request changes** (`urlfilter_request`) | Open **URL filter** in the left sidebar, see the customer's live profile, submit requests, follow their status |
| **URL filter: approve & push** (`urlfilter_approve`) | Review, approve (with an approved CR) or reject, re-review stale requests, push approved requests, roll back |

You **cannot approve your own request**; another approver has to (four eyes). A customer can turn
that off with `allow_self_approval: true` in its `url_filter` settings.

## For requesters: ask for a change


1. Click **URL filter** in the left sidebar (or the **URL filter self-service** tile on Home) and pick
   the customer. The card shows the profile, where it lives, and whether a rule uses it.
2. Click **Request a change**. The page reads the profile **live** from the device: every URL
   category the device knows, its action now (**Live now**) and the Palo Alto recommendation.


3. Change the **Requested** drop-down only where you want something different. The actions:
   - **allow**: allowed, not logged.
   - **alert**: allowed and logged (the usual choice for everything you do not block).
   - **continue**: a warning page; the user can click through.
   - **override**: a page that asks for the admin override password (only if the firewall has one set up).
   - **block**: a block page.

   Rows you change turn yellow. A red "differs from PA" note means your choice is not the Palo Alto
   recommendation; that is allowed, the approver just looks twice. Use the search box, the group
   filter (categories are grouped by risk: *Palo Alto recommends block*, *Consider blocking (your
   policy)*, then content groups), **only changed**, **Set shown rows to PA recommended** and
   **Reset to live**.
4. Optional: add sites to the **Always allow** or **Always block** list, one per line:
   `example.com`, `*.example.com` (all subdomains), `example.com/path`, or an IP address. Leave out
   `http://`, `https://` and ports; a wildcard over a whole top-level domain (`*.com`) is refused.
   Tick **remove** next to an existing entry to take it off.
5. Write a short note for the approver (why, and your ticket number), then **Submit request**.
6. The request page shows the status: **pending** → **approved** → **pushed**, or **rejected**
   with the approver's reason. Only real changes are stored: a category left as it is live is not part of the request.

If someone changed the profile while you had the form open, the submit is refused with a message;
reload the form and submit again.

## For approvers: review, approve, push


1. Open the request from **URL filter** (the list shows status, number of changes and how many
   differ from the Palo Alto recommendation).
2. Read **Category changes** (live at request → requested, with the recommendation),
   **Allow / block lists**, and the **Differs from the Palo Alto recommendation** box. Pay
   attention to "weaker than recommended" (for example unblocking `unknown`) and to allow-list
   additions: they bypass category blocking.
3. **Approve**: type the approved CR number (the customer's CR format) and an optional comment.
   Approving re-reads the live profile, builds the exact API operations and a CR change plan
   (summary, GUI steps, `set` CLI, XML API calls, commit and push, verification, backout). It
   writes nothing. Or **Reject** with a reason the requester will see.
4. **Push** (only where live push is allowed, see below): type the target name to confirm. The tool
   checks that nobody has uncommitted changes, re-reads the live profile, writes the custom
   categories and the profile, commits (description `panlab <CR> urlfilter <request>`), pushes the
   device group to its firewalls (Panorama), and reads the result back on Panorama **and** on the
   firewalls listed in `verify_targets`. The request page shows a PASS/FAIL line per check.


5. **Roll back** puts the profile and lists back exactly as they were when you approved (or removes
   them if this request created them), commits, pushes and verifies.

### Stale requests

If the live profile changed after the request was made (or after approval), **Approve** and **Push**
refuse and the request turns **stale**. Click **Re-review**: the tool recomputes the request against
what is live now and drops anything already in place. Then review and approve again.

### Dry-run vs live push

Same rule as the Push area: a standalone firewall may be pushed live; a Panorama only when the
customer has `allow_live_panorama_push: true` (today only one explicitly opted-in customer). Everywhere
else an approved request is **dry-run only**: there is no Push button and you implement the CR change
plan by hand (download it as markdown from the request page).

## Attach the profile to rules (administrators, once per customer)

The profile filters nothing until a security rule uses it. Usually you add it to the customer's
security profile group:

1. Panorama: **Objects > Device Group <customer DG> > Security Profile Groups**. Open the customer's
   group (or clone the one their rules use now) and set **URL Filtering** to `URL-<customer>`.
2. Make sure the customer's allow rules use that group (**Policies > Security > rule > Actions >
   Profile Setting**).
3. Commit and push the device group. The URL filter page now shows "In use by N security rule(s)".

The profile is created by the first approved and pushed request, so do this after that push. In the
Attach the generated URL Filtering profile to a security rule yourself.

## Setting up a customer (administrators)

Add a `url_filter` block to the customer profile (`customers/<name>/profile.yaml`):

```yaml
url_filter:
  target: pano-1               # a Panorama or firewall target of this customer
  device_group: DG-EXAMPLE   # Panorama only (vsys: vsys1 for a firewall)
  profile: URL-example         # optional, default URL-<customer>
  allow_category: URL-example-ALLOW   # optional
  block_category: URL-example-BLOCK   # optional
  verify_targets: [fw-1]  # firewalls read back after a Panorama push (optional)
  allow_self_approval: false  # optional
```

Customers without the block do not appear on the page. Requests are stored on the server under
the customer's data folder (`urlfilter/`, mode 600); every step is in the customer audit log
(`urlfilter_request`, `_approve`, `_reject`, `_rebase`, `_push`, `_rollback`).

## Where the recommendations come from

The **PA recommended** column follows Palo Alto Networks' public best practice for an Internet
gateway URL Filtering profile: **block** `command-and-control`, `copyright-infringement`,
`dynamic-dns`, `extremism`, `malware`, `phishing`, `proxy-avoidance-and-anonymizers`, `unknown`,
`newly-registered-domain`, `grayware` and `parked`, plus the newer `ransomware`; **alert** on every
other category for visibility. Categories Palo Alto suggests weighing against your own legal and
compliance policy (for example `hacking`, `adult`, `gambling`, `peer-to-peer`, `questionable`,
`weapons`) are grouped as *Consider blocking (your policy)* and stay **alert** in the recommendation.
`high-risk` is a risk rating, not a malicious category, and is not recommended for blocking.

- Palo Alto Networks, *URL Filtering Categories* (PAN-OS web interface help, Security Profiles > URL Filtering).
  https://docs.paloaltonetworks.com/ngfw/help/12-2/objects/objects-security-profiles-url-filtering/url-filtering-categories
- Palo Alto Networks, *Get Started with URL Filtering*. https://docs.paloaltonetworks.com/advanced-url-filtering/administration/configuring-url-filtering/get-started-with-url-filtering
- Palo Alto Networks, *URL Filtering Best Practices*. https://docs.paloaltonetworks.com/advanced-url-filtering/administration/configuring-url-filtering/url-filtering-best-practices
- Palo Alto Networks Knowledge Base, *What is the recommended action for high-risk category URLs?* https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000wkr2CAA
- LIVEcommunity, *URL Filtering Category Recommendations*. https://live.paloaltonetworks.com/t5/blogs/blogarticleprintpage/blog-id/CommunityBlog/article-id/1348

The category list itself is read live from each device (`show predefined pan-url-categories`), so
new PAN-DB categories appear without a code change (in an *Other* group until they get a description).

## Limits

- One profile per customer (plus the two lists). Per-rule or per-user-group profiles, credential
  submission settings, safe search, HTTP header logging and the other profile tabs are not managed
  here; settings you set by hand on those tabs are kept when a request is pushed.
- External dynamic lists and category-match custom categories are not managed.
- `override` only works if the firewall has URL admin override configured.
- The tool never attaches the profile to rules.
- Panorama pushes go to every member of the device group.

## Troubleshooting

| Message | Meaning | What to do |
|---|---|---|
| `has uncommitted changes from someone else` | Someone has a pending candidate on the device | Ask them to commit or revert, then push again |
| `the live profile changed ...` / status **stale** | Someone changed the profile since the request | Approver: **Re-review**, then approve again |
| `you cannot approve your own request` | Four-eyes rule | Ask another approver |
| `CR number ... does not match` | Wrong CR format for this customer | Use the approved CR |
| `live push is off for this customer` | Panorama without the explicit opt-in | Implement the change plan by hand |
| `job N still running after 900s` | Panorama was busy (another commit or a software job) | Check Panorama > Tasks; the job may still finish. Re-read the request page |
| Page says **Not attached** | No enabled rule uses the profile | Administrators: see Attach the profile |
