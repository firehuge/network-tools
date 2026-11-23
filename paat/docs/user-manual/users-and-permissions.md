# Users and permissions

Every GUI account has **checkboxes** for what it can do, and a **scope** for
which customers (and, if you want, which firewalls or device groups) it can do
it for. Use this to run an MSP/NOC model. Some examples:

- A NOC engineer who only runs OS upgrades at night for one customer.
- A change engineer who only does FCRs.
- A customer who upgrades their own firewalls after you have upgraded the
  shared Panorama.

Everything is checked on the server on every click. Customers and devices
outside a user's scope are hidden from lists and refused if someone types
the URL.


## The permissions

| Checkbox | Lets the user |
|---|---|
| `view` | See saved change sets, change plans and reports. Also opens **Trace a flow**: paste or upload an FCR, run it against the live read-only snapshot or backups, see the full plan, and export it. Cannot push. |
| `fcr` | Upload FCRs on the main prep page, decommission plans, backup-file uploads, deny-log lookups, and Trace a flow |
| `push` | Use the red **Push** area (prepare, apply, roll back) |
| `upgrade_plan` | OS upgrades: run read-only discovery and build dry-run plans |
| `upgrade_exec` | OS upgrades: arm a plan with an approved CR and run its steps |
| `upgrade_panorama` | Plan or run an upgrade of **Panorama itself**. Without it, Panorama shows read-only. |
| `backup_admin` | The **Backup destinations** page |
| `user_admin` | The **Users** page (this page) |
| `urlfilter_request` | **URL filter: request changes.** See the customer's URL Filtering profile and submit change requests ([URL filter self-service](url-filtering.md)) |
| `urlfilter_approve` | **URL filter: approve & push.** Review, approve (with a CR) or reject requests, push approved ones and roll them back |
| `approve` | **Approve FCR and push change plans.** Record a second-person approval (required when the customer has `two_person_approval`) |

Changing your own password needs no checkbox. A user with no permissions
can only log in and change their password.

## Scope: customers and devices

- **All customers** covers every customer, including ones added later.
- Or tick individual customers.
- Under each ticked customer you can limit the user to **specific devices**,
  one per line. Each line can be:
  - the profile target name (`fw-1`)
  - the hostname the device reports (`BRANCH-FW-01`)
  - the serial number
  - `dg:<device group>` for every firewall in that Panorama device group
    (`dg:DG-Branches`). Discovery reads group membership from Panorama
    (`show devicegroups`, read-only).

  Leave it blank for all devices of that customer.

What a device-scoped user sees in **OS upgrades**:

- Only their firewalls can be ticked. The page says how many other devices
  are hidden.
- The customer's Panorama is shown **read-only**, with its version, so they
  can see that Panorama was upgraded first. Panorama becomes selectable only
  with `upgrade_panorama` (and Panorama in scope, if devices are limited).
- Plans that include any device outside their scope do not appear in their
  list, and opening, arming or running them is refused.

### Example: Panorama first, then per-customer change windows

1. An admin (or someone with `upgrade_panorama`) upgrades the shared
   Panorama.
2. Each NOC user or customer user has `upgrade_plan` + `upgrade_exec`,
   scoped to their customer and `dg:<their device group>`.
3. In their own change window, each one runs discovery, plans their
   firewalls and runs them. The usual checks still apply: an approved CR,
   the yellow acknowledgement, a typed hostname per step, backups (copied
   off-box if configured), and the rule that a firewall can't go above its
   Panorama.

## Adding a user

1. **Users > + Add a user** (the add form is at the bottom when no user is
   being edited).
2. Fill in the user name and an initial password, or leave the password
   blank to generate one. A generated password is shown **once**.
3. Leave **Must choose a new password at first login** ticked. The user is
   sent to **Change password** before anything else.
4. Tick the permissions and the customers, and fill in the device lines if
   needed. Click **Save**.

## Editing, resetting, disabling, deleting

- **edit**: change checkboxes and scope. **Save** records the before and
  after in the audit table.
- **Reset a password**: set one or generate one. The user must change it at
  their next login.
- **Disable**: the user can't log in. An open session ends on their next
  click. **Enable** undoes it.
- **Delete**: removes the account (you are asked to confirm). The audit
  history stays.

### Guard rails (enforced on the server)

- You can't disable or delete yourself, or remove your own `user_admin`.
- The last enabled user with `user_admin` can't be disabled, deleted or
  demoted.
- You can only grant permissions and customers that you hold yourself. A
  user admin scoped to one customer can't grant **All customers** or
  another customer.
- You can't edit, reset, disable or delete a user who has access you don't
  have.
- Every attempt is written to `/etc/paat/user-audit.jsonl`, refused ones
  included, and shown under **User and permission audit**. Passwords and
  hashes are never written.

## Upgrading from the old roles

Before this change, users had one role. Each role became exactly the same
set of checkboxes, with **All customers**, so nobody gained or lost access:

| Old role | Permissions |
|---|---|
| viewer | `view` |
| prep | `view`, `fcr`, `upgrade_plan`, `upgrade_panorama` |
| engineer | prep + `push`, `upgrade_exec` |
| admin | everything, including `backup_admin`, `user_admin`, and `approve` |

On the PAAT server `/etc/paat/users.yaml` was backed up before the
migration (`users.yaml.bak-<date>`, mode 600). The **Matches layer** column shows a named layer (Viewer, Requester, Engineer, Approver, Admin / operator, Platform admin) when the checkboxes match a preset, an older role name (`prep`, `engineer`, `admin`) when they still match that bundle, or `custom` otherwise. The add and edit forms have an **Apply a layer preset** menu that ticks the boxes. It does not save until you click Save.
`paat users add --role ...` still works on the CLI and creates a user with
that role's set and **all customers**. Add `--customer NAME` (repeat for several) to
limit the new user to those customers: the role's permissions are then stored as
explicit checkboxes with that customer list, so the limit is enforced exactly like
one set on the Users page.

### Customer scope rules

- A user's customer list is always enforced, whether the user was made from a role,
  on the Users page, or with `--customer`.
- Ticking no customer means **no customer** (the account menu shows "No customers"), never "all".
- A hand-edited record that has permissions but no `customers:` list sees no customers
  (fail closed). Only an old role-only record (`role: admin`, no permissions list) means all customers.
- Fixed: creating a role user programmatically with a customer list used to drop
  the list, so that user could see every customer. Users made on the Users page were never affected.

## Troubleshooting

| You see | Meaning | Fix |
|---|---|---|
| `needs the 'upgrade_exec' permission` | That checkbox is not ticked for you | Ask a user admin |
| `customer X is not in your scope` | The customer is not ticked for you | Ask a user admin |
| `this plan includes a device outside your scope` | Someone else's plan covers more devices than yours | Build your own plan from discovery |
| `you cannot grant permissions you do not have` | Anti-escalation | Ask an admin with that permission |
| `... is the last enabled user admin` | Lock-out protection | Give another user `user_admin` first |
