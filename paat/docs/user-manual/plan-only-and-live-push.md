# Plan-only vs live push (tool → Panorama → firewall)

There are three ways a finished change plan can land on a device. The
default is the safest: **do not push from the tool**. Live Panorama
push is opt-in, per customer, and today only the test environment
`example` has it on.

## The three paths

### 1. Change plan only (always available)

Generate the plan, paste it into the CR, and stop. An engineer applies
the GUI steps or the CLI during a change window, on their own.

This is the right path for any customer that is not explicitly opted
in, and it is always available for `example` too.

### 2. Plan-only apply of the plan's CLI (engineer, by hand or script)

Use the **CLI** and **Rollback** sections of the change plan:

1. Apply the `set` commands (or the equivalent XML API operations) to
   **Panorama**, not directly to the firewall, when the customer is
   Panorama-managed.
2. Commit on Panorama (the commit description is the CR number).
3. Push only to the intended device: `commit-all` of the device group
   and, if the plan changed templates, the template stack, **limited
   to that serial**.
4. Verify on the firewall with the plan's **Verification** commands
   (and, for a managed firewall, `show config pushed-shared-policy`
   and `show config pushed-template`, not only the local running
   config).
5. If you need to back out, use the plan's **Rollback** CLI, then
   commit and push the same way, and verify the objects and rules are
   gone.

Do not leave a candidate hanging on Panorama. If a commit or push
fails because a device is rebooting or upgrading, wait and retry.

## Step by step (GUI live push, `example`)

1. Finish an FCR or decommission plan and read it. If anything is
   red-flagged or needs a human, stop and fix the plan first.
2. Open the **Push** area. You need the **push** permission, and the target must be in your scope. The bar is
   red on purpose.
3. You should see **Panorama: live apply opted in** on `example`, or
   **Panorama: dry run only** on other customers.
4. Enter the approved **CR** number. The button on a live Panorama
   customer reads **Apply + commit to Panorama, then push to
   firewalls**. Confirm the target.
5. Wait for the push report: operations applied, Panorama commit,
   device-group and/or template-stack `commit-all`, verification.
6. To back out, use the session **Rollback** in the same area (CR and
   confirmation still required). Rollback commits to Panorama and
   pushes to the same serials, then re-verifies.

The CLI equivalent:

```text
paat push --customer example --changeset <file.json> --apply --commit --cr CHG...
paat rollback --customer example --session <id> --confirm-target <target>
```

A dry-run (no `--apply`) only prints what would be sent.

## What you should see

- Dry-run: set commands and a commit-and-push *plan*, with a clear
  note that they were **not** executed (except on an opted-in customer
  after you actually apply).
- Live `example`: a job on Panorama, then a `commit-all` limited to the
  firewall, then a report. The firewall's local running-config xpath
  may still look empty; check **pushed-shared-policy** and
  **pushed-template**.
- Rollback: the new rules come out first, then unused objects the
  change created, then another commit and push.

## Safety checks already in the tool

- The **push** permission, the red bar, and an approved CR are required to apply.
- If the customer has `two_person_approval` on, a different person with the `approve` permission must record an approval before Prepare or Apply. The person who built the change cannot be that approver. The flag is off by default.
- `--apply` and `--commit` go together; the tool will not leave a
  half-written candidate as a supported path.
- `commit-all` is limited to the target serials in the plan, not
  "all devices".
- Suggested VR routes are never auto-pushed.
- Backup-file plans cannot be pushed.
- Policy-match verification is skipped on Panorama itself (it is not
  a forwarding device); verification runs against the firewall
  where it applies.
- If the flag is off, apply and rollback refuse even if someone
  tampered with a session file.

## Troubleshooting

| What you see | What to try |
| --- | --- |
| "Panorama: dry run only" and no real push | The customer is not opted in. Use the plan's CLI, or confirm `allow_live_panorama_push` is on and that `/etc/paat/customers/<name>.yaml` is not turning it off. |
| Push refused for a backup-built change set | Recreate the plan from a live export. |
| Commit-all fails, Panorama commit succeeded | The candidate is already committed. Read the job details on Panorama (`CommitAll`). Fix the validation error, then push again. Do not keep editing on the firewall locally. |
| "Zone of type unknown" on the firewall | The policy reached the device before the zones in the template stack did. Push the template stack first, confirm zones in `pushed-template`, then push the device group. |
| Verification says rules are missing | Look at `show config pushed-shared-policy` on a managed firewall. Local `running` xpaths often do not show Panorama-pushed rules. |
| Device is upgrading or rebooting | Wait, then retry the same commit or push. Do not invent a new design in the middle of an upgrade. |
| Rollback kept an object | Something else still references it. That is intentional. The report lists kept objects. |



## Which device is this? Hostname and serial

The push pages lead with what the device itself reports (`show system info`):
**`HOSTNAME · SN serial`**, with the profile target name in small grey text
(or `[brackets]` in the dropdown, reports and audit log). Page headings read
**Customer: <name>**.

- The **Target** list shows what each device last reported, or
  `fw-1 · hostname unknown · SN unknown` (profile name first) if it has not
  been read yet.
- **Prepare** reads the hostname and serial again (read-only), shows them on
  the session page, writes them to the audit log (`device-identity (prepare)`)
  and into the push report ("Device (as it reported itself)").
- **Apply** and **Rollback** ask you to type the **hostname the device
  reports** (the serial when the hostname is unknown or not unique). They read
  the identity again and refuse, writing nothing, if a different serial
  answers.
- If the hostname cannot be read, the session page shows a yellow
  "Could not read the hostname" box and falls back to the target name. Check
  the device itself before you apply.
- The CR change plan lists every profile device with the hostname and serial
  it last reported, near the top.
- The audit log has a **Device (hostname, serial)** column.

