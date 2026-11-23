# Finding your way around (sidebar, top bar, Home, breadcrumbs)

Every page after login has the same layout: a dark **sidebar** on the left, a light **top bar**
across the page, and the page itself in the middle. You can always get back to where you started.


## In 30 seconds (for everyone)

1. **Left sidebar** = the tools you may use. Click one to open it. The page you are on is highlighted.
2. **Top bar, left** = where you are (*Home / Saved change sets / cs-…*). Click any earlier part to go back.
3. **Top bar, right** = search, **Help**, light/dark switch, and your name. Click your name for
   **Change password** and **Log out**.
4. If the top bar has a red **PUSH AREA** badge and a red strip under it, the buttons on that page can
   change a live firewall. Everywhere else is read-only for the firewalls.

## The sidebar

The sidebar groups tools by job. You only see the links your account may use (the permission
checkboxes in [Users and permissions](users-and-permissions.md)); a hidden link is not a fault.


| Group | Link | Needs | What it is for |
|---|---|---|---|
| (top) | **Home** | any login | Your dashboard: counts, your next job, quick actions, recent change sets |
| Change requests | **Upload FCRs** | FCR or Request | Upload firewall change request spreadsheets; the plan is built for you |
| Change requests | **Trace a flow** | View, FCR or Flow | Check one or more flows hop by hop against the live firewalls or backups |
| Change requests | **Change sets** | View | Every saved plan, with its status (Planned, Awaiting approval, Approved, Pushed…) |
| Change requests | **Decommission** | FCR | Find rules and objects that still use old hosts |
| Operations | **OS upgrades** | OS upgrade plan or run | Plan and run PAN-OS upgrades step by step |
| Operations | **URL filter** | URL filter request or approve | URL category and allow/block list requests |
| Operations | **App-ID advisor** | View or FCR | Turn a port rule into an App-ID rule from traffic logs |
| Operations | **Backup files** | FCR | Upload device backups to plan against |
| Administration | **Users** | User admin | People, roles (layers), customer scope, passwords |
| Administration | **Backup destinations** | Backup admin | Off-box copies of device backups (git, SFTP, S3) |
| (bottom) | **Help** | any login | This manual |

Pushing is not a sidebar link on purpose: open a change set and use its **Push area** button.

On a phone or a narrow window the sidebar hides. Tap the **three-line menu button** at the top left
to slide it in; tap outside it (or press Esc) to close it.


## The top bar

- **Breadcrumbs** (left): for example *Home / Saved change sets / cs-… / change plan*.
- **Search** (if you have `view`): change-set ids, RITM, SCTASK, CR numbers and rule names, only for
  customers in your scope.
- **Help**: opens this manual.
- **Moon button**: switches between the light and dark look. Your browser remembers the choice.
- **Your name and role** (for example *Approver*): click it to see the customers you can see
  (*All customers*, one customer, or "N customers"), **Change password**, **Help** and **Log out**.


## Home

Home is a dashboard built for your role (see [Layers, Home, and the change workflow](layers-and-home.md)):

- a box that says what your role usually does next (for example *Waiting for you* for an Approver);
- **counts** from the saved data in your scope: customers, saved change sets, *Awaiting approval*,
  *Approved, not pushed*, *Pushed*, and (when you have those tools) upgrade plans and open URL filter
  requests. Click a count to open the matching list. An Approver sees *Awaiting approval* first; an
  Operator sees *Approved, not pushed* first. A red *Needs attention* card appears only when a push
  or its verification failed;
- **Quick actions**: one card per tool you may use;
- **Recent change sets** with a coloured status.

## Change sets and their status

**Change sets** lists every saved plan, newest first. The chips above the table filter by status;
click a column heading to sort; long lists get a *Filter rows* box.


| Status | Colour | Meaning |
|---|---|---|
| Planned | grey | Built and saved. No approval recorded yet (approval is optional for this customer). |
| Awaiting approval | amber | This customer uses the two-person rule and nobody has approved yet. |
| Approved | blue | Approved with a CR number. Ready for an Operator to push. |
| Rejected | red | An approver sent it back. Read the note on the Change plan page. |
| Pushed | green | Applied, committed and verified by the tool. |
| Verify failed / Push failed / Rollback failed | red | Something went wrong after Apply. Open the change set and its push report. |
| Rolled back | grey | The push was undone with Rollback. |
| Plan only | grey | Built from an uploaded backup file. It can be read and copied, never pushed. |

## The four steps on every change set

The change set, its change plan and its push page share a stepper:
**1 Request → 2 Plan → 3 Approval → 4 Push**. A green tick means done, the blue step is where you
are, red means blocked, and *locked* means your role cannot use that step.


## Colours, buttons and messages

- Green, amber and red mean good, check, and stop, everywhere (badges, table rows, boxes).
- **Blue** buttons do the normal action. **White** buttons are secondary. **Red** buttons change
  something that is hard to undo (delete, prepare a push, arm or run an upgrade step).
- After you press a button it shows a small spinner and greys out until the page answers, so a double
  click cannot send the same thing twice.
- Short confirmations (for example *Password changed*) can also pop up in the lower-right corner and
  disappear after a few seconds.
- Required fields have a red star (*). A field you filled in wrong turns red.
- Every page has a **How this page works** box. Click it for one or two sentences and a link to the
  matching manual page.

