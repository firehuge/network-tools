# $heading

**RITM:** $ritm

**SCTask:** $sctask

- Customer: $customer
- Tickets: $tickets
- Change set created: $created (America/Chicago)
- Scope: $scope
- Summary: $summary

$config_source

## How to use this plan

Do the steps in order. Copy names and values exactly (they are in `code` style). If a step does not match what you see on the firewall or Panorama, stop and ask; do not improvise. Read the callouts first: they flag routing gaps, app/port advice, and existing objects to reuse.

## Callouts and advice (read before you start)

$callouts

## Evidence from traffic logs (read-only lookup)

$evidence

## Open items before this can be scheduled

$open_items

## Implementation Plan

$gui_steps

## Commit

$commit_section

## Impact Analysis Statement

$impact_analysis

## Backout Plan

$backout_plan

## Validation Plan

$validation_plan

## Communications Plan

$communications_plan

## Implementation (CLI)

Enter `configure` first, paste the block, then follow the Commit section above.

```
$cli
```

## Verification

$verify

## Rollback

Run in `configure`, then commit (and push for Panorama). Rules are removed before the objects they use.

$rollback_notes

```
$rollback
```

Commit and push the rollback the same way:

$rollback_push
