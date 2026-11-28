# Notes from Palo Alto Expedition

Expedition was Palo Alto Networks' migration tool. It reached end of life with no support after
**31 December 2024**. It was never open source (the public `expedition-repo` on GitHub only hosts
package repository files), so nothing was copied from it. These notes cover the workflow and
lessons it documented, which shaped this tool.

## How Expedition did a PAN-OS to PAN-OS move

1. Import the old firewall's config.
2. **Remap interface names**: renaming a parent interface also renames its subinterfaces and every
   reference to them across the config.
3. Import the new firewall's base config (to keep its device-specific settings), merge, and export XML.
4. Load on the new firewall, validate, commit.

## Lessons we kept

- **Every reference follows an interface rename.** This tool walks the whole XML tree and renames any
  leaf or entry that names an interface (exact match, including subinterface suffixes), plus checks
  known paths. Each change is in the change log with its XPath.
- **Certificates and secrets don't move cleanly.** Expedition users were told to load the full
  config or device state because certificates were not migrated. Private keys and other secrets are
  encrypted with the master key; this tool lists them so you can set the same master key or re-enter them.
- **Fix management, HA and dataplane ports before commit.** The tool lets you set hostname and
  management IP, maps HA links onto dedicated or dataplane ports, and flags HA ports the target lacks.
- **Collapsing many physical ports into a trunk** was a common need. This tool does not do it yet
  (see KNOWN_GAPS.md).

## Sources

- Expedition end-of-life notice and user guide (versions 1.1 and 1.2), Palo Alto Networks.
- LIVEcommunity discussions on PAN-OS to PAN-OS migrations with Expedition.
