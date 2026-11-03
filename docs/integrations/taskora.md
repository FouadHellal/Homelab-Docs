# Taskora integration

atlas ↔ [Taskora](https://github.com/FouadHellal/Taskora) (PSA / service desk), 0.10.0 ↔ 0.3.0.
Design: [ADR-042](../DECISIONS.md). API contract (owned by Taskora):
`docs/integrations/atlas.md` in the Taskora repository.

## What it does

| You see | Where | How |
| --- | --- | --- |
| A ticket for each incident that lasts 5 minutes | Taskora | atlas sends the incident's full state; one ticket per incident, whatever happens |
| Internal notes when the incident changes (new evidence, severity) | Taskora ticket | only meaningful changes; heartbeats add nothing |
| The ticket resolved when atlas sees the recovery | Taskora | Taskora's *recovery policy* (resolve or note) |
| "Still failing" and a reopen when someone closes the ticket too early | both | atlas tells Taskora once; only atlas declares recovery |
| *Acknowledged by Taskora: Sam* when a technician takes the ticket | atlas Incidents | atlas reads Taskora's ticket feed every minute |
| Ticket number, status and assignee next to each incident | atlas Incidents | link opens the ticket in Taskora |
| atlas's machines and network devices in the CMDB | Taskora | preview, then apply (once, or after each scan) |

## Setup

1. **Taskora** (0.3.0+): *Integrations → atlas*: choose the company, keep CMDB on *Link to
   existing CIs* for now, tick *Accept incidents and inventory from atlas*, Save. *Tokens → New
   token*, scopes `atlas.incidents` and `atlas.cmdb`, copy the `tki_…` value (shown once).
2. **atlas**: *Integrations → Taskora service desk*: the address you open Taskora with
   (`https://taskora.lan`), an instance name (`atlas` is fine; it prefixes incident keys), the
   token. Leave both options unticked. Save.
3. *Test connection*: it says whether the integration is enabled and a company chosen.
   *Send a test incident*: Taskora accepts it and creates no ticket.
4. *Preview CMDB sync*: the table shows, per machine, `link` (an existing CI with the same MAC
   or serial), `create`, `propose` (same name only), `conflict` or `unmatched`. Nothing is
   written. Decide conflicts and proposals in Taskora (*CMDB reconciliation*).
5. *Apply CMDB sync*. If you want atlas to add devices nothing else manages, switch Taskora's
   CMDB mode to *Link, and create unmanaged infrastructure* and apply again. Tick *Apply the CMDB
   sync after each scan* to keep it current.
6. Tick *Create and update tickets* and Save. Open incidents older than 5 minutes become
   tickets within a minute.

For a self-signed Taskora put its CA (PEM) in the config dir and enter its file name in *CA
file*. Plain `http://` is allowed only to a private LAN IP with the box ticked.

## Operations

- **Deliveries** (Integrations page): *delivered* with the revision, *waiting*, or the error.
  Errors: `retry` (Taskora down or rate limited: automatic, backing off up to 1 h),
  `config` (token revoked, scope missing, integration disabled, no company: fix it, atlas
  retries every 30 min or press *Retry failed deliveries*), `permanent` (Taskora refused this
  payload: held until the incident changes or you retry).
- **Taskora restored from a backup?** Press *Re-send all*: Taskora ignores what it already has
  and re-creates what it lost, without duplicates.
- **Revoking the token** in Taskora stops everything immediately; atlas keeps the outbox and
  resumes when you save a new token.
- **Turning it off**: untick both options (links and history are kept) or *Remove*.

## What crosses the wire

To Taskora: incident title, kind, severity, state, timestamps, evidence lines, recent changes
on the machine, a link to atlas's Incidents page, and the affected machine (name, kind, IPs,
MACs, Proxmox node/VMID, network/VLAN/uplink); for the CMDB the same per machine plus OS and
recognised apps. All of it is already redacted in atlas's database and redacted again on the
way out. No secrets, no raw command output, no client devices.

From Taskora: ticket number, status, priority, assignee and technician events on atlas's own
tickets. atlas treats it as untrusted (validated, capped, rendered escaped).
