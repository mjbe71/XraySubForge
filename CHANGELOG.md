# Changelog

## 0.6.0

Breaking: exits no longer come from the accounts file.

- Removed: the older `warp` block type, the chain mode `exit_first`, the `exit` key of classic chains and the `account_exit` hop. A chain block with an *own outbound* hop replaces them. In the admin panel, *Convert to a Chain block* turns an old WARP block into a chain block and copies the exits it finds in the accounts file into the hop. Saved configs that still use the removed options are reported as problems.
- The own-outbound hop can hold one outbound per flag: `{"<flag>": outbound, ..., "default": outbound}`.
- Removed: `output.remark_rewrite`. Name configs with the *Name* setting of a block.
- New: a global WARP endpoint pool (`accounts.endpoints`) with a form in Settings. Order: the hop's own `endpoints`, the pool, the account's `masque.endpoints`.
- New: a per-rule position (`end` or `early`) for the routing rules of balancer blocks.
- Settings redesigned: *Input* (what is read from the panel) and *Output* (the addresses users get: JSON always, raw links and Clash switched on one by one); the old *Inbounds & routing* card is split into *Inbounds & sniffing* and *Routing*; every routing option has a short explanation; the prune fields show only when prune is on.
- Clearer wording for where the configs come from and what the raw-link address gives users.

## 0.5.0

- Chain blocks: a config goes through up to four hops (WARP personal or shared, another config, an imported outbound); plain outbound tags (`proxy01`, ...).
- Routing rules for list, WARP and chain blocks, with a per-rule position (`end` or `early`); added rules go in front of a trailing catch-all rule; empty fields are dropped.
- DNS: forms (servers, hosts, `tag`, edit / import JSON), `dedicated_dns` with several servers, `direct_dns` adds its servers.
- `accounts.prune` and `prune-accounts [--dry-run]`: remove the WARP accounts of users the panel no longer has (off by default).
- Block settings: personal or shared WARP account, Xray values to pick from, duplicate a block, scrolling while dragging.
- The balancer's *Catch-all rules* are now *Routing rules*.

## 0.4.0-beta

Balancer strategy settings, member cost and placement, WARP forms, new README and banner.
