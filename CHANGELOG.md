# Changelog

## 0.5.0

- Chain blocks: a config goes through up to four hops (WARP personal or shared, another config, an imported outbound); plain outbound tags (`proxy01`, ...).
- Routing rules for list, WARP and chain blocks, with a per-rule position (`end` or `early`); added rules go in front of a trailing catch-all rule; empty fields are dropped.
- DNS: forms (servers, hosts, `tag`, edit / import JSON), `dedicated_dns` with several servers, `direct_dns` adds its servers.
- `accounts.prune` and `prune-accounts [--dry-run]`: remove the WARP accounts of users the panel no longer has (off by default).
- Block settings: personal or shared WARP account, Xray values to pick from, duplicate a block, scrolling while dragging.
- The balancer's *Catch-all rules* are now *Routing rules*.

## 0.4.0-beta

Balancer strategy settings, member cost and placement, WARP forms, new README and banner.
