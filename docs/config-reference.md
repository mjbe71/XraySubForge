# Configuration reference

XraySubForge is an advanced add-on for 3x-ui. It adds what the panel does not do by itself: conditional rules
(conditions and regex on any field), balancers built from name patterns (one per country, for example), a WARP chain
with a separate account for each user, and a preview of the result. It does not repeat the panel's own Hosts and
Sub Balancers; use those first, and use this when they are not enough.

Everything XraySubForge does comes from one JSON file, `config.json` (path: environment variable
`XRAYSUBFORGE_CONFIG`, default `./config.json`). The file is re-read automatically when it changes (only
`server.route` needs a restart). An empty or missing file means: **subscriptions pass through unchanged**.

* A wrong value is ignored and reported on stderr; a broken file keeps the previous settings.
* Any key starting with `_` is a comment and is ignored (anywhere in the file).
* Check a file without starting the service: `python -m xraysubforge check config.json`
* See what your rules do to a saved panel response: `python -m xraysubforge preview panel.json config.json`

Nothing below is assumed by the program: it never looks for special words in names. You decide what each config is.

## How a subscription is processed

```
panel response ──► patches (stage "source") ──► rules ──► groups ──► chains ──► patches (stage "output") ──► client
```

## `server`

| Key | Default | Meaning |
|---|---|---|
| `host` | `"127.0.0.1"` | Address to listen on (`0.0.0.0` for all). The Docker image overrides it with the env var `XRAYSUBFORGE_HOST`. |
| `port` | `8080` | Port. |
| `route` | `"/sub/"` | Public path; the subscription id is appended. Needs a restart to change. |
| `raw_route`, `clash_route` | `"/raw/"`, `"/clash/"` | Public paths of the raw and Clash subscriptions, served only while `panel.raw_url` / `panel.clash_url` is set. Empty = off. Must differ from `route` and `admin.path`. Needs a restart to change. |
| `subid_regex` | `"^[A-Za-z0-9_-]{4,64}$"` | Ids not matching this get a 404 without contacting the panel. |
| `workers`, `threads` | `2`, `4` | Used by gunicorn (`gunicorn.conf.py`). |
| `tls_cert`, `tls_key` | `""` | Serve HTTPS directly: paths of the certificate (full chain) and the private key; set both or neither. The service user must be able to read them (the installer keeps copies in `/etc/xraysubforge/certs`). Needs a restart. |
| `hosts` | `[]` | Host names that choose this profile when several [profiles](#profiles-several-services-in-one-install) share a route (the request's `Host` header is compared). |
| `domains` | `[]` | More names, each with its own certificate: `[{"name": "sub2.example.com", "cert": "...", "key": "..."}]` (`*.example.com` works too). The app's requested name (SNI) picks the certificate; other names get the default one (`tls_cert`, or the first domain's). Renewed files are picked up by themselves. A domain behind Cloudflare can use Cloudflare's Origin certificate. Needs a restart to change. |

## Profiles: several services in one install

`config.json` is the default profile. Every `profiles/<name>.json` next to it is another one: a complete config of the same
shape, with its own `panel`, `blocks`, `rules`, `accounts` and `output`. Profiles are read at startup (restart to add one);
a name is lowercase letters, digits, `-` or `_`.

Which profile answers a request:

1. only one profile uses the requested route (`server.route`, `raw_route`, `clash_route`) -> that one;
2. several profiles share the route -> the one whose `server.hosts` holds the request's host name;
3. still several -> the profile whose panel knows the subscription id (the panels are asked at once; a found id is remembered
   for an hour). An id that exists in more than one panel goes to the first profile (default first) and is logged once.

Profiles that share a domain must never hand out the same subscription id to two different users. The admin panel has a profile switcher (with "+ New profile" (empty or a copy without its accounts), Rename and Delete; Delete moves the file to `profiles/trash/`) next to the title; a new profile needs a service restart for its routes.

## `admin`

The web admin panel at `server`'s address + `admin.path`. It is **off until you set a password**.

| Key | Default | Meaning |
|---|---|---|
| `password_hash` | `""` | Recommended. Create it with `python -m xraysubforge hash-password` and paste the result. |
| `password` | `""` | Plain-text alternative (a note is logged). Ignored when `password_hash` is set. |
| `path` | `"/admin"` | Where the panel lives. Needs a restart to change. |
| `session_hours` | `12` | How long a login lasts. Changing the password logs everyone out. |
| `max_failed_logins`, `lockout_seconds` | `5`, `300` | After this many wrong passwords from one address, logins from it are refused for that long. |

The panel edits every other section of `config.json` but never shows or changes `admin`.

## `panel`

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"engine"` | `"engine"` applies your rules. `"proxy"` is a plain reverse proxy: the panel's reply (body, content type and `pass_headers`) is handed through unchanged and no rule, group, chain or patch runs. |
| `url` | `""` | The panel's JSON-subscription URL; the id is appended, or put where `{id}` is (for panels whose address goes on after the id, e.g. `https://panel.example.com/sub/{id}/v2ray-json`). **Required** (without it the service answers 503). The same `{id}` works in `raw_url`, `clash_url` and `page_url`. |
| `source` | `"json"` | `"raw"`: build the JSON configs from the share links at `raw_url` (`vless`, `vmess`, `trojan`, `ss`), so the panel's JSON subscription is not needed. Each link goes into `json_template`. Other link types (masque, hysteria2, tuic, wireguard) are left out, and what links cannot carry (the panel's DNS and routing, Final Mask / fragment, mux, sockopt) is lost: the JSON subscription is the better source when you can turn it on. |
| `json_template` | `{}` | With `source: "raw"`: the client config every link is put into (inbounds, DNS, routing, extra outbounds); the link's outbound comes first, tagged `proxy`. Empty = a built-in one (socks 10808, http 10809). |
| `raw_mode` | `"pass"` | The raw route: `"pass"` hands the panel's links through; `"engine"` turns them into configs, applies your rules and blocks, and writes links again. A balancer becomes one link per member; what a link cannot carry (fragment, cipher suites, chains) is left out. |
| `raw_url`, `clash_url` | `""` | The panel's raw and Clash subscription URLs (id appended). When set, the service passes these formats through unchanged at `server.raw_route` / `server.clash_route`, in both modes. |
| `page_url` | `""` | Optional. If set, browsers (`Accept: text/html`) are redirected to `page_url` + id. |
| `timeout` | `10` | Seconds. |
| `verify_tls` | `true` | Check the panel's TLS certificate. |
| `headers` | `{}` | Extra request headers sent to the panel. |
| `pass_headers` | `Profile-Title`, `Profile-Update-Interval`, `Subscription-Userinfo`, `Profile-Web-Page-Url`, `Support-Url`, `Announce`, `Content-Disposition` | Panel response headers copied to the client. |

## Conditions (`when`)

Used by rules, groups, patches and `member_cost`. Besides the fields of a config, `made_by` is the id of the group or chain that built an output config (missing for the panel's own configs); it is useful in `order` and output-stage patches. A `when` is an object; **all** its entries must hold. A missing or
empty `when` matches every config.

```json
{ "remark": { "contains": "fast" }, "network": "xhttp" }
{ "any": [ { "port": 443 }, { "port": 8443 } ] }
{ "not": { "protocol": "socks" } }
```

A plain value means "equals": `{ "network": "ws" }`.

**Fields.** They are read from the config's *main outbound* (the first outbound that is not `freedom`, `blackhole`,
`dns` or `loopback`):
`remark`, `protocol`, `tag`, `address`, `port`, `network`, `security`, `sni`, `host`, `path`, `flag` (the first flag
emoji in the remark, if any). Anything else can be reached with a dotted path into the whole config, e.g.
`"outbounds.0.settings.vnext.0.users.0.flow"`.

**Operators.** `equals`, `not_equals`, `contains`, `icontains`, `not_contains`, `startswith`, `endswith`, `regex`,
`iregex` (regular expression, searched anywhere in the value), `in`, `not_in` (lists), `exists` (true/false),
`gt`, `gte`, `lt`, `lte` (numbers). **Combinators:** `all` (list), `any` (list), `not` (object).

## `rules`: keep, drop, reorder

A list, evaluated in order. For each config the **first matching rule decides**; configs matching no rule are kept.

```json
{ "id": "hide-tests", "when": { "remark": { "startswith": "test" } }, "do": "drop" }
```

| Key | Meaning |
|---|---|
| `id` | Name (unique). Optional. |
| `enabled` | `false` switches the rule off without deleting it. |
| `when` | Condition. |
| `do` | `keep` (stop here, leave it alone), `drop` (remove it), `pin_top`, `pin_bottom`. |

## `groups`: combine configs into balancers

A list, evaluated in order. Each group collects the configs matching `when` (dropped ones are excluded) and builds
**one config per bucket** that contains all the members' outbounds and a balancer over them. Everything else
(inbounds, DNS, other outbounds, routing rules) is taken from the bucket's first member.

```json
{
  "id": "fast",
  "when": { "remark": { "regex": "^fast-" } },
  "split_by": { "field": "remark", "regex": "^fast-([^-]+)" },
  "name": "{split} ({n})",
  "type": "leastLoad",
  "params": { "expected": 2, "maxRTT": "1s" },
  "probe": { "destination": "https://www.gstatic.com/generate_204", "interval": "30s", "sampling": 2 },
  "member_cost": [ { "when": { "address": { "startswith": "b1." } }, "value": 5 } ]
}
```

| Key | Default | Meaning |
|---|---|---|
| `id` | auto | Unique name. Also used to build outbound tags (`<id>-<bucket>-<n>`). |
| `enabled` | `true` | Switch off without deleting. |
| `when` | everything | Which configs are candidates. |
| `split_by` | none | `{"field": ..., "regex": ...}`: one balancer **per distinct value** of the regex's first capture group (or the whole match). Configs where it does not match are not grouped. Without `split_by` all candidates form one balancer. |
| `name` | `{split}` with `split_by`, else the group id | Remark of the resulting config. `{split}` = the bucket value, `{n}` = member count, `{group}` = group id. |
| `type` | **required** | The Xray balancer strategy, as you would write it by hand: `leastLoad`, `leastPing`, `random`, `roundRobin`, ... |
| `params` | none | Copied as-is to the strategy's `settings` (for `leastLoad`: `expected`, `maxRTT`, `tolerance`, `baselines`, `costs`, ...). |
| `probe` | none | The observatory settings, copied as-is. For `leastLoad` they become `burstObservatory.pingConfig`; for other types the `observatory` object. Without it no observatory is written. |
| `probe_kind` | by type | Force `"burst"` or `"observatory"`. |
| `member_cost` | none | List of `{"when": ..., "value": number}`; the first matching entry gives that member a `costs` entry (added to any `costs` you put in `params`). |
| `min_members` | `1` | Buckets with fewer members are not built (their configs stay as they were). |
| `remove_members_from_output` | `true` | `false` keeps the original single configs next to the balancer. |
| `position` | where the first member was | `"top"` or `"bottom"`. |
| `member_tag`, `balancer_tag` | none | Plain outbound tags: with `"member_tag": "proxy"` the members are tagged `proxy01`, `proxy02`, ... and the balancer `balancer` (or `balancer_tag`), instead of tags built from the group id. Blocks always use this. |

Notes: routing rules that pointed at the first member's outbound are re-pointed to the balancer, and a final
"all traffic → balancer" rule is added. The old `observatory`/`burstObservatory` of the template are removed
because they referred to the old tags.

## `chains`: put your own outbound in front of an exit

A chain builds, from an **exit config** of the panel, a new config whose traffic goes through **your own `entry`
outbound** (for example a WARP/masque or WireGuard outbound), which in turn is dialed *through* the exit
(`sockopt.dialerProxy`). The program knows nothing about what the entry is: you paste the outbound JSON.

```json
{
  "id": "second-hop",
  "exit_when": { "remark": { "startswith": "fast-" } },
  "split_by": { "field": "remark", "regex": "^fast-([^-]+)" },
  "name": "{split} + second hop",
  "entry": {
    "protocol": "masque",
    "settings": { "address": "gate.example.com", "port": 443 },
    "streamSettings": { "masqueSettings": { "warp": { "privateKey": "{account.privateKey}", "address": "{account.address}" } } }
  }
}
```

| Key | Default | Meaning |
|---|---|---|
| `id`, `enabled` | | As for rules. |
| `exit_when` | everything | Which configs may serve as the exit. |
| `split_by` | none | One chain per bucket (the bucket's **first** config is the exit). Without it, one chain from the first matching config. For one chain per config use `{"field": "remark", "regex": "^(.*)$"}`. |
| `name` | `{split}` with `split_by`, else the id | Remark of the result (`{split}`, `{n}`, `{group}`). |
| `entry` | **required** | The outbound to dial through the exit. Placeholders are filled in (below). |
| `through_exit` | `true` | `false` = no exit: the config only borrows DNS/inbounds/routing from the first match and its own outbound is replaced by `entry`. |
| `remove_exit_from_output` | `false` | Remove the exit config from the result. |
| `position` | where the exit was | `"top"` or `"bottom"`. |
| `entry_tag`, `exit_tag` | from the chain id | The tags of the two outbounds. Chain blocks use `warp` and `proxy01`. |
| `account` | personal | `"shared"`: this chain always uses the default account, never a user's personal one. |

**Placeholders** inside `entry` (strings only): `{choice.<name>}` (one value from this chain's `choices`), `{account.<key>}` values from [`accounts`](#accounts), `{exit.<field>}`
any field of the exit config (`address`, `port`, `remark`, ...), `{split}`, `{n}`. A string that is *only* a placeholder
keeps the value's type (so lists such as an address list work). If a value is missing, that chain is skipped and the
problem is reported (preview, stderr); everything else still works. The `entry` outbound gets the tag
`<id>-<bucket>-entry` and the exit `<id>-<bucket>-exit`; routing rules that pointed at the exit's old tag, and a final
"all traffic" rule, now point at the entry.

`choices` (optional) is an object of lists, e.g. `{"endpoint": ["1.2.3.4", "5.6.7.8"]}`. Each user gets one value from each
list, available as `{choice.endpoint}`; it depends only on the subscription id and the chain, so a user always gets the same
one and users are spread over the list. Without a subscription id (preview) the first value is used.

A complete, working WARP-over-MASQUE setup is in `examples/warp-masque.json`.

## `accounts`

Where `{account.*}` values come from. Optional.

| Key | Default | Meaning |
|---|---|---|
| `file` | `""` | JSON file (relative paths are relative to `config.json`), re-read when it changes. |
| `default` | `{}` | Values written inline; the file wins on conflicts. |

The file is either one flat object (one account for everybody) or
`{"default": {...}, "users": {"<subscription id>": {...}}}`: a user's own entry is merged over `default`, so you can give
individual users personal values. Treat the file as a secret (`accounts*.json` is in `.gitignore`).
See `examples/accounts.example.json` and `examples/chain.json`.

### `accounts.endpoints`: the WARP endpoint pool

A list of WARP endpoints (`host`, `host:port` or `[v6]:port`; the output of an endpoint scanner can be pasted in the admin panel, Settings,
*Accounts and WARP*). Every WARP hop that has no `endpoints` of its own picks one from the pool: at random, or the same
one for the same user with `pick: "per_user"`. Order of precedence: the hop's own `endpoints`, then this pool, then the account's
`masque.endpoints`. A bad entry is reported and ignored; duplicates are dropped. Empty (the default) = use the account's endpoints.

### `accounts.register`: create WARP accounts automatically (optional, off by default)

Instead of filling the accounts file by hand, the service can create a Cloudflare WARP (MASQUE) account for each user
the first time that user fetches the subscription, and save it in the accounts file under `users`.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Needs `accounts.file`, and at least one enabled chain. |
| `retry_seconds` | `600` | After a failed attempt, wait this long before trying again for that user. |
| `api`, `client_version` | `""` | Override the built-in Cloudflare client API address / version string. |

The account has these values for `{account.*}`: `privateKey` (base64), `address` (list), `publicKey` (the server's key,
when the API gave one) and `id` (device id). **This uses Cloudflare's unofficial client API**: it can change or start
refusing requests without notice. A failed registration never breaks a subscription: that user just gets the
subscription without the chain, and it is retried later. Registration happens inside the request, so a user's very
first fetch takes a couple of seconds longer.

Manual creation: `python -m xraysubforge register-account [--subid ID] [--force]` (no id = the shared account), or the
button in the admin panel (Settings tab). Only WARP over **MASQUE** accounts are created (WireGuard accounts work differently and are not supported yet). Needs the `cryptography` package (in `requirements.txt`).

### `accounts.prune`: remove the accounts of users who left (optional, off by default)

Personal accounts stay in the accounts file after a user is deleted from the panel. With `accounts.prune` the service
asks the panel about every user that has a personal account, about once per `interval_hours`, and removes the accounts
of users the panel no longer has. A removed user who comes back simply gets a new account (with `accounts.register`).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Needs `accounts.file`. The check starts from subscription requests, so a service nobody uses checks nothing. |
| `after_days` | `3` | A user must be missing in at least two checks, this many days apart, before the account is removed. `0` removes at the first check. |
| `max_percent` | `50` | With 10 or more users: when more than this share look missing in one check, nothing is removed (the panel is more likely wrong than the users gone). |
| `interval_hours` | `24` | Time between two automatic checks. |

What "no such user" looks like is learned from the panel: a random id is asked first, and only users answered exactly
like it (the same 4xx status, or an empty reply) count as missing. Nothing is removed when the panel cannot be reached,
or answers a random id with configs or with a server error. A panel that still serves expired users keeps their
accounts; only users the panel no longer answers for are removed. The bookkeeping (who is missing since when, the
time of the last check) is kept in the accounts file under `_prune`.

By hand: `python -m xraysubforge prune-accounts [--dry-run]`, or the two buttons in the admin panel (Settings tab):
*Check now* only counts, *Run now* is one normal check.

## `patches`: change anything

Merge JSON of your own into matching configs. This is how you add DNS, routing rules, fragment/mux settings, etc.
The program ships none of these.

```json
{
  "id": "mux-off",
  "stage": "source",
  "target": "outbound",
  "when": { "network": "xhttp" },
  "merge": { "mux": { "enabled": false }, "streamSettings": { "xhttpSettings": { "mode": "auto" } } },
  "routing_prepend": [ { "type": "field", "domain": ["example.org"], "outboundTag": "direct" } ]
}
```

| Key | Default | Meaning |
|---|---|---|
| `stage` | `"source"` | `source`: before rules/groups, on the panel's original configs (so `when` sees the original names, and the changes carry into groups). `output`: on the final configs. |
| `target` | `"config"` | `config`: merge into the whole config. `outbound`: merge into every non-`freedom`/`blackhole`/`dns` outbound of it. |
| `when` | everything | Condition on the config. |
| `merge` | none | Deep-merged: objects are merged, lists and values replaced, **`null` deletes** the key. |
| `random` | none | `{"dotted.path": [choice, ...]}`: one random choice per config (or per outbound with `target: "outbound"`), e.g. a fragment profile or a cipher list. |
| `routing_early` | none | Rules added after the DNS rules at the top (the DNS interception and the `inboundTag`-only rules) and in front of the private / domestic direct rules. Used by block rules with `"position": "early"`. |
| `routing_prepend`, `routing_append` | none | Lists of routing rules added before / after the existing ones (`routing_append`: in front of a trailing catch-all rule, which would otherwise make it dead). `"outboundTag": "{main}"` is replaced by the outbound (or balancer) that carries the config's traffic. |

## `blocks`: the final subscription as blocks

The layout the admin panel's block editor writes. You can also write it by hand. Each block takes some **kinds** of
configs (a kind is a condition, like a `when`); a config belongs to the **first** block from the top whose kinds match
it, and the blocks come out in this order. The program turns the blocks into ordinary rules, groups, patches and
order items (ids starting with `blk-`), placed after your own ones, so everything above still applies.

```json
"blocks": {
  "rest": "keep",
  "list": [
    { "id": "fast", "name": "Fast", "type": "balancer", "per_country": true,
      "kinds": [ { "remark": { "regex": "^fast-\\d+🇩🇪$" }, "network": "xhttp" } ],
      "settings": { "fragment": ["tlshello-0-len", "tlshello-6-98"], "cipher": ["semi-python"],
                    "fingerprint": "chrome", "strategy": "leastLoad", "pool": ["a.example.com", "b.example.com"] } },
    { "id": "gone", "type": "drop", "kinds": [ { "remark": { "startswith": "Tunnel" } } ] }
  ]
}
```

| Key | Meaning |
|---|---|
| `rest` | `keep` (default): configs no block takes come last, as they are. `top`: they come first (for example the panel's info config). `hide`: they are removed. |
| `list[].id` | Letters, digits, `-` and `_`. |
| `list[].type` | `list` (default): the configs as they are. `balancer`: one balancer (or one per country with `per_country`). `chain`: each config goes through a chain of hops (below). The older `warp` block type was removed in 0.6.0 (its exit came from the accounts file): use a `chain` block. `drop`: removed. |
| `list[].flagless` | Balancers with `per_country`: `own` (default) puts configs without a flag into one balancer of their own; `single` leaves them as they are. |
| `list[].kinds` | A list of conditions; the block takes configs matching any of them. |
| `list[].enabled` | `false` switches the block off; its configs go on to the next blocks. |
| `settings.fragment` | One or more of `tlshello-0-len`, `tlshello-6-98`, or your own `"packets, lengths, delays[, maxSplit]"`. With several, each config (or member) gets one at random. |
| `settings.cipher` | One or more of `semi-python`, `real-firefox`, or your own `TLS_…:TLS_…` list; random as above. TLS configs only. |
| `settings.fingerprint` | `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`, `randomized`, `unsafe` (TLS and Reality). |
| `settings.strategy` | Balancers: `leastLoad` (default), `leastPing`, `random`, `roundRobin`. `leastLoad` and `leastPing` get a default probe. |
| `settings.member_position` | Balancers: `[{ "when": {...}, "at": "first" \| "last" }]`, where matching members sit in the balancer (the first matching entry decides). |
| `settings.member_patch` | Balancers: `[{ "when", "merge", "random" }]`, extra steps applied to every member after the fragment/cipher/fingerprint steps (for example `alpn` or `sockopt`). |
| `settings.catchall_rules` | Balancers: the routing rules sent to the balancer, in this order (the balancer tag is filled in). Default: `{"network": "tcp,udp"}`. A rule can have `"position": "early"` (ours, removed from the output): it goes after the DNS rules at the top and in front of the private / domestic direct rules. If every rule is early, the default catch-all stays at the end. |
| `settings.expand` | Balancers: the `expand` object (see below): several members per server. Wins over `pool`. |
| `settings.min_members` | Balancers: whole number, 1 or more; buckets with fewer members are not built (same as the group key). |
| `settings.keep_members` | Balancers: `true` keeps the original single configs next to the balancer. |
| `settings.include_balanced` | Balancers: `true` also uses configs that already have a balancer of the panel's own. |
| `settings.probe_kind` | Balancers: `burst` or `observatory`; default by strategy (`burst` for `leastLoad`). |
| `settings.position` | Old setting (still honoured, no longer offered): `top` or `bottom`, ignoring the block order. Order the blocks instead. |
| `settings.hops` | Chain blocks: the path of the traffic, a list of 1 to 4 hops (see [Chain blocks](#chain-blocks)). Default `[{"from": "warp"}, {"from": "block"}]`. |
| `settings.rules` | List, WARP and chain blocks: routing rules added at the end of the config's rules, but in front of a trailing catch-all rule (one that matches all tcp and udp traffic: a balancer's, a decoy's), since a rule after it would never apply. Empty fields (`"domain": []`) are dropped. A rule without `outboundTag` / `balancerTag` goes to the block's own proxy. Each rule can have `"position": "early"` (a key of ours, not Xray's, removed from the output): that rule goes after the DNS rules at the top and in front of the private / domestic direct rules, so it can override them. Default `"end"`. |
| `settings.patches` | List blocks: a list of patches (`stage`, `target`, `when`, `merge`, `routing_prepend`, `routing_append`) for this block's configs. |
| `settings.choices` | Chain blocks: object of non-empty lists, picked from with `{choice.x}` placeholders in the hops. |
| `settings.pool` | Balancers: every member gets one copy per address in this list. |
| `settings.name` | Balancers: the name, with `{block}`, `{country}` (the flag) and `{n}` (members). Default `{block} {country}` or `{block}`. |

### Chain blocks

A chain block sends the traffic of its configs through several outbounds, one after the other:
client → hop 1 → hop 2 → the internet. In Xray terms every hop is dialed through the hop before it
(`streamSettings.sockopt.dialerProxy`); the last hop is tagged `proxy01`, the ones before it `warp` or `hop1`, `hop2`.
Each config in the block gives one chained config (with `per_country`: the first config of each country), and the
block's own configs are replaced by the chained ones. The same thing as the classic `chains` item with `"mode": "hops"`.

```json
{ "id": "far", "name": "Far", "type": "chain", "kinds": [ { "remark": { "contains": "gate" } } ],
  "settings": { "hops": [ { "from": "block" },
                          { "from": "outbound", "outbound": { "protocol": "vless", "settings": { "vnext": [
                              { "address": "far.example.com", "port": 443, "users": [ { "id": "{user.id}" } ] } ] } } } ] } }
```

| `from` | The hop's outbound | Other keys |
|---|---|---|
| `block` | The config itself (its main outbound). At most one hop. | none |
| `warp` | The WARP outbound of the account (`{account.masque.outbound}`), with one of the account's endpoints. | `account`: `personal` (default) or `shared`; `pick`: `random` (default) or `per_user`; `endpoints`, `entry`: your own list / outbound instead of the account's; `merge`: an object merged into the outbound |
| `outbound` | An outbound you write (the panel can import it from a `vless://`, `vmess://`, `trojan://` or `ss://` link). Placeholders are filled in: `{user.id}` (the user's own id, the most frequent one among the user's configs), `{account.x}`, `{choice.x}`. `outbound` can also be a map `{"🇩🇪": {outbound}, "🇹🇷": {outbound}, "default": {outbound}}`: the flag of the config picks the outbound (then `"default"`; none = that chain is skipped and the error is reported). This keeps exits in the configuration, so the accounts file needs no `exits`. | `outbound` (required) |
| `config` | Another config of the same subscription: the first one matching `when`, one with the same flag first. That config also stays in the list. | `when` (required) |

Other settings of a chain block: `name` (`{block}`, `{name}` = the config's own name, `{country}`; default `{name}`, or
`{block} {country}` with `per_country`), `decoy` (`"vless"`: an unused outbound in front), `choices`, `rules`. When a hop
cannot be built for a user (no account, no matching config), that config is left as it was and the error is listed in
the preview.

## More options for `groups`

| Key | Meaning |
|---|---|
| `include_balanced` | Default `false`: configs that already have a balancer (the panel's own) are left alone. `true` lets a group use them too. |
| `expand` | Several balancer members per **server**, not just one per config. See below. |
| `member_patch` | A list of `{ "when", "merge", "random" }` steps applied to every member's outbound. `merge` works like a patch (`null` deletes); `random` maps a dotted path to a list, and every member gets one random value (for example a cipher list or a fragment profile). |
| `member_position` | `[{ "when": {...}, "at": "first" \| "last" }]`: where matching members sit in the balancer. |
| `catchall_rules` | The routing rules sent to the balancer, in this order (the balancer tag is filled in). Default: one rule `{"network": "tcp,udp"}`. |

**`expand`**

```json
"expand": {
  "copies": 2,
  "server_by": { "field": "remark", "regex": "s(\\d+)" },
  "addresses": ["a.example.com", "b.example.com", "c.example.com"],
  "address_regex": "^[a-z]\\.example\\.com$",
  "when": { "remark": { "contains": "CF" } },
  "pick": "random",
  "layout": "blocks"
}
```

Every server (`server_by` finds it; without it each config is its own server) gets `copies` members. They alternate over
the server's configs (for example different SNIs). If `addresses` is set, every member gets an address from that pool;
a config whose own address does not match `address_regex` keeps its own address. Configs that do not match `when` stay
single members. `pick`: `random` (a new random choice on every fetch) or `per_user` (stable for a subscription id).
`layout`: `grouped` (a server's members together) or `blocks` (`copies` blocks, each with one member of every server, so
members of one server are not next to each other).

## `output`: settings for every returned config

Everything is off unless you turn it on. `when` limits it to some configs.

| Key | Meaning |
|---|---|
| `split_inbounds` | Replace `mixed` by a `socks` (tag `socks`) and an `http` inbound (some apps cannot use `mixed`). Ports are kept. |
| `sniff_override`, `route_only`, `socks_port`, `http_port` | With `split_inbounds`: the sniffing `destOverride` list (default `http`, `tls`, `quic`, `fakedns`), sniffing `routeOnly` (default off) and the two ports (default: the panel's own). All shown in the admin panel. |
| `dns_out` | Add a `dns-out` outbound and a rule that sends DNS queries from the `socks` inbound to Xray's own DNS module. Only for configs that have DNS servers. |
| `block_udp_443` + `quic_domains` | Block QUIC (UDP 443) for these domains (a built-in list unless you set `quic_domains`). |
| `base_rules` | `true`: private and `.ir` destinations go direct. Or give your own list of rules. |
| `direct_dns` | `true` or `{"ips": ["223.5.5.5"], "domains": [["geosite:private"], ["domain:ir", "geosite:category-ir"]], "tag_regex": "^domestic-dns"}`: domestic DNS servers for domestic names, asked directly. One server entry is added in front of `dns.servers` for each line of `domains` and each IP (`finalQuery`, `skipFallback`, tags `domestic-dns_<line>_<ip>`), and a routing rule sends the queries of every server whose tag matches `tag_regex` direct. `true` uses the values shown. Servers of the panel that already have a matching tag are used instead of ours; `"ips": []` adds none (only the rule). Only for configs that have a `dns` section. |
| `dedicated_dns` | `true` or `{"ips": ["8.8.8.8", "1.1.1.1"], "tag": "dedicated-dns"}`: the names the proxies themselves connect to (address, SNI, host) are resolved by these DNS servers, directly (`"ip": "..."` is still accepted for one server). |
| `dns` | Your own DNS settings for every config: `{"hosts": {...}, "servers": [...], "servers_at": "replace" \| "first" \| "last", ...}`. `hosts` and any other key of Xray's `dns` object (`queryStrategy`, `disableCache`, ...) are merged into the config's `dns`; `servers` replace the config's servers (default), or go before / after them. A config without `dns` gets one. Applied before `dedicated_dns` and `direct_dns`. |
| `replace_routing` | Drop the template's routing rules and keep only balancer rules (and rules made by chains). With `domain_strategy` set, also sets it. |
| `sampling` | Observatory `sampling` of **our** balancers: `{"fixed": 2}` or `{"members_div": 2, "extra": 2}` (members ÷ 2 + 2). |
| `panel_balancers` | Tune the panel's own `leastLoad` balancers: `{"max_rtt": "2500ms", "few_max_members": 2, "expected_few": 1, "expected_many": 2}`. |

## `order`: the order of the result

A list of `{ "id", "when", "rank" }`. Every returned config gets the `rank` of the first item that matches it (smaller =
higher); the sort is stable, and configs that match nothing go last. An item without `when` catches the rest.
