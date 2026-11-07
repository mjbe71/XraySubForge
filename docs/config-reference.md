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
| `url` | `""` | The panel's JSON-subscription URL; the id is appended. **Required** (without it the service answers 503). |
| `raw_url`, `clash_url` | `""` | The panel's raw and Clash subscription URLs (id appended). When set, the service passes these formats through unchanged at `server.raw_route` / `server.clash_route`, in both modes. |
| `page_url` | `""` | Optional. If set, browsers (`Accept: text/html`) are redirected to `page_url` + id. |
| `timeout` | `10` | Seconds. |
| `verify_tls` | `true` | Check the panel's TLS certificate. |
| `headers` | `{}` | Extra request headers sent to the panel. |
| `pass_headers` | `Profile-Title`, `Profile-Update-Interval`, `Subscription-Userinfo`, `Profile-Web-Page-Url`, `Support-Url`, `Announce`, `Content-Disposition` | Panel response headers copied to the client. |

## Conditions (`when`)

Used by rules, groups, patches and `member_cost`. A `when` is an object; **all** its entries must hold. A missing or
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
| `routing_prepend`, `routing_append` | none | Lists of routing rules added before / after the existing ones. |

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

## `chains` in `exit_first` mode

The normal chain puts your outbound in front of an exit config. With `"mode": "exit_first"` the matched config
(for example a placeholder the panel hands out per country) becomes `[exit, entry]`: traffic leaves through the exit and
the exit is dialed **through** the entry (client → entry → exit). The matched config itself is removed from the result.

```json
{
  "id": "warp-then-exit",
  "mode": "exit_first",
  "exit_when": { "protocol": "masque" },
  "split_by": { "field": "flag", "regex": "(.+)" },
  "name": "{split} WARP",
  "entry": "{account.masque.outbound}",
  "endpoints": "{account.masque.endpoints}",
  "entry_merge": { "streamSettings": { "sockopt": { "domainStrategy": "UseIP" } } },
  "pick": "random"
}
```

- `entry`: an outbound, or one `{account.x}` placeholder (the placeholders inside it are filled too).
- `endpoints`: a list (or placeholder) of `host`, `host:port` or `[v6]:port`; one is picked and written into the entry's address and port. `pick`: `random` or `per_user`.
- `exit`: where the exit outbound comes from. By default the account's `exits` object, keyed by the config's flag, then the account's `exit`. The user's own id (the most frequent vless/vmess id among their other configs) is filled in. `{"user_id": false}` leaves the template as it is.
- `"exit": false`: **entry only** (no exit). `before` is a list of outbounds placed in front of the entry, with `{entry.address}`, `{entry.port}` and `{user.id}` available; all traffic still goes to the entry.
- If the user has no config with an id, no config is made and the problem shows in the preview's report.

If the account has a `pool` list, a user without a personal account gets one entry of it, fixed by the subscription id.

## `output`: settings for every returned config

Everything is off unless you turn it on. `when` limits it to some configs.

| Key | Meaning |
|---|---|
| `split_inbounds` | Replace `mixed` by a `socks` (tag `socks`) and an `http` inbound (some apps cannot use `mixed`). Ports are kept. |
| `dns_out` | Add a `dns-out` outbound and a rule that sends DNS queries from the `socks` inbound to Xray's own DNS module. Only for configs that have DNS servers. |
| `block_udp_443` + `quic_domains` | Block QUIC (UDP 443) for these domains (a built-in list unless you set `quic_domains`). |
| `base_rules` | `true`: private and `.ir` destinations go direct. Or give your own list of rules. |
| `direct_dns` | `true` or `{"tag_regex": "..."}`: queries of the config's own DNS servers whose tag matches (default `^domestic-dns`) go direct. |
| `dedicated_dns` | `true` or `{"ip": "8.8.8.8", "tag": "dedicated-dns"}`: the names the proxies themselves connect to (address, SNI, host) are resolved by this DNS, directly. |
| `replace_routing` | Drop the template's routing rules and keep only balancer rules (and rules made by chains). With `domain_strategy` set, also sets it. |
| `sampling` | Observatory `sampling` of **our** balancers: `{"fixed": 2}` or `{"members_div": 2, "extra": 2}` (members ÷ 2 + 2). |
| `panel_balancers` | Tune the panel's own `leastLoad` balancers: `{"max_rtt": "2500ms", "few_max_members": 2, "expected_few": 1, "expected_many": 2}`. |
| `remark_rewrite` | `[{ "if": "regex", "regex": "...", "replace": "..." }]` applied to each remark in order (`if` is optional). |
| `decoy` | `{"param": "decoy", "default": false, "ping_url": "...", "when": {...}}`: a harmless `freedom` outbound tagged `decoy` as the **first** outbound, for apps that ping only the first one. `?decoy=1` turns it on, `?decoy=0` off, otherwise `default` decides. Real traffic keeps its routing. |

## `order`: the order of the result

A list of `{ "id", "when", "rank" }`. Every returned config gets the `rank` of the first item that matches it (smaller =
higher); the sort is stable, and configs that match nothing go last. An item without `when` catches the rest.
