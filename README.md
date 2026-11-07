# XraySubForge

[فارسی](README.fa.md) · English

An **advanced add-on for 3x-ui**: a small Flask service that sits between your 3x-ui panel and your users' VPN apps.
It reads the panel's JSON subscription and reshapes it with **conditional rules** you write, matching configs by
condition or regular expression on any field (remark, protocol, security, port, ...).

What it adds on top of the panel:

- **Conditional rules with regex.** Drop, keep, pin or reorder configs depending on what they are, not just on which host they came from.
- **Pattern-based balancers per country.** Merge all configs whose name matches a pattern into one load-balanced config (Xray `leastLoad`, `leastPing`, `random`, ...), one balancer for each country (or any other group) the pattern captures.
- **Per-user WARP chain.** Route a config through an outbound of your own (Cloudflare WARP, ...) with a separate WARP account for each user.
- **Preview.** Enter a subscription id and see, in plain words, what happens to every config as you edit the rules.
- **Patches** for anything else in the JSON (DNS, routing, mux, fragment, ...).

It does not replace what 3x-ui already does. If the panel's own **Hosts** and **Sub Balancers** are enough for you,
you do not need this; use it when you need rules, patterns or per-user logic that they cannot express.

It knows no naming scheme and no provider. You decide what each config is, what is removed and what is combined.
With no rules it returns the panel's subscription unchanged.

```
client app ──► XraySubForge ──► your 3x-ui panel (JSON subscription)
                    └─ applies your rules, returns the result
```

> Beta (v0.3). Covered by automated tests and in use on a real server, but not yet used by many people. An independent project, not affiliated with Xray or 3x-ui.

## Install on a server (one command)

On a Linux server (Debian/Ubuntu: everything else is installed for you), as root:

```bash
curl -fsSL https://raw.githubusercontent.com/mjbe71/XraySubForge/main/install.sh | sudo bash
```

The installer asks what it needs and does the rest. In order:

1. **Panel address.** If a 3x-ui panel runs on the same server, it suggests the address of its JSON subscription.
2. **HTTPS.** Enter the domain users will connect to. Then, in this order:
   your own certificate files, if you give their paths; otherwise a certificate that already exists on the
   server (3x-ui's); otherwise it gets a **free Let's Encrypt certificate** for the domain (the domain must already
   point to this server, and port 80 must be free for a minute). Certificates are checked (valid, not expired,
   key matches, covers the domain) and renewals are picked up automatically. Press Enter at the domain question to
   skip HTTPS (plain HTTP on localhost only).
3. **Port**, and whether to enable the **web admin panel** (and its password).

Then it creates a service that starts at boot and prints your subscription link. Afterwards:

```bash
sudo xraysubforge help        # status, logs, restart, update, tls (change HTTPS), set-admin-password, ...
sudo xraysubforge update      # get the newest version, keeping your settings
```

Run `sudo xraysubforge` with no arguments for an **interactive terminal menu** (English): service status/logs/restart/update, panel URL, port and HTTPS, the admin password, adding/editing/reordering rules, groups, chains and patches with guided questions (or as JSON in your editor), a live preview for a subscription id, and WARP accounts. Every change is validated before it is written.

Everything can also be given as options for unattended installs (`--panel-url`, `--domain`, `--cert`/`--key`,
`--letsencrypt`, `--port`, `--admin`, `--yes`, ...): run `install.sh --help`. Settings live in
`/etc/xraysubforge/config.json`, the program in `/opt/xraysubforge`. To remove it: `sudo xraysubforge uninstall`.

> The installer has been tested on a real server. The 3x-ui detection reads setting names from memory of 3x-ui; if it finds nothing, it just asks you.
> Please report problems.

## Manual install

You need Python 3.9+ (or Docker) and a 3x-ui panel with the **JSON subscription** enabled.

```bash
git clone https://github.com/mjbe71/XraySubForge && cd XraySubForge
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json       # then put your panel's JSON-subscription URL in it
python app.py                            # development server (see below for production)
```

Open `http://127.0.0.1:8080/sub/<a user's subscription id>`: you get the panel's subscription (unchanged, since there
are no rules yet).

**Your panel's URL.** Find the JSON-subscription address in your panel's settings (3x-ui usually offers a path
like `/json/`; check yours). Put it in `config.json` as `panel.url`; the user's id is appended to it.

### Try the rules without any network

```bash
python -m xraysubforge preview examples/sample-panel.json examples/balancers.json
```

prints what each config in a saved panel response becomes under `examples/balancers.json`.
`python -m xraysubforge check config.json` validates a file.

### Production

```bash
gunicorn app:app        # address, port, workers and HTTPS (server.tls_cert / tls_key) come from config.json
```

or Docker: `mkdir -p data && cp config.json data/ && docker compose up -d --build` (the right-hand port in
`docker-compose.yml` must match `server.port`). The Docker files are not yet tested by the author; please report problems.

For HTTPS either set `server.tls_cert` and `server.tls_key` (what the installer does) or put a reverse proxy
with HTTPS in front and **turn its access log off**: the URL contains each user's secret id.

```nginx
server {
    listen 443 ssl;
    server_name sub.example.com;
    # ssl_certificate ...;
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Web admin panel

Everything below can be edited in a browser instead of by hand. The panel is **off by default**; turn it on by
setting a password in `config.json`:

```bash
python -m xraysubforge hash-password        # asks for a password, prints a hash
```

```json
{ "admin": { "password_hash": "<paste the hash here>" } }
```

Then open `http://127.0.0.1:8080/admin` (path: `admin.path`) and log in. The **Blocks** page is the main editor: fetch a user's subscription, then drag its configs (grouped into kinds) into blocks of the final subscription (a list, a balancer, a WARP chain, or Removed), each with its own settings such as fragment and cipher presets, fingerprint, address pool and names. Items made the old way can be turned into blocks there, and Save shows what changes and how many configs users get before and after. The **Start** page is a step-by-step setup guide that checks everything (is the panel reachable, does a test subscription work, HTTPS, accounts, settings) and can create common setups for you (hide configs, balance configs, route through WARP). The other tabs are forms for filters, balancers, chains, advanced edits and settings (plus a raw JSON editor). Conditions are written in plain words (a field such as the name, a kind such as "ends with", and one or more words), with values to pick from your own subscription and a count of how many of your configs each condition matches; patterns (regex) are only needed under "Advanced". Balancers and chains pick how to split from a list ("one for each country", "first word of the name", "part of the name after a text", ...). There is also a **live preview** that explains in words what happens to each config: enter a subscription id, fetch the panel's
real response, and watch what every config becomes as you edit. **Save** writes `config.json`; changes apply at once.
English and Persian (right-to-left) are built in.

Use it only over HTTPS (or through an SSH tunnel): the password travels in the login request. Login settings
(`admin.*`) can only be changed in `config.json`, never from the panel.

## Just a reverse proxy

With no rules, the JSON subscription passes through unchanged, and you can go one step further: set `panel.mode` to `"proxy"`
(or pick "Only forward my panel's subscriptions" in the admin panel's Start page) and the panel's reply is handed to the app
byte for byte. Set `panel.raw_url` and `panel.clash_url` and those two formats are forwarded as well, at `/raw/<id>` and
`/clash/<id>`. Your users get their subscriptions from your own domain, with HTTPS, while the 3x-ui panel itself can stay
on localhost or a private network. Add rules later without changing anyone's link.

## Configuring

Everything is in `config.json`, and changes apply without a restart. See **[docs/config-reference.md](docs/config-reference.md)**
for all options and `examples/` for ready examples:

| You want to | Use |
|---|---|
| remove or reorder configs | `rules` |
| merge configs into one balancer (per country, per name prefix, ...) | `groups` |
| put your own outbound (WARP, WireGuard, ...) in front of an exit config | `chains` + `accounts` |
| change anything else (DNS, routing, mux, fragment, ...) | `patches` |
| change address, port, URL path, timeouts | `server`, `panel` |

## Security notes

- The subscription id is checked (`server.subid_regex`) before it is sent to the panel.
- The public subscription route has no login and no rate limiting (the subscription id is the secret). Keep the port on localhost and use a reverse proxy. The admin panel has a password, signed session cookies, CSRF protection and a failed-login lockout.
- Never commit `config.json` (the `.gitignore` excludes it).
- The service never logs subscription ids or panel URLs.

## Not included (yet)

Automatic per-user WARP account registration (`accounts.register`, off by default, uses Cloudflare's unofficial API; tested against a simulated API only, not the real one).

## Similar projects (not affiliated)

Remnawave, Raven-subscribe, subscribe-middleware-go, Sub-Store.

## License

MIT, see [LICENSE](LICENSE).
