# Demo 01 - basic stack fingerprint

## Scenario

You are doing an authorized asset inventory of a web property your team owns.
You captured the HTTP response with your own tooling, e.g.:

```
curl -i -s https://your-authorized-host.example/ > sample_response.http
```

`sample_response.http` in this folder is a realistic captured response for a
WordPress site behind Cloudflare and nginx, running PHP, with jQuery and Google
Tag Manager on the page. WEBRECON never makes network requests itself -- it only
analyzes the response you already collected.

## Run it

Table output (human triage):

```
python -m webrecon scan demos/01-basic/sample_response.http
```

Machine-readable output (pipe into jq, detection rules, asset DB):

```
python -m webrecon scan demos/01-basic/sample_response.http --format json
```

From stdin:

```
cat demos/01-basic/sample_response.http | python -m webrecon scan -
```

## Expected

WEBRECON should identify, among others:

- **server**: nginx (with version), and **cdn**: Cloudflare (from `cf-ray` / `server`)
- **language**: PHP (from `X-Powered-By` and the `PHPSESSID` cookie)
- **cms**: WordPress (from the `generator` meta tag, `/wp-content/` paths, and `wordpress_*` cookie)
- **javascript**: jQuery (version from the script URL)
- **analytics**: Google Tag Manager

Exit code is `1` because findings were produced (actionable), `0` only when
nothing is identified.

## Why this is defensive only

The tool reads a response you captured under your own authorization and reports
the technology stack. There is no scanning, no exploitation, and no network
activity in the tool itself -- it is pure offline analysis to support inventory,
triage and detection engineering.
