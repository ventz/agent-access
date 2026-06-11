# Proton Pass provider for Agent Access

This fork adds a `proton` credential provider to `aac`, backed by the official
[Proton Pass CLI](https://protonpass.github.io/pass-cli/) (`pass-cli`). It lets
an Agent Access listener serve credentials out of a Proton Pass vault over the
same end-to-end encrypted tunnel used by the built-in Bitwarden provider.

## Prerequisites

1. A paid Proton Pass plan (the CLI is gated to paid tiers).
2. `pass-cli` installed and on your `PATH`
   (<https://protonpass.github.io/pass-cli/get-started/installation/>).
3. `aac` built from this fork:
   ```sh
   cargo build -p ap-cli --release   # binary: target/release/aac
   ```

## Authentication

The provider authenticates with a **Personal Access Token** (`pst_…::KEY`). You
can paste one into the `aac` unlock prompt, or pre-establish a session so the
provider starts in the `Ready` state:

```sh
# Pre-existing session (interactive web login, or a PAT):
PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_…::KEY" pass-cli login
```

### Recommended: a scoped agent token

Proton's `agent` tokens are PATs restricted to specific vaults/items and write
an audited reason for every read — ideal for this use case:

```sh
pass-cli agent create my-listener --expiration 1w --vault "Automation"
# prints the token ONCE — use it as the PAT above
pass-cli agent access grant my-listener --vault-name "Automation" --role viewer
pass-cli agent monitor my-listener            # review what was accessed
```

## Usage

```sh
aac listen --provider proton
```

Then connect from the remote side as usual and request a credential by domain,
item id, or free-text search.

### Audit reasons

Every credential read runs `pass-cli item view` with `PROTON_PASS_AGENT_REASON`,
which Proton records in the agent audit log. Set your own (≤300 chars) to make
the log meaningful; otherwise a default is used:

```sh
PROTON_PASS_AGENT_REASON="CI deploy: fetch DB creds" aac listen --provider proton
```

## How lookups work

* **Fast path** — for normal sessions, `pass-cli item list --show-secrets`
  returns each item's full content in one call per vault, so a domain/id/search
  is matched locally and the credential is built directly from the listing (no
  per-item reads).
* **Agent fallback** — agent-scoped sessions reject `--show-secrets`, so the
  provider falls back to a metadata listing plus `item view` per candidate.
  Agent tokens are scoped to a small set of items, so this stays cheap.

A query maps to a Proton item as follows:

| Agent Access query | Match strategy |
| --- | --- |
| domain / URL | item title or any stored login URL host (sub/parent-domain aware) |
| item id | Proton item id |
| free-text search | case-insensitive item title match (exact preferred) |

TOTP is returned as the stored `otpauth://` URI (the secret), mirroring the
Bitwarden provider.

## Notes & limitations

* Proton share IDs can start with `-`; the provider always passes
  `--share-id=VALUE` (attached) so the CLI doesn't mis-parse it as a flag.
* Only login items yield credentials; other item types are skipped.
* The CLI is in beta, so its command surface may shift.
