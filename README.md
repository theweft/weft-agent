<h1><img src="https://theweft.org/brand/repos/weft-agent.svg" alt="" width="44" height="44" align="absmiddle"> weft-agent</h1>

> **Status: experimental (0.0.x).** Works offline (L1): inbox directory, decisions, config files,
> install hook, report, with the decider and executor as separate, sandboxed processes. Document
> sync tested in a deterministic simulation. No network transports yet.
> Like all of weft, it is built heavily with AI; see
> [How weft is made](https://github.com/theweft/weft-design#how-weft-is-made).

The agent that runs on Linux devices and gateways around
[weft-verifier](https://github.com/theweft/weft-verifier): it receives signed documents over any
path, lets the verifier decide, saves the decision state and executes the result. Design:
[weft-design docs/20-agent.md](https://github.com/theweft/weft-design/blob/main/docs/20-agent.md).

```text
 network / USB ──► [ transport ]   unprivileged, sandboxed: Zenoh/MQTT/USB/registry I/O, document sync
                        │ raw bytes (documents, artifacts by digest)
                        ▼
                   [ decider ]     no network, no privileges: weft-verifier + persisted state
                        │ typed instructions: install(hash) · apply_config(hash) · start(app)
                        ▼
                   [ executor ]    privileged, tiny: re-checks hashes, activation gates,
                                   calls SWUpdate / Podman / systemd; nothing else
```

## L1: a device agent without weft networking

```sh
weft-agent --tenant acme --anchor root.pub --label site=s1 --label line=l1 \
  --state-dir /var/lib/weft --inbox /media/usb/weft --config-dir /etc/weft/config \
  --on-config 'systemctl reload "$WEFT_COMPONENT"' \
  --on-install 'my-ota-tool install --sha256 "$WEFT_ARTIFACT"'
```

Each round (every `--interval` seconds, or once with `--once`):

1. reads signed documents from the inbox (never modifies it) and stores new ones in
   `<state-dir>/documents/`, before deciding;
2. lets weft-verifier decide; the verifier state is saved durably *before* anything runs;
3. writes the effective configuration to `<config-dir>/<component>.json` and runs `--on-config`;
   runs `--on-install` with `WEFT_COMPONENT` and `WEFT_ARTIFACT` (SHA-256) for installs;
4. writes `<state-dir>/outbox/report.json`: installed, applied, executed, failed, conflicts,
   withheld, rejected, pending.

Documents are made with [weft-cli](https://github.com/theweft/weft-cli) (`weft config`, `weft
deploy`, ...). Hooks are run with values only in environment variables and at least once, so
they must be idempotent. The system clock is not trusted unless `--trust-system-clock` is given.

### Separated: unprivileged decider, privileged executor

```sh
weft-agent executor --socket /run/weft/executor.sock        # root; hooks from WEFT_ON_CONFIG / WEFT_ON_INSTALL
weft-agent decider  --executor-socket /run/weft/executor.sock --tenant acme --anchor root.pub ...
```

The decider parses all untrusted input (inbox files, documents) and runs as user `weft` without
privileges, without network and on a read-only system
([dist/systemd/weft-decider.service](dist/systemd/weft-decider.service)). It sends the executor
only typed instructions over a Unix socket (`root:weft`, 0660): *apply this configuration* or
*install this artifact*. The executor re-checks the configuration hash and the component path,
refuses everything else, and runs the hooks it was configured with; the decider cannot name a
command or a directory. `weft-agent run` keeps both in one process.

## Crates

| Crate | Contents |
|---|---|
| [`weft-transport`](crates/weft-transport) | Transport contract (best-effort publish/subscribe, portable topic keys) and a turmoil adapter for simulations |
| [`weft-sync`](crates/weft-sync) | Document sync without I/O: content-addressed store, push plus anti-entropy pull, pending vs. shared, quarantine, limits |
| [`weft-decider`](crates/weft-decider) | Runs `weft_verifier::step`, saves the state **before** acting (durable, atomic `FileStore`, power-loss tested), drives the executor, classifies documents for sync |
| [`weft-agent`](crates/weft-agent) | The `weft-agent` binary (L1: inbox, document store, config and install hook executor, report) and the networked node runtime; the simulation and the requirements gate live in its tests |

## What the simulation checks

[`crates/weft-agent/tests/simulation.rs`](crates/weft-agent/tests/simulation.rs) runs a small
fleet in [turmoil](https://github.com/tokio-rs/turmoil), deterministic per seed:

```text
  cloud ── gateway ──┬── dev-a          (site=s1, line=l1)
                     ├── dev-c          (site=s1, line=l2; technician USB stick)
                     └── relay ── dev-b (site=s1, line=l1; behind a MALICIOUS relay)
```

Random latency, message loss, link failures, a partition and a restart of dev-a; documents enter
at random times from the cloud and a USB stick. The relay drops, tampers with and replays
documents. After the network heals:

1. **Convergence:** all honest nodes hold exactly the issued documents, and nothing forged.
2. **Agreement:** dev-a and dev-b (same labels, different paths) decide the same.
3. **Oracle:** each device's final state equals a fresh evaluation of the same documents.
4. **Safety:** tampered documents are never accepted; time floor and version marks never go back.
5. **Outcome:** the tie between two site keys is reported, the revoked technician's change is gone.

The simulation found two design flaws on its first runs, both fixed:

- Documents signed by unknown keys were stored and spread by every node, so anyone could flood the fleet. Now only verified documents travel (AGT-003).
- weft-verifier reported "revoked" for documents that merely *claimed* a revoked key. Now "revoked" requires a valid signature by that key.

## Run

```sh
nix develop          # or: rustup reads rust-toolchain.toml; needs ../weft-verifier next to this repo
just test            # all tests, 16 simulation seeds
just sim 500         # more seeds
WEFT_SIM_SEED=13 just sim   # replay one seed
just ci              # everything CI checks
```

## Requirements

[requirements/agent.sdoc](requirements/agent.sdoc) (StrictDoc): AGT-001 to AGT-016, each
satisfying system requirements in
[weft-design](https://github.com/theweft/weft-design/blob/main/requirements/system.sdoc) and traced
to functions and tests with `@relation` markers. `cargo test` fails when an active requirement has
no implementation or no test; `just requirements` renders HTML and ReqIF.

## License

MIT, see [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
