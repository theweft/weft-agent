<h1><img src="https://theweft.org/brand/repos/weft-agent.svg" alt="" width="44" height="44" align="absmiddle"> weft-agent</h1>

> **Status: experimental (0.0.x).** First milestone: document sync and decisions, tested in a
> deterministic simulation. No real transports, no executor backends, no process separation yet.
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

## Crates

| Crate | Contents |
|---|---|
| [`weft-transport`](crates/weft-transport) | Transport contract (best-effort publish/subscribe, portable topic keys) and a turmoil adapter for simulations |
| [`weft-sync`](crates/weft-sync) | Document sync without I/O: content-addressed store, push plus anti-entropy pull, pending vs. shared, quarantine, limits |
| [`weft-decider`](crates/weft-decider) | Runs `weft_verifier::step`, saves the state **before** acting, drives the executor, classifies documents for sync |
| [`weft-agent`](crates/weft-agent) | Node runtime that ties them together; the simulation and the requirements gate live in its tests |

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

[requirements/agent.sdoc](requirements/agent.sdoc) (StrictDoc): AGT-001 to AGT-009, each
satisfying system requirements in
[weft-design](https://github.com/theweft/weft-design/blob/main/requirements/system.sdoc) and traced
to functions and tests with `@relation` markers. `cargo test` fails when an active requirement has
no implementation or no test; `just requirements` renders HTML and ReqIF.

## License

MIT, see [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
