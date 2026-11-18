# Examples

## Policy files

- [`dev.toml`](dev.toml) - the development preset used by the README quick start.
  More room to work, still no network, `exec_on_write = true` for compile-and-run.
- [`network-allowlist.toml`](network-allowlist.toml) - **not runnable**. Documents
  the designed-but-unimplemented allowlist mode. Carapace refuses it before any
  code runs (fail closed).

## Runnable code

The library quick-start lives in the crate, not here:

```sh
cargo run -p carapace-native --example hello_sandbox
```

Other examples in the same place:

```sh
cargo run -p carapace-native --example bench      # cold-start measurement
cargo run -p carapace-escape-tests --example gen_table
```

All examples require a Tier 1 ready host (`cara doctor`). On WSL2, run them
from inside the systemd user slice; `scripts/check.sh` shows the bridge.

## Product demo

`demo/demo.sh` runs the escape scenarios through the real `cara` CLI:

```sh
CARA=/path/to/cara demo/demo.sh
DEMO_DRY_RUN=1 demo/demo.sh   # print commands, execute nothing
```

The demo self-bridges into the user slice on WSL2 and prints a summary of
which scenarios held.
