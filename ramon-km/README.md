# ramon-km

The driver crate. Build from this directory (its `.cargo/config.toml` sets the driver link flags):

```
cargo build
```

The result is `ramon.dll`; `Makefile.toml` (cargo-make) has tasks for renaming it to `ramon.sys`,
signing with a test certificate and running `inf2cat`.

See the repository README for the architecture, the event protocol, the IRQL contracts and the
known limits. This is an example, not a production driver.
