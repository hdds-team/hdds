# Installing hdds_gen

The IDL code generator lives in its own repository,
[hdds_gen](https://git.hdds.io/hdds/hdds_gen.git), and installs a binary named
**`hddsgen`**:

```bash
git clone https://git.hdds.io/hdds/hdds_gen.git
cargo install --path hdds_gen     # installs the `hddsgen` command into ~/.cargo/bin
hddsgen --version                 # must print hddsgen 2.0.0 or later
```

`cargo install` puts the binary in `~/.cargo/bin`. That directory must be on
your `PATH`, or the shell reports `hddsgen: command not found` even though the
install succeeded. Add this line to your shell profile:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

To keep an `hddsgen` that is already installed (for example an older one in
`~/.cargo/bin`), install to another root and call that binary by its full path:

```bash
cargo install --path hdds_gen --root "$HOME/hddsgen-2.0"
"$HOME/hddsgen-2.0/bin/hddsgen" --version
```

HDDS 1.5 expects code from **hddsgen 2.0 or later**. Older generators emit FINAL
instead of APPENDABLE for types without an extensibility annotation,
`std::array` instead of a bounded `std::vector` for `sequence<T, N>` in C++,
and a different alignment of 8-byte members in Python. Use
`--default-extensibility final` to get the FINAL layout from hddsgen 2.0
(see the [CLI reference](cli-reference.md)).

The crates.io package `hdds-gen` is a different tool (`tools/hdds-gen` in this
workspace, a QoS validator); it does not provide `hddsgen`. The crates.io
package `hddsgen` stops at 1.0.12, which is older than HDDS 1.5 expects: install
the generator from the git repository as shown above.
