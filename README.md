# Execute payload from memory

Bundles and encrypts a payload into a static binary. The unencrypted payload will never touch disk.

## Building

### Normal

```sh
# Configure
meson setup builddir --buildtype=release -Dpayload=/path/to/payload

# Build
meson compile -C builddir

# Run
./builddir/executor
```

### Statically-linked with Musl

```sh
# Configure
CC=musl-gcc meson setup builddir --buildtype=release -Dstatic=true -Dpayload=/path/to/payload

# Build
meson compile -C builddir

# Run
./builddir/executor
```
