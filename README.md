# Execute payload from memory

Encrypts and bundles a payload into a static binary and executes it without `execve()`.

## Building

### Prerequisites

- Python 3.10 or newer
- Meson
- Ninja

```sh
pip install -r requirements.txt
```

### Normal

```sh
# Configure
meson setup builddir --buildtype=release -Dpayload=/path/to/payload -Daes_key=11223344556677889900aabbccddeeff

# Build
meson compile -C builddir

# Run
./builddir/executor
```

### Statically-linked with Musl

```sh
# Configure
CC=musl-gcc meson setup builddir --buildtype=release -Dpayload=/path/to/payload -Daes_key=11223344556677889900aabbccddeeff

# Build
meson compile -C builddir

# Run
./builddir/executor
```
