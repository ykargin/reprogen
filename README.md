# ReproGen

A fast, reproducible file generator for benchmarking and testing.

## Overview

ReproGen is a lightweight C utility designed to generate files with reproducible content. Its primary purpose is to create test files with predictable properties for benchmarking I/O performance, filesystem behavior, or other scenarios where you need consistent test data.

### Key Features

- **Reproducible content**: Files with the same ID always have identical content
- **High-performance**: Optimized for speed with minimal overhead
- **Configurable**: Control file size, quantity, and I/O parameters
- **Multiple content patterns**: Uniform bytes, patterns, random data, or mixed

## Installation

ReproGen is designed to be compiled as a static binary for maximum portability.

### Using Musl (recommended)

```bash
# Install musl compiler if needed
# On Debian/Ubuntu:
apt-get install musl-tools

# Compile with musl
musl-gcc -O2 -Wall -static src/reprogen.c -o reprogen
```

### Alternative: Standard GCC with static linking

```bash
gcc -O2 -Wall -static src/reprogen.c -o reprogen
```

## Usage

```
ReproGen - Reproducible File Generator

USAGE:
  reprogen -d <directory> [OPTIONS]

REQUIRED ARGUMENTS:
  -d, --directory DIR   Directory where files will be created

OPTIONS:
  -s, --size SIZE       Size of each generated file in bytes (default: 32768)
  -n, --number NUM      Number of files to generate (default: 1)
  -i, --id ID           Recreate a specific file by its 12-character ID
  -b, --buffer SIZE     Buffer size for I/O operations (default: 4096)
  -m, --mark-blocks     Mark blocks with identifiers (for debugging)
  -D, --direct          Use O_DIRECT flag for bypassing OS cache
  -S, --sync            Use O_SYNC flag for synchronous writes
  -h, --help            Show this help message
```

## Examples

### Generate a single 1MB file

```bash
./reprogen -d /tmp/test -s 1048576
```

### Generate 10 files of 4KB each

```bash
./reprogen -d /tmp/test -s 4096 -n 10
```

### Recreate a specific file by ID

```bash
./reprogen -d /tmp/test -s 1048576 -i abc123xyz456
```

### Use direct I/O with a large buffer for better performance

```bash
./reprogen -d /tmp/test -s 104857600 -b 1048576 -D
```

## How It Works

1. ReproGen generates a random 12-character file ID (or uses the provided one)
2. The ID is used to seed a deterministic PRNG for content generation
3. Content is generated in chunks based on a chosen pattern type
4. Generated data is written to disk with requested I/O flags

The reproducible nature makes it perfect for:
- Filesystem benchmarking
- Storage I/O testing
- Verification of data integrity
- Creating predictable test datasets

## License

This project is open source and available under the [MIT License](LICENSE).