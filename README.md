# srec_bytearray

A Python library for reading, manipulating and writing Motorola S-Record files
using native `bytearray` objects.

## Overview

This library models S-Record files at three levels of abstraction:

- **SRec** -- A single S-Record line (type, address, data, checksum).
- **SRecSector** -- A contiguous block of `SRec` entries sharing an address range.
- **SRecFile** -- A complete `.s19` / `.srec` file composed of headers, data sectors and footers.

It also provides a command pattern (`SRecCmd`, `SRecFileInvoker`) for
undoable patch and remap operations, and an `SRecFileHandler` for higher-level
features like hex dumps.

## Supported S-Record types

| Type | Purpose         | Address length |
|------|-----------------|----------------|
| S0   | Header          | 2 bytes        |
| S1   | Data            | 2 bytes        |
| S2   | Data            | 3 bytes        |
| S3   | Data            | 4 bytes        |
| S5   | Record count    | 2 bytes        |
| S7   | End (S3 match)  | 4 bytes        |
| S8   | End (S2 match)  | 3 bytes        |
| S9   | End (S1 match)  | 2 bytes        |

## Installation

```bash
pip install git+https://github.com/RlVlZ/SRec_bytearray.git
```

Requires Python 3.10 or later.

## Usage

### Read an S-Record file

```python
from srec_bytearray import SRecFile

sf = SRecFile()
sf.read_file("firmware.s19")
print(sf.sectors_infos())
```

### Patch bytes at an address

```python
sf.patch(0x80001000, bytearray([0xDE, 0xAD, 0xBE, 0xEF]))
```

### Check if an address is in the file

```python
if 0x80001000 in sf:
    print("Address is within the loaded data")
```

### Read data back

```python
data = sf.get_data(0x80001000, 4)
print(data.hex())
```

### Remap a sector to a new base address

```python
sf.remap_sector(0, 0x90000000)
```

### Write the modified file

```python
with open("patched.s19", "w") as f:
    for hdr in sf.headers:
        f.write(str(hdr) + "\n")
    for sector in sf.sectors:
        for srec in sector:
            f.write(str(srec) + "\n")
    for ftr in sf.footers:
        f.write(str(ftr) + "\n")
```

### Undoable operations with the command pattern

```python
from srec_bytearray import SRecFileInvoker, SRecFPatchCmd

invoker = SRecFileInvoker()
cmd = SRecFPatchCmd(sf, 0x80001000, bytearray([0x42]))
invoker.execute(cmd)
invoker.undo_last()
```

## License

MIT
