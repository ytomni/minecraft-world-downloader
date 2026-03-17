# ROMFILE backup extractor

`romfile_cfg_extractor.py` extracts the `<ROMFILE>...</ROMFILE>` XML block from router backup files (for example `romfile.cfg` exports), including files with extra wrapper bytes or common compression layers.

## Legal / scope

Use this only on devices you own or are explicitly authorized to administer.

## Usage

```bash
python3 romfile_cfg_extractor.py /path/to/romfile.cfg
```

By default, output is written to:

```
/path/to/romfile.cfg.xml
```

### Options

- `-o, --output <path>`: write XML to a custom path
- `--pretty`: pretty-print XML output
- `--max-depth <n>`: increase nested decode attempts (default `2`)
- `--try-xor`: try single-byte XOR sweep for obfuscated backups (slower)

## Examples

```bash
# basic extraction
python3 romfile_cfg_extractor.py romfile.cfg

# pretty output
python3 romfile_cfg_extractor.py romfile.cfg --pretty -o config.xml

# if payload is obfuscated/wrapped
python3 romfile_cfg_extractor.py romfile.cfg --try-xor --max-depth 4
```
