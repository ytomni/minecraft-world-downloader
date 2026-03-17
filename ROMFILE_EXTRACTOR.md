# ROMFILE backup extractor

`romfile_cfg_extractor.py` extracts the `<ROMFILE>...</ROMFILE>` XML block from router backup files (for example `romfile.cfg` exports), including files with extra wrapper bytes or common compression layers.

It also includes detection paths for common ZTE backup container/payload formats used by encrypted/compressed exports.

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
- `--try-all-known-keys`: try bundled known ZTE keys/model guesses
- `--zte-key <key>`: add one explicit ZTE key (repeatable)
- `--model <model>`: add one explicit model for type-3 derive (repeatable)
- `--serial`, `--mac`, `--longpass`, `--signature`: optional inputs for type-4 key derivation paths

## Examples

```bash
# basic extraction
python3 romfile_cfg_extractor.py romfile.cfg

# pretty output
python3 romfile_cfg_extractor.py romfile.cfg --pretty -o config.xml

# if payload is obfuscated/wrapped
python3 romfile_cfg_extractor.py romfile.cfg --try-xor --max-depth 4

# encrypted ZTE-style payloads (broad key scan)
python3 romfile_cfg_extractor.py romfile.cfg --try-all-known-keys --max-depth 4
```

## Notes

- If your backup was copied into chat/text, byte fidelity is usually lost. Always run extraction on the original binary file exported from the router UI.
- Some vendor ROMFILE XML files are not strict XML (non-standard attribute names). The extractor still returns the full ROMFILE block.
- For encrypted payload types, install AES support if needed:

```bash
python3 -m pip install pycryptodomex
```
