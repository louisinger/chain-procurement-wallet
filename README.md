# chain-procurement-wallet

## Install

```bash
./scripts/install-deps.sh
```

WARNING: You need to enter a command after the script execution. Just copy and past the command prompted at the end of `install_deps.sh` output.

## Build

```bash
./scripts/build.sh
```

The target folder is `build`.

## Generate a new confidential address

Adrr only work for REGTEST.

```bash
./build/Main '{"mnemonic": "enact luggage write fuel sing drama soccer reason million upper tilt glimpse safe sweet govern error utility candy manage fish bring twenty funny grape", "depth": 2}'
```

The command above will generate the confidential address (and the non-confidential one) with a depth of 2 (deterministic key generation). It needs a 24 words mnemonic sentence.

Result:
```
{
 "address" : "2dhPLwXL2MRXUUNkv4bkoggXQ54yaTPPnJJ",
 "confidentialAddress" : "CTEmQkNZeQAKuLTKUKBYuDMyUrBc7oDNSLqHwsxBuQeyFj3oPvtmSEpsDqLFYWmfCtrUGZtfCohCSjMa"
}

```
