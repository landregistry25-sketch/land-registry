from solcx import install_solc, compile_standard, get_installed_solc_versions
import json
import os

# Desired Solidity compiler version
SOLC_VERSION = '0.8.0'

# Install compiler if not installed
if SOLC_VERSION not in get_installed_solc_versions():
    print(f"Installing Solidity compiler {SOLC_VERSION}...")
    install_solc(SOLC_VERSION)
else:
    print(f"Solidity compiler {SOLC_VERSION} already installed.")

# Read Solidity contract source
contract_path = os.path.join(os.getcwd(), 'LandRegistry.sol')
with open(contract_path, 'r') as f:
    source = f.read()

# Compile the contract
compiled_sol = compile_standard({
    "language": "Solidity",
    "sources": {
        "LandRegistry.sol": {
            "content": source
        }
    },
    "settings": {
        "outputSelection": {
            "*": {
                "*": ["abi", "evm.bytecode"]
            }
        }
    }
}, solc_version=SOLC_VERSION)

# Print error messages (if any)
if 'errors' in compiled_sol:
    for error in compiled_sol['errors']:
        print(error['formattedMessage'])

# Save compiled contract JSON to file
output_path = os.path.join(os.getcwd(), 'compiled_contract.json')
with open(output_path, 'w') as f:
    json.dump(compiled_sol, f)

print("Compilation completed successfully.")
