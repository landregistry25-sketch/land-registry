import json
from web3 import Web3

# Connect to Ganache local blockchain
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))


if not w3.is_connected():
    raise Exception("Failed to connect to Ganache")

print("Connected to Ganache")

# Use one of Ganache's pre-funded accounts (private key)
private_key = 0x64f59e37b026084066f8e14ad5bd8179bf2a7335cc020504efa51f38be3b5300

account = w3.eth.account.from_key(private_key)
address = account.address

with open('compiled_contract.json') as f:
    compiled_sol = json.load(f)

abi = compiled_sol['contracts']['LandRegistry.sol']['LandRegistry']['abi']
bytecode = compiled_sol['contracts']['LandRegistry.sol']['LandRegistry']['evm']['bytecode']['object']

LandRegistry = w3.eth.contract(abi=abi, bytecode=bytecode)

nonce = w3.eth.get_transaction_count(address)
transaction = LandRegistry.constructor().build_transaction({
    'chainId': 1337,  # Ganache default chain id
    'gas': 3000000,
    'gasPrice': w3.to_wei('20', 'gwei'),
    'nonce': nonce
})

signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

print(f"Deploying contract, transaction hash: {tx_hash.hex()}")

tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Contract successfully deployed at: {tx_receipt.contractAddress}")
