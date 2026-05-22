"""
Configuration file for the Certificate Verification System
"""

# Flask Secret Key
SECRET_KEY = "your-secret-key-change-in-production"

# Blockchain Configuration
BLOCKCHAIN_URL = "http://127.0.0.1:7545"  # Ganache default URL

# Smart Contract Configuration
# Update these after deploying the smart contract
CONTRACT_ADDRESS = "0x0000000000000000000000000000000000000000"  # Replace with deployed contract address

# Contract ABI - Update after deployment
CONTRACT_ABI = []  # Paste your contract ABI here
