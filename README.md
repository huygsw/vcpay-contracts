# VCPay Contracts

Smart contracts for the VCPay project - a multi-signature wallet implementation with EIP-712 typed data signing.

## Overview

This repository contains **GSWSafeV1**, a production-grade multi-signature wallet contract featuring:

- **M-of-N Multisig**: Configurable threshold signature requirements
- **EIP-712 Signing**: Typed data signatures for improved security and UX
- **Token Support**: Native ETH, ERC20, ERC721, and ERC1155
- **Replay Protection**: Nonce-based transaction invalidation
- **Reentrancy Guard**: Protection against reentrancy attacks
- **Signature Malleability Protection**: Lower-S enforcement on secp256k1 curve

## Contracts

| Contract | Description |
|----------|-------------|
| `GSWSafeV1.sol` | Main multi-signature wallet contract |
| `tests/Counter.sol` | Test helper for calldata execution |
| `tests/MockERC20.sol` | Test helper for token transfers |
| `tests/Reenter.sol` | Test helper for reentrancy testing |
| `tests/FailingContract.sol` | Test helper for error handling |

## Prerequisites

- Node.js >= 16
- npm or yarn

## Installation

```bash
npm install
```

## Development

### Compile Contracts

```bash
npx hardhat compile
```

### Run Tests

```bash
npm t
```

### Run Tests with Coverage

```bash
npm run test:coverage
```

### Lint Contracts

```bash
npm run lint
```

## Project Structure

```
vcpay-contracts/
├── contracts/
│   ├── GSWSafeV1.sol              # Main multisig contract
│   └── tests/                     # Test helper contracts
├── tests/
│   └── GSWSafe.test.js            # Comprehensive test suite
├── scripts/                       # Deployment scripts
├── hardhat.config.js              # Hardhat configuration
├── .solhint.json                  # Solidity linting rules
├── .solcover.js                   # Coverage configuration
└── .env.example                   # Environment variables template
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required variables:
- `PRIVATE_KEY` - Deployment wallet private key
- `BSCAN_API_KEY` - BSCScan API key for verification
- `QUICK_NODE_HTTP_PROVIDER_URL` - RPC endpoint

### Supported Networks

- BSC Mainnet (`bsc`)
- BSC Testnet (`bscTestnet`)

## Deployment

### Deploy to BSC

```bash
npm run run-script:bsc
```

### Verify on BSCScan

```bash
npm run verify-script:bsc
```

## Contract Features

### GSWSafeV1

#### Execution Methods
- `execute()` - Execute transaction, returns success status
- `executeStrict()` - Execute transaction, reverts on failure

#### Administrative Functions
- `setExecutor()` - Change the executor address
- `addOwner()` - Add new owner with optional threshold adjustment
- `removeOwner()` - Remove owner with threshold adjustment
- `setThreshold()` - Update signature requirement
- `cancelNonce()` - Invalidate pending transactions

#### Security Features
- Maximum deadline duration: 30 days
- Sorted signature validation (prevents duplicate signers)
- Shared nonce between execute and admin functions
- Self-call prevention

## Dependencies

- **Hardhat** - Development framework
- **OpenZeppelin Contracts** - Standard library (v5.0.1)
- **Safe Contracts** - Gnosis Safe integration
- **Ethers.js** - Ethereum library
- **Solidity Coverage** - Code coverage tool

## License

ISC

## Author

Huy Tran
