// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

/// Stand-in for QoreChain's PQC precompiles (0x…0a01 verify, 0x…0a02 key status) on a local EVM.
/// A local EVM can't run ML-DSA-87, so run.mjs verifies every signature with real ML-DSA-87
/// (noble post-quantum, the same answers as the QoreChain SDK) and records only the tuples it checked.
/// Anything not recorded is invalid: it fails closed. Invoice Leash's Foundry tests use the same
/// approach. On QoreChain itself the precompile does the verification.
contract PqcStandIn {
    mapping(bytes32 => bool) public checked;
    mapping(address => bytes) internal keys;

    function record(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external {
        checked[keccak256(abi.encode(pubkey, signature, message))] = true;
    }
    function setKey(address account, bytes calldata pubkey) external { keys[account] = pubkey; }

    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external view returns (bool) {
        return checked[keccak256(abi.encode(pubkey, signature, message))];
    }
    function pqcKeyStatus(address account) external view returns (bool, uint8, bytes memory, bool) {
        bytes memory k = keys[account];
        return (k.length > 0, 1, k, k.length > 0);
    }
}

/// Minimal 6-decimal ERC-20 for the example (stands in for fUSD).
contract TestUSD {
    string public constant symbol = "tUSD";
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(address to, uint256 amount) { balanceOf[to] = amount; emit Transfer(address(0), to, amount); }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; emit Approval(msg.sender, s, v); return true; }
    function transfer(address to, uint256 v) external returns (bool) { _move(msg.sender, to, v); return true; }
    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        uint256 a = allowance[f][msg.sender];
        require(a >= v, "allowance");
        allowance[f][msg.sender] = a - v;
        _move(f, to, v);
        return true;
    }
    function _move(address f, address to, uint256 v) internal {
        require(balanceOf[f] >= v, "balance");
        balanceOf[f] -= v; balanceOf[to] += v;
        emit Transfer(f, to, v);
    }
}
