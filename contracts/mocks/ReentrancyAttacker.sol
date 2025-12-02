// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICircuitBreaker {
    function executeEmergencyWithdrawal(uint256 withdrawalId) external;
    function depositForEmergencyWithdrawal(address token, uint256 amount) external;
    function requestEmergencyWithdrawal(address token, uint256 amount) external returns (uint256);
}

/**
 * @title ReentrancyAttacker
 * @notice Test contract to verify reentrancy protection
 * @dev Attempts to reenter during withdrawal execution
 */
contract ReentrancyAttacker {
    ICircuitBreaker public circuitBreaker;
    uint256 public attackCount;
    uint256 public withdrawalId;

    constructor(address _circuitBreaker) {
        circuitBreaker = ICircuitBreaker(_circuitBreaker);
    }

    function attack() external {
        // This should fail due to reentrancy guard
        circuitBreaker.executeEmergencyWithdrawal(withdrawalId);
    }

    // Fallback to attempt reentrancy
    receive() external payable {
        if (attackCount < 3) {
            attackCount++;
            circuitBreaker.executeEmergencyWithdrawal(withdrawalId);
        }
    }
}
