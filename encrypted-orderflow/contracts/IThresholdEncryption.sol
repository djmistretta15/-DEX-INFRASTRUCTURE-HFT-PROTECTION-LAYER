// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IThresholdEncryption
 * @notice Interface for threshold encryption oracle
 * @dev Implements timelock encryption using distributed key generation
 */
interface IThresholdEncryption {

    /**
     * @notice Verify decryption proof and return plaintext
     * @param ciphertext Encrypted order data
     * @param proof Zero-knowledge proof of correct decryption
     * @return plaintext Decrypted order data
     */
    function verifyAndDecrypt(
        bytes calldata ciphertext,
        bytes calldata proof
    ) external view returns (bytes memory plaintext);

    /**
     * @notice Get current encryption public key for the epoch
     */
    function getCurrentPublicKey() external view returns (bytes memory);

    /**
     * @notice Verify that decryption happened after timelock
     */
    function verifyTimelock(uint256 timestamp) external view returns (bool);
}
