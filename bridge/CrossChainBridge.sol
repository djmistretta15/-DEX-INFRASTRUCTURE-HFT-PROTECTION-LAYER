// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * CROSS-CHAIN BRIDGE INFRASTRUCTURE
 *
 * HYPOTHESIS: A secure, multi-validator bridge with fraud proofs and
 * optimistic verification will enable trustless cross-chain transfers
 * with >99.99% security and <10 minute finality.
 *
 * SUCCESS METRICS:
 * - Security incidents: 0 exploits
 * - Transfer success rate: >99.9%
 * - Average finality time: <10 minutes
 * - Validator consensus: 67% threshold
 * - Liquidity utilization: >80%
 *
 * SECURITY CONSIDERATIONS:
 * - Multi-signature validation with threshold
 * - Optimistic fraud proof system
 * - Challenge periods for disputes
 * - Emergency pause mechanisms
 * - Rate limiting per chain
 * - Canonical token registry
 */

// Bridge message structure
struct BridgeMessage {
    uint256 nonce;
    uint256 sourceChain;
    uint256 destChain;
    address sender;
    address recipient;
    address token;
    uint256 amount;
    bytes32 dataHash;
    uint256 timestamp;
}

// Validator information
struct Validator {
    address addr;
    uint256 stake;
    uint256 attestationCount;
    uint256 lastActiveBlock;
    bool isActive;
    uint256 slashCount;
}

// Transfer status
enum TransferStatus {
    PENDING,
    ATTESTED,
    FINALIZED,
    CHALLENGED,
    CANCELLED,
    REFUNDED
}

// Transfer record
struct Transfer {
    bytes32 messageHash;
    BridgeMessage message;
    TransferStatus status;
    uint256 attestationCount;
    mapping(address => bool) attestedBy;
    uint256 challengeDeadline;
    address challenger;
    bytes32 fraudProof;
    uint256 createdAt;
    uint256 finalizedAt;
}

// Liquidity pool
struct LiquidityPool {
    address token;
    uint256 totalLiquidity;
    uint256 availableLiquidity;
    uint256 pendingOutbound;
    uint256 feeRate; // basis points
    mapping(address => uint256) providerShares;
    uint256 totalShares;
}

contract CrossChainBridge is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // Roles
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // Chain ID
    uint256 public immutable chainId;

    // Validators
    mapping(address => Validator) public validators;
    address[] public validatorList;
    uint256 public validatorCount;
    uint256 public requiredAttestations;
    uint256 public minValidatorStake;

    // Transfers
    mapping(bytes32 => Transfer) public transfers;
    mapping(uint256 => uint256) public outboundNonce; // destChain => nonce
    mapping(uint256 => uint256) public inboundNonce; // sourceChain => nonce

    // Liquidity pools
    mapping(address => LiquidityPool) public pools;
    address[] public supportedTokens;

    // Rate limiting
    mapping(uint256 => uint256) public dailyVolume; // day => volume
    mapping(uint256 => mapping(address => uint256)) public userDailyVolume;
    uint256 public maxDailyVolume;
    uint256 public maxUserDailyVolume;

    // Configuration
    uint256 public challengePeriod = 1 hours;
    uint256 public minTransferAmount = 1e15; // 0.001 tokens
    uint256 public maxTransferAmount = 1e24; // 1M tokens
    uint256 public baseFee = 10; // 0.1%

    // Supported chains
    mapping(uint256 => bool) public supportedChains;
    uint256[] public chainList;

    // Canonical tokens (source chain => source token => wrapped token)
    mapping(uint256 => mapping(address => address)) public canonicalTokens;

    // Events
    event TransferInitiated(
        bytes32 indexed messageHash,
        address indexed sender,
        address indexed recipient,
        uint256 sourceChain,
        uint256 destChain,
        address token,
        uint256 amount,
        uint256 nonce
    );

    event TransferAttested(
        bytes32 indexed messageHash,
        address indexed validator,
        uint256 attestationCount,
        uint256 required
    );

    event TransferFinalized(
        bytes32 indexed messageHash,
        address indexed recipient,
        uint256 amount
    );

    event TransferChallenged(
        bytes32 indexed messageHash,
        address indexed challenger,
        bytes32 fraudProof
    );

    event ValidatorAdded(address indexed validator, uint256 stake);
    event ValidatorRemoved(address indexed validator);
    event ValidatorSlashed(address indexed validator, uint256 amount);

    event LiquidityAdded(address indexed provider, address indexed token, uint256 amount);
    event LiquidityRemoved(address indexed provider, address indexed token, uint256 amount);

    event ChainAdded(uint256 indexed chainId);
    event ChainRemoved(uint256 indexed chainId);

    constructor(
        uint256 _chainId,
        uint256 _requiredAttestations,
        uint256 _minValidatorStake
    ) {
        chainId = _chainId;
        requiredAttestations = _requiredAttestations;
        minValidatorStake = _minValidatorStake;

        maxDailyVolume = 100_000_000e18; // 100M per day
        maxUserDailyVolume = 1_000_000e18; // 1M per user per day

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /**
     * Initiate cross-chain transfer
     */
    function initiateTransfer(
        uint256 destChain,
        address recipient,
        address token,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant whenNotPaused returns (bytes32 messageHash) {
        require(supportedChains[destChain], "Unsupported destination chain");
        require(amount >= minTransferAmount, "Amount below minimum");
        require(amount <= maxTransferAmount, "Amount exceeds maximum");
        require(recipient != address(0), "Invalid recipient");

        // Check rate limits
        uint256 today = block.timestamp / 1 days;
        require(
            dailyVolume[today] + amount <= maxDailyVolume,
            "Daily volume limit exceeded"
        );
        require(
            userDailyVolume[today][msg.sender] + amount <= maxUserDailyVolume,
            "User daily limit exceeded"
        );

        // Check liquidity
        LiquidityPool storage pool = pools[token];
        require(pool.totalLiquidity > 0, "Token not supported");
        require(pool.availableLiquidity >= amount, "Insufficient liquidity");

        // Lock tokens
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Calculate fee
        uint256 fee = (amount * (baseFee + pool.feeRate)) / 10000;
        uint256 netAmount = amount - fee;

        // Update liquidity
        pool.pendingOutbound += netAmount;
        pool.availableLiquidity -= netAmount;

        // Create message
        uint256 nonce = outboundNonce[destChain]++;
        BridgeMessage memory message = BridgeMessage({
            nonce: nonce,
            sourceChain: chainId,
            destChain: destChain,
            sender: msg.sender,
            recipient: recipient,
            token: token,
            amount: netAmount,
            dataHash: keccak256(data),
            timestamp: block.timestamp
        });

        messageHash = hashMessage(message);

        // Store transfer
        Transfer storage transfer = transfers[messageHash];
        transfer.messageHash = messageHash;
        transfer.message = message;
        transfer.status = TransferStatus.PENDING;
        transfer.createdAt = block.timestamp;

        // Update rate limits
        dailyVolume[today] += amount;
        userDailyVolume[today][msg.sender] += amount;

        emit TransferInitiated(
            messageHash,
            msg.sender,
            recipient,
            chainId,
            destChain,
            token,
            netAmount,
            nonce
        );

        return messageHash;
    }

    /**
     * Attest to transfer validity (validator only)
     */
    function attestTransfer(
        bytes32 messageHash,
        bytes calldata signature
    ) external onlyRole(VALIDATOR_ROLE) whenNotPaused {
        Transfer storage transfer = transfers[messageHash];
        require(transfer.createdAt > 0, "Transfer not found");
        require(
            transfer.status == TransferStatus.PENDING ||
            transfer.status == TransferStatus.ATTESTED,
            "Invalid transfer status"
        );
        require(!transfer.attestedBy[msg.sender], "Already attested");

        // Verify signature
        address signer = messageHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signature");

        // Verify validator
        Validator storage validator = validators[msg.sender];
        require(validator.isActive, "Validator not active");
        require(validator.stake >= minValidatorStake, "Insufficient stake");

        // Record attestation
        transfer.attestedBy[msg.sender] = true;
        transfer.attestationCount++;
        validator.attestationCount++;
        validator.lastActiveBlock = block.number;

        emit TransferAttested(
            messageHash,
            msg.sender,
            transfer.attestationCount,
            requiredAttestations
        );

        // Check if enough attestations
        if (transfer.attestationCount >= requiredAttestations) {
            transfer.status = TransferStatus.ATTESTED;
            transfer.challengeDeadline = block.timestamp + challengePeriod;
        }
    }

    /**
     * Finalize transfer after challenge period
     */
    function finalizeTransfer(bytes32 messageHash) external nonReentrant whenNotPaused {
        Transfer storage transfer = transfers[messageHash];
        require(transfer.status == TransferStatus.ATTESTED, "Not ready for finalization");
        require(
            block.timestamp >= transfer.challengeDeadline,
            "Challenge period not ended"
        );

        transfer.status = TransferStatus.FINALIZED;
        transfer.finalizedAt = block.timestamp;

        BridgeMessage memory message = transfer.message;

        // Release tokens on destination
        if (message.destChain == chainId) {
            // This is the destination chain
            address destToken = canonicalTokens[message.sourceChain][message.token];
            if (destToken == address(0)) {
                destToken = message.token; // Native token
            }

            LiquidityPool storage pool = pools[destToken];
            require(pool.availableLiquidity >= message.amount, "Insufficient liquidity");

            pool.availableLiquidity -= message.amount;
            IERC20(destToken).safeTransfer(message.recipient, message.amount);

            emit TransferFinalized(messageHash, message.recipient, message.amount);
        }
    }

    /**
     * Challenge fraudulent transfer
     */
    function challengeTransfer(
        bytes32 messageHash,
        bytes32 fraudProof
    ) external nonReentrant {
        Transfer storage transfer = transfers[messageHash];
        require(
            transfer.status == TransferStatus.ATTESTED,
            "Cannot challenge"
        );
        require(
            block.timestamp < transfer.challengeDeadline,
            "Challenge period ended"
        );

        // Verify fraud proof (simplified - real implementation would verify Merkle proof)
        require(fraudProof != bytes32(0), "Invalid fraud proof");

        transfer.status = TransferStatus.CHALLENGED;
        transfer.challenger = msg.sender;
        transfer.fraudProof = fraudProof;

        // Slash validators who attested
        for (uint256 i = 0; i < validatorList.length; i++) {
            address validatorAddr = validatorList[i];
            if (transfer.attestedBy[validatorAddr]) {
                _slashValidator(validatorAddr);
            }
        }

        emit TransferChallenged(messageHash, msg.sender, fraudProof);
    }

    /**
     * Add validator
     */
    function addValidator(
        address validatorAddr
    ) external payable onlyRole(GUARDIAN_ROLE) {
        require(!validators[validatorAddr].isActive, "Already a validator");
        require(msg.value >= minValidatorStake, "Insufficient stake");

        validators[validatorAddr] = Validator({
            addr: validatorAddr,
            stake: msg.value,
            attestationCount: 0,
            lastActiveBlock: block.number,
            isActive: true,
            slashCount: 0
        });

        validatorList.push(validatorAddr);
        validatorCount++;

        _grantRole(VALIDATOR_ROLE, validatorAddr);

        emit ValidatorAdded(validatorAddr, msg.value);
    }

    /**
     * Remove validator
     */
    function removeValidator(address validatorAddr) external onlyRole(GUARDIAN_ROLE) {
        Validator storage validator = validators[validatorAddr];
        require(validator.isActive, "Not a validator");

        validator.isActive = false;
        validatorCount--;

        // Return stake
        uint256 stake = validator.stake;
        validator.stake = 0;
        payable(validatorAddr).transfer(stake);

        _revokeRole(VALIDATOR_ROLE, validatorAddr);

        emit ValidatorRemoved(validatorAddr);
    }

    /**
     * Add liquidity to pool
     */
    function addLiquidity(
        address token,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        require(amount > 0, "Amount must be positive");

        LiquidityPool storage pool = pools[token];
        if (pool.totalLiquidity == 0) {
            // Initialize pool
            pool.token = token;
            pool.feeRate = 5; // 0.05%
            supportedTokens.push(token);
        }

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Calculate shares
        uint256 shares;
        if (pool.totalShares == 0) {
            shares = amount;
        } else {
            shares = (amount * pool.totalShares) / pool.totalLiquidity;
        }

        pool.providerShares[msg.sender] += shares;
        pool.totalShares += shares;
        pool.totalLiquidity += amount;
        pool.availableLiquidity += amount;

        emit LiquidityAdded(msg.sender, token, amount);
    }

    /**
     * Remove liquidity from pool
     */
    function removeLiquidity(
        address token,
        uint256 shares
    ) external nonReentrant {
        LiquidityPool storage pool = pools[token];
        require(pool.providerShares[msg.sender] >= shares, "Insufficient shares");

        uint256 amount = (shares * pool.totalLiquidity) / pool.totalShares;
        require(pool.availableLiquidity >= amount, "Insufficient available liquidity");

        pool.providerShares[msg.sender] -= shares;
        pool.totalShares -= shares;
        pool.totalLiquidity -= amount;
        pool.availableLiquidity -= amount;

        IERC20(token).safeTransfer(msg.sender, amount);

        emit LiquidityRemoved(msg.sender, token, amount);
    }

    /**
     * Add supported chain
     */
    function addChain(uint256 _chainId) external onlyRole(OPERATOR_ROLE) {
        require(!supportedChains[_chainId], "Chain already supported");
        supportedChains[_chainId] = true;
        chainList.push(_chainId);
        emit ChainAdded(_chainId);
    }

    /**
     * Remove supported chain
     */
    function removeChain(uint256 _chainId) external onlyRole(GUARDIAN_ROLE) {
        require(supportedChains[_chainId], "Chain not supported");
        supportedChains[_chainId] = false;
        emit ChainRemoved(_chainId);
    }

    /**
     * Set canonical token mapping
     */
    function setCanonicalToken(
        uint256 sourceChain,
        address sourceToken,
        address wrappedToken
    ) external onlyRole(OPERATOR_ROLE) {
        canonicalTokens[sourceChain][sourceToken] = wrappedToken;
    }

    /**
     * Update configuration
     */
    function updateConfig(
        uint256 _challengePeriod,
        uint256 _minTransferAmount,
        uint256 _maxTransferAmount,
        uint256 _baseFee
    ) external onlyRole(GUARDIAN_ROLE) {
        challengePeriod = _challengePeriod;
        minTransferAmount = _minTransferAmount;
        maxTransferAmount = _maxTransferAmount;
        baseFee = _baseFee;
    }

    /**
     * Emergency pause
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * Unpause
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /**
     * Get pool information
     */
    function getPoolInfo(address token) external view returns (
        uint256 totalLiquidity,
        uint256 availableLiquidity,
        uint256 pendingOutbound,
        uint256 feeRate,
        uint256 totalShares
    ) {
        LiquidityPool storage pool = pools[token];
        return (
            pool.totalLiquidity,
            pool.availableLiquidity,
            pool.pendingOutbound,
            pool.feeRate,
            pool.totalShares
        );
    }

    /**
     * Get transfer information
     */
    function getTransferInfo(bytes32 messageHash) external view returns (
        TransferStatus status,
        uint256 attestationCount,
        uint256 challengeDeadline,
        address challenger,
        uint256 createdAt,
        uint256 finalizedAt
    ) {
        Transfer storage transfer = transfers[messageHash];
        return (
            transfer.status,
            transfer.attestationCount,
            transfer.challengeDeadline,
            transfer.challenger,
            transfer.createdAt,
            transfer.finalizedAt
        );
    }

    /**
     * Check if validator attested
     */
    function hasAttested(
        bytes32 messageHash,
        address validator
    ) external view returns (bool) {
        return transfers[messageHash].attestedBy[validator];
    }

    /**
     * Get user liquidity shares
     */
    function getUserShares(
        address token,
        address user
    ) external view returns (uint256) {
        return pools[token].providerShares[user];
    }

    /**
     * Calculate withdrawal amount
     */
    function calculateWithdrawalAmount(
        address token,
        uint256 shares
    ) external view returns (uint256) {
        LiquidityPool storage pool = pools[token];
        if (pool.totalShares == 0) return 0;
        return (shares * pool.totalLiquidity) / pool.totalShares;
    }

    /**
     * Hash bridge message
     */
    function hashMessage(BridgeMessage memory message) public pure returns (bytes32) {
        return keccak256(abi.encode(
            message.nonce,
            message.sourceChain,
            message.destChain,
            message.sender,
            message.recipient,
            message.token,
            message.amount,
            message.dataHash,
            message.timestamp
        ));
    }

    /**
     * Internal: Slash validator
     */
    function _slashValidator(address validatorAddr) internal {
        Validator storage validator = validators[validatorAddr];
        uint256 slashAmount = validator.stake / 10; // 10% slash

        validator.stake -= slashAmount;
        validator.slashCount++;

        if (validator.stake < minValidatorStake) {
            validator.isActive = false;
            validatorCount--;
            _revokeRole(VALIDATOR_ROLE, validatorAddr);
        }

        emit ValidatorSlashed(validatorAddr, slashAmount);
    }
}
