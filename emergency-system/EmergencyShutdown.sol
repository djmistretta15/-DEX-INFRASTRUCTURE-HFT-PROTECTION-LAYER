// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * EMERGENCY SHUTDOWN SYSTEM
 *
 * HYPOTHESIS: A multi-layered emergency shutdown system with graduated
 * responses and automatic recovery will protect user funds while minimizing
 * false positives to <0.01% and enabling 99.9% uptime.
 *
 * SUCCESS METRICS:
 * - False positive rate: <0.01%
 * - Response time: <1 block for critical issues
 * - Fund protection: 100% in emergency scenarios
 * - System uptime: >99.9%
 * - Recovery time: <1 hour for non-critical events
 *
 * SECURITY CONSIDERATIONS:
 * - Multi-sig guardian approval
 * - Graduated shutdown levels
 * - Automated threat detection
 * - Safe fund withdrawal paths
 * - Decentralized control
 */

// Emergency level
enum EmergencyLevel {
    NORMAL,         // System operating normally
    CAUTION,        // Monitoring increased, some features limited
    WARNING,        // New positions disabled, withdrawals slowed
    CRITICAL,       // Trading halted, only withdrawals allowed
    SHUTDOWN        // Complete system halt, emergency withdrawals only
}

// Shutdown reason
enum ShutdownReason {
    NONE,
    ORACLE_FAILURE,
    LIQUIDITY_CRISIS,
    EXPLOIT_DETECTED,
    GOVERNANCE_DECISION,
    MARKET_MANIPULATION,
    SMART_CONTRACT_BUG,
    EXTERNAL_ATTACK,
    REGULATORY_COMPLIANCE,
    SCHEDULED_MAINTENANCE
}

// Guardian vote
struct GuardianVote {
    address guardian;
    EmergencyLevel proposedLevel;
    ShutdownReason reason;
    uint256 timestamp;
    bool executed;
}

// System state snapshot
struct SystemSnapshot {
    uint256 snapshotId;
    uint256 blockNumber;
    uint256 timestamp;
    EmergencyLevel level;
    uint256 totalValueLocked;
    uint256 openPositions;
    uint256 pendingWithdrawals;
    bytes32 stateRoot;
}

// Recovery plan
struct RecoveryPlan {
    uint256 planId;
    EmergencyLevel fromLevel;
    EmergencyLevel toLevel;
    uint256 proposedAt;
    uint256 executionTime;
    uint256 approvals;
    uint256 requiredApprovals;
    bool executed;
    address proposer;
    string description;
}

// Withdrawal queue entry
struct WithdrawalRequest {
    address user;
    address token;
    uint256 amount;
    uint256 requestTime;
    uint256 processAfter;
    bool processed;
}

contract EmergencyShutdown is ReentrancyGuard, Pausable, AccessControl {

    // Roles
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MONITOR_ROLE = keccak256("MONITOR_ROLE");

    // Current state
    EmergencyLevel public currentLevel = EmergencyLevel.NORMAL;
    ShutdownReason public currentReason = ShutdownReason.NONE;
    uint256 public lastLevelChange;

    // Guardians
    address[] public guardians;
    uint256 public requiredGuardians;
    mapping(bytes32 => mapping(address => bool)) public guardianApprovals;

    // Votes
    mapping(uint256 => GuardianVote) public votes;
    uint256 public voteCount;

    // System snapshots
    mapping(uint256 => SystemSnapshot) public snapshots;
    uint256 public snapshotCount;
    uint256 public lastSnapshotBlock;

    // Recovery plans
    mapping(uint256 => RecoveryPlan) public recoveryPlans;
    uint256 public recoveryPlanCount;

    // Withdrawal queue
    WithdrawalRequest[] public withdrawalQueue;
    uint256 public processedWithdrawals;

    // Configuration by level
    mapping(EmergencyLevel => uint256) public withdrawalDelays;
    mapping(EmergencyLevel => uint256) public maxWithdrawalAmount;
    mapping(EmergencyLevel => bool) public newPositionsAllowed;
    mapping(EmergencyLevel => bool) public tradingAllowed;

    // Circuit breakers
    uint256 public maxPriceDeviation = 2000; // 20%
    uint256 public maxVolumeSpike = 10000; // 10x normal
    uint256 public minLiquidityThreshold;
    uint256 public oracleHeartbeatTimeout = 3600; // 1 hour

    // Monitoring
    uint256 public lastOracleUpdate;
    uint256 public lastVolumeCheck;
    uint256 public currentVolume;
    uint256 public baselineVolume;

    // Cooldown periods
    uint256 public escalationCooldown = 300; // 5 minutes
    uint256 public deescalationCooldown = 3600; // 1 hour
    uint256 public lastEscalation;

    // Events
    event EmergencyLevelChanged(
        EmergencyLevel oldLevel,
        EmergencyLevel newLevel,
        ShutdownReason reason,
        address initiator
    );

    event GuardianVoteSubmitted(
        address indexed guardian,
        EmergencyLevel proposedLevel,
        ShutdownReason reason,
        uint256 voteId
    );

    event SystemSnapshotTaken(
        uint256 indexed snapshotId,
        uint256 blockNumber,
        EmergencyLevel level
    );

    event RecoveryPlanProposed(
        uint256 indexed planId,
        EmergencyLevel fromLevel,
        EmergencyLevel toLevel,
        address proposer
    );

    event RecoveryPlanExecuted(uint256 indexed planId);

    event WithdrawalQueued(
        address indexed user,
        address indexed token,
        uint256 amount,
        uint256 processAfter
    );

    event WithdrawalProcessed(
        address indexed user,
        address indexed token,
        uint256 amount
    );

    event CircuitBreakerTriggered(string reason, uint256 value, uint256 threshold);

    constructor(address[] memory _guardians, uint256 _requiredGuardians) {
        require(_guardians.length >= _requiredGuardians, "Invalid guardian count");
        require(_requiredGuardians > 0, "Need at least 1 guardian");

        guardians = _guardians;
        requiredGuardians = _requiredGuardians;

        for (uint256 i = 0; i < _guardians.length; i++) {
            _grantRole(GUARDIAN_ROLE, _guardians[i]);
        }

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(MONITOR_ROLE, msg.sender);

        // Initialize level configurations
        _initializeLevelConfigs();

        lastLevelChange = block.timestamp;
    }

    function _initializeLevelConfigs() internal {
        // NORMAL
        withdrawalDelays[EmergencyLevel.NORMAL] = 0;
        maxWithdrawalAmount[EmergencyLevel.NORMAL] = type(uint256).max;
        newPositionsAllowed[EmergencyLevel.NORMAL] = true;
        tradingAllowed[EmergencyLevel.NORMAL] = true;

        // CAUTION
        withdrawalDelays[EmergencyLevel.CAUTION] = 300; // 5 minutes
        maxWithdrawalAmount[EmergencyLevel.CAUTION] = 100000 ether; // $100k
        newPositionsAllowed[EmergencyLevel.CAUTION] = true;
        tradingAllowed[EmergencyLevel.CAUTION] = true;

        // WARNING
        withdrawalDelays[EmergencyLevel.WARNING] = 3600; // 1 hour
        maxWithdrawalAmount[EmergencyLevel.WARNING] = 10000 ether; // $10k
        newPositionsAllowed[EmergencyLevel.WARNING] = false;
        tradingAllowed[EmergencyLevel.WARNING] = true;

        // CRITICAL
        withdrawalDelays[EmergencyLevel.CRITICAL] = 7200; // 2 hours
        maxWithdrawalAmount[EmergencyLevel.CRITICAL] = 1000 ether; // $1k
        newPositionsAllowed[EmergencyLevel.CRITICAL] = false;
        tradingAllowed[EmergencyLevel.CRITICAL] = false;

        // SHUTDOWN
        withdrawalDelays[EmergencyLevel.SHUTDOWN] = 86400; // 24 hours
        maxWithdrawalAmount[EmergencyLevel.SHUTDOWN] = 100 ether; // $100
        newPositionsAllowed[EmergencyLevel.SHUTDOWN] = false;
        tradingAllowed[EmergencyLevel.SHUTDOWN] = false;
    }

    /**
     * Submit guardian vote for emergency level
     */
    function submitGuardianVote(
        EmergencyLevel proposedLevel,
        ShutdownReason reason
    ) external onlyRole(GUARDIAN_ROLE) returns (uint256) {
        require(proposedLevel != currentLevel, "Already at this level");

        // Check cooldown for escalation
        if (uint256(proposedLevel) > uint256(currentLevel)) {
            require(
                block.timestamp >= lastEscalation + escalationCooldown,
                "Escalation cooldown"
            );
        }

        voteCount++;
        votes[voteCount] = GuardianVote({
            guardian: msg.sender,
            proposedLevel: proposedLevel,
            reason: reason,
            timestamp: block.timestamp,
            executed: false
        });

        emit GuardianVoteSubmitted(msg.sender, proposedLevel, reason, voteCount);

        // Check if enough votes to execute
        _checkAndExecuteVote(proposedLevel, reason);

        return voteCount;
    }

    /**
     * Approve guardian vote
     */
    function approveVote(uint256 voteId) external onlyRole(GUARDIAN_ROLE) {
        GuardianVote storage vote = votes[voteId];
        require(!vote.executed, "Already executed");
        require(vote.timestamp > 0, "Vote not found");

        bytes32 voteHash = keccak256(abi.encode(voteId, vote.proposedLevel, vote.reason));
        require(!guardianApprovals[voteHash][msg.sender], "Already approved");

        guardianApprovals[voteHash][msg.sender] = true;

        _checkAndExecuteVote(vote.proposedLevel, vote.reason);
    }

    /**
     * Trigger automatic circuit breaker
     */
    function triggerCircuitBreaker(
        string calldata reason,
        uint256 value,
        uint256 threshold
    ) external onlyRole(MONITOR_ROLE) {
        emit CircuitBreakerTriggered(reason, value, threshold);

        // Automatically escalate based on severity
        if (keccak256(bytes(reason)) == keccak256("ORACLE_FAILURE")) {
            if (currentLevel < EmergencyLevel.CRITICAL) {
                _setEmergencyLevel(EmergencyLevel.CRITICAL, ShutdownReason.ORACLE_FAILURE);
            }
        } else if (keccak256(bytes(reason)) == keccak256("EXPLOIT_DETECTED")) {
            _setEmergencyLevel(EmergencyLevel.SHUTDOWN, ShutdownReason.EXPLOIT_DETECTED);
        } else if (keccak256(bytes(reason)) == keccak256("LIQUIDITY_CRISIS")) {
            if (currentLevel < EmergencyLevel.WARNING) {
                _setEmergencyLevel(EmergencyLevel.WARNING, ShutdownReason.LIQUIDITY_CRISIS);
            }
        }
    }

    /**
     * Take system snapshot
     */
    function takeSnapshot(
        uint256 totalValueLocked,
        uint256 openPositions,
        uint256 pendingWithdrawals,
        bytes32 stateRoot
    ) external onlyRole(OPERATOR_ROLE) {
        require(block.number > lastSnapshotBlock, "Already snapshotted this block");

        snapshotCount++;
        snapshots[snapshotCount] = SystemSnapshot({
            snapshotId: snapshotCount,
            blockNumber: block.number,
            timestamp: block.timestamp,
            level: currentLevel,
            totalValueLocked: totalValueLocked,
            openPositions: openPositions,
            pendingWithdrawals: pendingWithdrawals,
            stateRoot: stateRoot
        });

        lastSnapshotBlock = block.number;

        emit SystemSnapshotTaken(snapshotCount, block.number, currentLevel);
    }

    /**
     * Propose recovery plan
     */
    function proposeRecoveryPlan(
        EmergencyLevel toLevel,
        uint256 executionDelay,
        string calldata description
    ) external onlyRole(GUARDIAN_ROLE) returns (uint256) {
        require(uint256(toLevel) < uint256(currentLevel), "Can only de-escalate");
        require(
            block.timestamp >= lastLevelChange + deescalationCooldown,
            "De-escalation cooldown"
        );

        recoveryPlanCount++;
        recoveryPlans[recoveryPlanCount] = RecoveryPlan({
            planId: recoveryPlanCount,
            fromLevel: currentLevel,
            toLevel: toLevel,
            proposedAt: block.timestamp,
            executionTime: block.timestamp + executionDelay,
            approvals: 1,
            requiredApprovals: requiredGuardians,
            executed: false,
            proposer: msg.sender,
            description: description
        });

        emit RecoveryPlanProposed(recoveryPlanCount, currentLevel, toLevel, msg.sender);

        return recoveryPlanCount;
    }

    /**
     * Approve recovery plan
     */
    function approveRecoveryPlan(uint256 planId) external onlyRole(GUARDIAN_ROLE) {
        RecoveryPlan storage plan = recoveryPlans[planId];
        require(!plan.executed, "Already executed");
        require(plan.proposedAt > 0, "Plan not found");
        require(plan.fromLevel == currentLevel, "Level changed");

        plan.approvals++;

        if (plan.approvals >= plan.requiredApprovals && block.timestamp >= plan.executionTime) {
            _executeRecoveryPlan(planId);
        }
    }

    /**
     * Execute recovery plan
     */
    function executeRecoveryPlan(uint256 planId) external {
        RecoveryPlan storage plan = recoveryPlans[planId];
        require(!plan.executed, "Already executed");
        require(plan.approvals >= plan.requiredApprovals, "Insufficient approvals");
        require(block.timestamp >= plan.executionTime, "Too early");
        require(plan.fromLevel == currentLevel, "Level changed");

        _executeRecoveryPlan(planId);
    }

    /**
     * Queue emergency withdrawal
     */
    function queueWithdrawal(
        address token,
        uint256 amount
    ) external nonReentrant {
        require(amount <= maxWithdrawalAmount[currentLevel], "Amount exceeds limit");

        uint256 delay = withdrawalDelays[currentLevel];
        uint256 processAfter = block.timestamp + delay;

        withdrawalQueue.push(WithdrawalRequest({
            user: msg.sender,
            token: token,
            amount: amount,
            requestTime: block.timestamp,
            processAfter: processAfter,
            processed: false
        }));

        emit WithdrawalQueued(msg.sender, token, amount, processAfter);
    }

    /**
     * Process withdrawal from queue
     */
    function processWithdrawal(uint256 queueIndex) external nonReentrant {
        require(queueIndex < withdrawalQueue.length, "Invalid index");

        WithdrawalRequest storage request = withdrawalQueue[queueIndex];
        require(!request.processed, "Already processed");
        require(block.timestamp >= request.processAfter, "Too early");

        request.processed = true;
        processedWithdrawals++;

        // In production: actually transfer tokens
        // Here we just emit event
        emit WithdrawalProcessed(request.user, request.token, request.amount);
    }

    /**
     * Check if action is allowed at current level
     */
    function isActionAllowed(string calldata action) external view returns (bool) {
        if (keccak256(bytes(action)) == keccak256("NEW_POSITION")) {
            return newPositionsAllowed[currentLevel];
        }
        if (keccak256(bytes(action)) == keccak256("TRADING")) {
            return tradingAllowed[currentLevel];
        }
        return currentLevel == EmergencyLevel.NORMAL;
    }

    /**
     * Get current system status
     */
    function getSystemStatus() external view returns (
        EmergencyLevel level,
        ShutdownReason reason,
        uint256 timeSinceLevelChange,
        bool canTrade,
        bool canOpenPositions,
        uint256 withdrawalDelay,
        uint256 maxWithdrawal
    ) {
        return (
            currentLevel,
            currentReason,
            block.timestamp - lastLevelChange,
            tradingAllowed[currentLevel],
            newPositionsAllowed[currentLevel],
            withdrawalDelays[currentLevel],
            maxWithdrawalAmount[currentLevel]
        );
    }

    /**
     * Get pending withdrawal count
     */
    function getPendingWithdrawals() external view returns (uint256) {
        return withdrawalQueue.length - processedWithdrawals;
    }

    /**
     * Update circuit breaker thresholds
     */
    function updateCircuitBreakerThresholds(
        uint256 _maxPriceDeviation,
        uint256 _maxVolumeSpike,
        uint256 _minLiquidityThreshold,
        uint256 _oracleHeartbeatTimeout
    ) external onlyRole(OPERATOR_ROLE) {
        maxPriceDeviation = _maxPriceDeviation;
        maxVolumeSpike = _maxVolumeSpike;
        minLiquidityThreshold = _minLiquidityThreshold;
        oracleHeartbeatTimeout = _oracleHeartbeatTimeout;
    }

    /**
     * Update level configuration
     */
    function updateLevelConfig(
        EmergencyLevel level,
        uint256 delay,
        uint256 maxAmount,
        bool allowNewPositions,
        bool allowTrading
    ) external onlyRole(OPERATOR_ROLE) {
        withdrawalDelays[level] = delay;
        maxWithdrawalAmount[level] = maxAmount;
        newPositionsAllowed[level] = allowNewPositions;
        tradingAllowed[level] = allowTrading;
    }

    /**
     * Internal: Check and execute vote if enough approvals
     */
    function _checkAndExecuteVote(EmergencyLevel proposedLevel, ShutdownReason reason) internal {
        uint256 approvalCount = 0;

        bytes32 voteHash = keccak256(abi.encode(voteCount, proposedLevel, reason));

        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardianApprovals[voteHash][guardians[i]]) {
                approvalCount++;
            }
        }

        // Check if original voter should count
        GuardianVote storage vote = votes[voteCount];
        if (vote.guardian != address(0) && !guardianApprovals[voteHash][vote.guardian]) {
            guardianApprovals[voteHash][vote.guardian] = true;
            approvalCount++;
        }

        if (approvalCount >= requiredGuardians) {
            vote.executed = true;
            _setEmergencyLevel(proposedLevel, reason);
        }
    }

    /**
     * Internal: Set emergency level
     */
    function _setEmergencyLevel(EmergencyLevel newLevel, ShutdownReason reason) internal {
        EmergencyLevel oldLevel = currentLevel;
        currentLevel = newLevel;
        currentReason = reason;
        lastLevelChange = block.timestamp;

        if (uint256(newLevel) > uint256(oldLevel)) {
            lastEscalation = block.timestamp;
        }

        if (newLevel == EmergencyLevel.SHUTDOWN) {
            _pause();
        } else if (oldLevel == EmergencyLevel.SHUTDOWN && newLevel != EmergencyLevel.SHUTDOWN) {
            _unpause();
        }

        emit EmergencyLevelChanged(oldLevel, newLevel, reason, msg.sender);
    }

    /**
     * Internal: Execute recovery plan
     */
    function _executeRecoveryPlan(uint256 planId) internal {
        RecoveryPlan storage plan = recoveryPlans[planId];

        plan.executed = true;
        _setEmergencyLevel(plan.toLevel, ShutdownReason.NONE);

        emit RecoveryPlanExecuted(planId);
    }
}
