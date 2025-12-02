// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title DAOGovernance
 * @notice On-chain governance for MEV-resistant DEX protocol
 * @dev Implements time-weighted voting, quadratic voting, delegation, and treasury management
 *
 * SCIENTIFIC HYPOTHESIS:
 * Decentralized governance with time-weighted voting power reduces plutocratic control
 * by 60% and increases community participation by 300% compared to simple token voting.
 *
 * SUCCESS METRICS:
 * - Voter participation: >30% of token holders
 * - Proposal quality: <5% malicious proposals reaching quorum
 * - Execution success rate: >98%
 * - Treasury security: Zero unauthorized withdrawals
 *
 * SECURITY CONSIDERATIONS:
 * - Timelock on all governance actions
 * - Flash loan attack prevention (snapshot-based voting)
 * - Guardian veto power for emergencies
 * - Quorum requirements to prevent low-turnout attacks
 * - Vote delegation audit trail
 */
contract DAOGovernance is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using Counters for Counters.Counter;

    // ═══════════════════════════════════════════════════════════════════
    //                           ENUMS & STRUCTS
    // ═══════════════════════════════════════════════════════════════════

    enum ProposalState {
        Pending,
        Active,
        Canceled,
        Defeated,
        Succeeded,
        Queued,
        Expired,
        Executed
    }

    enum VoteType {
        Against,
        For,
        Abstain
    }

    struct Proposal {
        uint256 id;
        address proposer;
        string title;
        string description;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        uint256 startBlock;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        uint256 quorumVotes;
        bool canceled;
        bool executed;
        uint256 eta; // Execution time (after timelock)
        mapping(address => Receipt) receipts;
    }

    struct Receipt {
        bool hasVoted;
        VoteType support;
        uint256 votes;
        bool delegated;
    }

    struct ProposalConfig {
        uint256 votingDelay; // Blocks before voting starts
        uint256 votingPeriod; // Blocks voting is open
        uint256 proposalThreshold; // Tokens needed to propose
        uint256 quorumNumerator; // Quorum percentage (4 = 4%)
        uint256 timelockDelay; // Seconds before execution
    }

    struct Checkpoint {
        uint32 fromBlock;
        uint224 votes;
    }

    struct DelegateInfo {
        address delegatee;
        uint256 delegatedAt;
        uint256 amount;
    }

    // ═══════════════════════════════════════════════════════════════════
    //                           STATE VARIABLES
    // ═══════════════════════════════════════════════════════════════════

    IERC20 public governanceToken;
    address public guardian;
    address public treasury;

    ProposalConfig public config;
    Counters.Counter private _proposalIdTracker;

    mapping(uint256 => Proposal) public proposals;
    mapping(address => address) public delegates;
    mapping(address => Checkpoint[]) public checkpoints;
    mapping(address => uint256) public numCheckpoints;
    mapping(address => DelegateInfo) public delegations;

    // Time-weighted voting
    mapping(address => uint256) public tokenLockTime;
    uint256 public constant MAX_TIME_WEIGHT = 4; // 4x multiplier for max lock

    // Quadratic voting support
    bool public quadraticVotingEnabled;

    // Proposal execution queue
    mapping(bytes32 => bool) public queuedTransactions;

    uint256 public constant GRACE_PERIOD = 14 days;
    uint256 public constant MINIMUM_DELAY = 2 days;
    uint256 public constant MAXIMUM_DELAY = 30 days;

    // ═══════════════════════════════════════════════════════════════════
    //                              EVENTS
    // ═══════════════════════════════════════════════════════════════════

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        string title,
        address[] targets,
        uint256[] values,
        bytes[] calldatas,
        uint256 startBlock,
        uint256 endBlock,
        string description
    );

    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        VoteType support,
        uint256 votes,
        string reason
    );

    event ProposalCanceled(uint256 indexed proposalId);
    event ProposalQueued(uint256 indexed proposalId, uint256 eta);
    event ProposalExecuted(uint256 indexed proposalId);

    event DelegateChanged(
        address indexed delegator,
        address indexed fromDelegate,
        address indexed toDelegate
    );

    event DelegateVotesChanged(
        address indexed delegate,
        uint256 previousBalance,
        uint256 newBalance
    );

    event TokensLocked(address indexed user, uint256 amount, uint256 lockDuration);
    event TokensUnlocked(address indexed user, uint256 amount);

    event GuardianVeto(uint256 indexed proposalId, string reason);
    event TreasuryWithdrawal(address indexed token, address indexed to, uint256 amount);

    // ═══════════════════════════════════════════════════════════════════
    //                            CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════

    constructor(
        address _governanceToken,
        address _guardian,
        address _treasury
    ) {
        governanceToken = IERC20(_governanceToken);
        guardian = _guardian;
        treasury = _treasury;

        config = ProposalConfig({
            votingDelay: 1, // 1 block
            votingPeriod: 17280, // ~3 days (assuming 15s blocks)
            proposalThreshold: 100000 * 1e18, // 100k tokens to propose
            quorumNumerator: 4, // 4% quorum
            timelockDelay: 2 days
        });

        quadraticVotingEnabled = false;
    }

    // ═══════════════════════════════════════════════════════════════════
    //                        PROPOSAL LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Create a new governance proposal
     * @param targets Contract addresses to call
     * @param values ETH values to send
     * @param calldatas Function call data
     * @param title Proposal title
     * @param description Detailed description
     * @return proposalId Unique proposal identifier
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory title,
        string memory description
    ) external returns (uint256 proposalId) {
        require(
            getVotes(msg.sender, block.number - 1) >= config.proposalThreshold,
            "Proposer votes below threshold"
        );
        require(targets.length == values.length, "Invalid proposal length");
        require(targets.length == calldatas.length, "Invalid proposal length");
        require(targets.length > 0, "Empty proposal");
        require(targets.length <= 10, "Too many actions");

        _proposalIdTracker.increment();
        proposalId = _proposalIdTracker.current();

        Proposal storage proposal = proposals[proposalId];
        proposal.id = proposalId;
        proposal.proposer = msg.sender;
        proposal.title = title;
        proposal.description = description;
        proposal.targets = targets;
        proposal.values = values;
        proposal.calldatas = calldatas;
        proposal.startBlock = block.number + config.votingDelay;
        proposal.endBlock = proposal.startBlock + config.votingPeriod;
        proposal.quorumVotes = quorum();

        emit ProposalCreated(
            proposalId,
            msg.sender,
            title,
            targets,
            values,
            calldatas,
            proposal.startBlock,
            proposal.endBlock,
            description
        );
    }

    /**
     * @notice Cast vote on a proposal
     * @param proposalId Proposal to vote on
     * @param support Vote type (Against=0, For=1, Abstain=2)
     * @param reason Optional reason for vote
     */
    function castVote(
        uint256 proposalId,
        VoteType support,
        string calldata reason
    ) external {
        return _castVote(msg.sender, proposalId, support, reason);
    }

    /**
     * @notice Cast vote with signature (gasless voting)
     */
    function castVoteBySig(
        uint256 proposalId,
        VoteType support,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("DEX Governance")),
                block.chainid,
                address(this)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Ballot(uint256 proposalId,uint8 support)"),
                proposalId,
                uint8(support)
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "Invalid signature");

        _castVote(signatory, proposalId, support, "");
    }

    function _castVote(
        address voter,
        uint256 proposalId,
        VoteType support,
        string memory reason
    ) internal {
        require(state(proposalId) == ProposalState.Active, "Voting is closed");

        Proposal storage proposal = proposals[proposalId];
        Receipt storage receipt = proposal.receipts[voter];

        require(!receipt.hasVoted, "Already voted");

        uint256 votes = getVotes(voter, proposal.startBlock);

        // Apply quadratic voting if enabled
        if (quadraticVotingEnabled) {
            votes = Math.sqrt(votes * 1e18) / 1e9; // Square root with precision
        }

        // Apply time-weighted multiplier
        votes = votes * getTimeWeightMultiplier(voter) / 1e18;

        if (support == VoteType.For) {
            proposal.forVotes += votes;
        } else if (support == VoteType.Against) {
            proposal.againstVotes += votes;
        } else {
            proposal.abstainVotes += votes;
        }

        receipt.hasVoted = true;
        receipt.support = support;
        receipt.votes = votes;
        receipt.delegated = delegates[voter] != address(0);

        emit VoteCast(voter, proposalId, support, votes, reason);
    }

    /**
     * @notice Queue successful proposal for execution
     * @param proposalId Proposal to queue
     */
    function queue(uint256 proposalId) external {
        require(state(proposalId) == ProposalState.Succeeded, "Proposal not succeeded");

        Proposal storage proposal = proposals[proposalId];
        uint256 eta = block.timestamp + config.timelockDelay;

        for (uint256 i = 0; i < proposal.targets.length; i++) {
            _queueTransaction(
                proposal.targets[i],
                proposal.values[i],
                proposal.calldatas[i],
                eta
            );
        }

        proposal.eta = eta;

        emit ProposalQueued(proposalId, eta);
    }

    function _queueTransaction(
        address target,
        uint256 value,
        bytes memory data,
        uint256 eta
    ) internal {
        require(
            eta >= block.timestamp + MINIMUM_DELAY && eta <= block.timestamp + MAXIMUM_DELAY,
            "Invalid ETA"
        );

        bytes32 txHash = keccak256(abi.encode(target, value, data, eta));
        queuedTransactions[txHash] = true;
    }

    /**
     * @notice Execute a queued proposal
     * @param proposalId Proposal to execute
     */
    function execute(uint256 proposalId) external payable nonReentrant {
        require(state(proposalId) == ProposalState.Queued, "Proposal not queued");

        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp >= proposal.eta, "Timelock not expired");
        require(block.timestamp <= proposal.eta + GRACE_PERIOD, "Proposal expired");

        proposal.executed = true;

        for (uint256 i = 0; i < proposal.targets.length; i++) {
            _executeTransaction(
                proposal.targets[i],
                proposal.values[i],
                proposal.calldatas[i],
                proposal.eta
            );
        }

        emit ProposalExecuted(proposalId);
    }

    function _executeTransaction(
        address target,
        uint256 value,
        bytes memory data,
        uint256 eta
    ) internal {
        bytes32 txHash = keccak256(abi.encode(target, value, data, eta));
        require(queuedTransactions[txHash], "Transaction not queued");

        queuedTransactions[txHash] = false;

        (bool success, ) = target.call{value: value}(data);
        require(success, "Transaction execution failed");
    }

    /**
     * @notice Cancel a proposal (only proposer or guardian)
     * @param proposalId Proposal to cancel
     */
    function cancel(uint256 proposalId) external {
        ProposalState currentState = state(proposalId);
        require(
            currentState != ProposalState.Canceled &&
            currentState != ProposalState.Defeated &&
            currentState != ProposalState.Executed,
            "Cannot cancel"
        );

        Proposal storage proposal = proposals[proposalId];
        require(
            msg.sender == proposal.proposer || msg.sender == guardian,
            "Not authorized"
        );

        proposal.canceled = true;

        emit ProposalCanceled(proposalId);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                         DELEGATION
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Delegate voting power to another address
     * @param delegatee Address to delegate to
     */
    function delegate(address delegatee) external {
        return _delegate(msg.sender, delegatee);
    }

    /**
     * @notice Delegate by signature
     */
    function delegateBySig(
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("DEX Governance")),
                block.chainid,
                address(this)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)"),
                delegatee,
                nonce,
                expiry
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);

        require(signatory != address(0), "Invalid signature");
        require(block.timestamp <= expiry, "Signature expired");

        _delegate(signatory, delegatee);
    }

    function _delegate(address delegator, address delegatee) internal {
        address currentDelegate = delegates[delegator];
        uint256 delegatorBalance = governanceToken.balanceOf(delegator);

        delegates[delegator] = delegatee;
        delegations[delegator] = DelegateInfo({
            delegatee: delegatee,
            delegatedAt: block.timestamp,
            amount: delegatorBalance
        });

        emit DelegateChanged(delegator, currentDelegate, delegatee);

        _moveDelegates(currentDelegate, delegatee, delegatorBalance);
    }

    function _moveDelegates(
        address srcRep,
        address dstRep,
        uint256 amount
    ) internal {
        if (srcRep != dstRep && amount > 0) {
            if (srcRep != address(0)) {
                uint256 srcRepNum = numCheckpoints[srcRep];
                uint256 srcRepOld = srcRepNum > 0
                    ? checkpoints[srcRep][srcRepNum - 1].votes
                    : 0;
                uint256 srcRepNew = srcRepOld - amount;
                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
            }

            if (dstRep != address(0)) {
                uint256 dstRepNum = numCheckpoints[dstRep];
                uint256 dstRepOld = dstRepNum > 0
                    ? checkpoints[dstRep][dstRepNum - 1].votes
                    : 0;
                uint256 dstRepNew = dstRepOld + amount;
                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
            }
        }
    }

    function _writeCheckpoint(
        address delegatee,
        uint256 nCheckpoints,
        uint256 oldVotes,
        uint256 newVotes
    ) internal {
        uint32 blockNumber = safe32(block.number);

        if (
            nCheckpoints > 0 &&
            checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber
        ) {
            checkpoints[delegatee][nCheckpoints - 1].votes = safe224(newVotes);
        } else {
            checkpoints[delegatee].push(
                Checkpoint({fromBlock: blockNumber, votes: safe224(newVotes)})
            );
            numCheckpoints[delegatee] = nCheckpoints + 1;
        }

        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                     TIME-WEIGHTED VOTING
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Lock tokens for increased voting power
     * @param amount Amount to lock
     * @param duration Lock duration in seconds
     */
    function lockTokens(uint256 amount, uint256 duration) external nonReentrant {
        require(amount > 0, "Amount must be positive");
        require(duration >= 7 days, "Minimum lock is 7 days");
        require(duration <= 4 * 365 days, "Maximum lock is 4 years");

        governanceToken.safeTransferFrom(msg.sender, address(this), amount);

        uint256 unlockTime = block.timestamp + duration;
        if (tokenLockTime[msg.sender] < unlockTime) {
            tokenLockTime[msg.sender] = unlockTime;
        }

        // Update voting power
        _moveDelegates(address(0), delegates[msg.sender], amount);

        emit TokensLocked(msg.sender, amount, duration);
    }

    /**
     * @notice Unlock tokens after lock period expires
     * @param amount Amount to unlock
     */
    function unlockTokens(uint256 amount) external nonReentrant {
        require(block.timestamp >= tokenLockTime[msg.sender], "Tokens still locked");

        governanceToken.safeTransfer(msg.sender, amount);

        emit TokensUnlocked(msg.sender, amount);
    }

    /**
     * @notice Get time-weight multiplier for an address
     * @param account Address to check
     * @return multiplier Multiplier scaled by 1e18
     */
    function getTimeWeightMultiplier(address account) public view returns (uint256) {
        uint256 lockEnd = tokenLockTime[account];

        if (lockEnd <= block.timestamp) {
            return 1e18; // No bonus for unlocked tokens
        }

        uint256 remainingLock = lockEnd - block.timestamp;
        uint256 maxLock = 4 * 365 days;

        // Linear scaling from 1x to 4x based on lock time
        uint256 multiplier = 1e18 + ((MAX_TIME_WEIGHT - 1) * 1e18 * remainingLock) / maxLock;

        return multiplier;
    }

    // ═══════════════════════════════════════════════════════════════════
    //                      GUARDIAN FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Guardian can veto malicious proposals
     * @param proposalId Proposal to veto
     * @param reason Reason for veto
     */
    function guardianVeto(uint256 proposalId, string calldata reason) external {
        require(msg.sender == guardian, "Not guardian");
        require(!proposals[proposalId].executed, "Already executed");

        proposals[proposalId].canceled = true;

        emit GuardianVeto(proposalId, reason);
    }

    /**
     * @notice Transfer guardian role
     * @param newGuardian New guardian address
     */
    function setGuardian(address newGuardian) external {
        require(msg.sender == guardian, "Not guardian");
        require(newGuardian != address(0), "Invalid guardian");
        guardian = newGuardian;
    }

    /**
     * @notice Abdicate guardian role (cannot be undone)
     */
    function abdicateGuardian() external {
        require(msg.sender == guardian, "Not guardian");
        guardian = address(0);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                      TREASURY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════

    /**
     * @notice Withdraw tokens from treasury (governance controlled)
     * @param token Token to withdraw
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function withdrawFromTreasury(
        address token,
        address to,
        uint256 amount
    ) external {
        require(msg.sender == address(this), "Only via governance");
        require(to != address(0), "Invalid recipient");

        IERC20(token).safeTransfer(to, amount);

        emit TreasuryWithdrawal(token, to, amount);
    }

    // ═══════════════════════════════════════════════════════════════════
    //                         VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    function state(uint256 proposalId) public view returns (ProposalState) {
        Proposal storage proposal = proposals[proposalId];

        if (proposal.canceled) {
            return ProposalState.Canceled;
        } else if (block.number <= proposal.startBlock) {
            return ProposalState.Pending;
        } else if (block.number <= proposal.endBlock) {
            return ProposalState.Active;
        } else if (proposal.forVotes <= proposal.againstVotes || proposal.forVotes < proposal.quorumVotes) {
            return ProposalState.Defeated;
        } else if (proposal.eta == 0) {
            return ProposalState.Succeeded;
        } else if (proposal.executed) {
            return ProposalState.Executed;
        } else if (block.timestamp >= proposal.eta + GRACE_PERIOD) {
            return ProposalState.Expired;
        } else {
            return ProposalState.Queued;
        }
    }

    function getVotes(address account, uint256 blockNumber) public view returns (uint256) {
        require(blockNumber < block.number, "Block not yet mined");

        uint256 nCheckpoints = numCheckpoints[account];
        if (nCheckpoints == 0) {
            return governanceToken.balanceOf(account);
        }

        // Binary search for the checkpoint
        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
            return checkpoints[account][nCheckpoints - 1].votes;
        }

        if (checkpoints[account][0].fromBlock > blockNumber) {
            return governanceToken.balanceOf(account);
        }

        uint256 lower = 0;
        uint256 upper = nCheckpoints - 1;

        while (upper > lower) {
            uint256 center = upper - (upper - lower) / 2;
            Checkpoint memory cp = checkpoints[account][center];
            if (cp.fromBlock == blockNumber) {
                return cp.votes;
            } else if (cp.fromBlock < blockNumber) {
                lower = center;
            } else {
                upper = center - 1;
            }
        }

        return checkpoints[account][lower].votes;
    }

    function quorum() public view returns (uint256) {
        return (governanceToken.totalSupply() * config.quorumNumerator) / 100;
    }

    function getProposalInfo(uint256 proposalId)
        external
        view
        returns (
            address proposer,
            string memory title,
            uint256 forVotes,
            uint256 againstVotes,
            uint256 abstainVotes,
            ProposalState currentState
        )
    {
        Proposal storage proposal = proposals[proposalId];
        return (
            proposal.proposer,
            proposal.title,
            proposal.forVotes,
            proposal.againstVotes,
            proposal.abstainVotes,
            state(proposalId)
        );
    }

    function hasVoted(uint256 proposalId, address account) external view returns (bool) {
        return proposals[proposalId].receipts[account].hasVoted;
    }

    function getReceipt(uint256 proposalId, address voter) external view returns (Receipt memory) {
        return proposals[proposalId].receipts[voter];
    }

    // ═══════════════════════════════════════════════════════════════════
    //                      ADMIN FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    function setVotingDelay(uint256 newVotingDelay) external {
        require(msg.sender == address(this), "Only via governance");
        config.votingDelay = newVotingDelay;
    }

    function setVotingPeriod(uint256 newVotingPeriod) external {
        require(msg.sender == address(this), "Only via governance");
        require(newVotingPeriod >= 5760, "Voting period too short"); // Min 1 day
        config.votingPeriod = newVotingPeriod;
    }

    function setProposalThreshold(uint256 newThreshold) external {
        require(msg.sender == address(this), "Only via governance");
        config.proposalThreshold = newThreshold;
    }

    function setQuorumNumerator(uint256 newQuorumNumerator) external {
        require(msg.sender == address(this), "Only via governance");
        require(newQuorumNumerator >= 1 && newQuorumNumerator <= 50, "Invalid quorum");
        config.quorumNumerator = newQuorumNumerator;
    }

    function setTimelockDelay(uint256 newDelay) external {
        require(msg.sender == address(this), "Only via governance");
        require(newDelay >= MINIMUM_DELAY && newDelay <= MAXIMUM_DELAY, "Invalid delay");
        config.timelockDelay = newDelay;
    }

    function enableQuadraticVoting(bool enabled) external {
        require(msg.sender == address(this), "Only via governance");
        quadraticVotingEnabled = enabled;
    }

    // ═══════════════════════════════════════════════════════════════════
    //                      UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════

    function safe32(uint256 n) internal pure returns (uint32) {
        require(n < 2**32, "Value doesn't fit in 32 bits");
        return uint32(n);
    }

    function safe224(uint256 n) internal pure returns (uint224) {
        require(n < 2**224, "Value doesn't fit in 224 bits");
        return uint224(n);
    }

    receive() external payable {}
}
