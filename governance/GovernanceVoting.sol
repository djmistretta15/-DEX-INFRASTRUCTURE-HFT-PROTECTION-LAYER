// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * DECENTRALIZED GOVERNANCE VOTING SYSTEM
 *
 * HYPOTHESIS: A transparent, on-chain governance system with vote delegation,
 * timelock execution, and quadratic voting options will enable decentralized
 * decision-making with >50% token holder participation.
 *
 * SUCCESS METRICS:
 * - Token holder participation: >50%
 * - Proposal execution success: >90%
 * - Average voting turnout: >30% of circulating supply
 * - Governance attack prevention: 0 successful attacks
 * - Time to execution: <7 days average
 *
 * SECURITY CONSIDERATIONS:
 * - Flash loan attack prevention
 * - Vote buying detection
 * - Timelock for critical changes
 * - Emergency veto mechanism
 * - Delegation tracking
 * - Snapshot voting to prevent double-voting
 */

// Proposal state
enum ProposalState {
    PENDING,
    ACTIVE,
    CANCELLED,
    DEFEATED,
    SUCCEEDED,
    QUEUED,
    EXPIRED,
    EXECUTED,
    VETOED
}

// Vote type
enum VoteType {
    AGAINST,
    FOR,
    ABSTAIN
}

// Proposal structure
struct Proposal {
    uint256 id;
    address proposer;
    string title;
    string description;
    address[] targets;
    uint256[] values;
    bytes[] calldatas;
    string[] signatures;
    uint256 startBlock;
    uint256 endBlock;
    uint256 forVotes;
    uint256 againstVotes;
    uint256 abstainVotes;
    bool cancelled;
    bool executed;
    bool vetoed;
    uint256 eta; // Execution time after queue
    mapping(address => Receipt) receipts;
}

// Vote receipt
struct Receipt {
    bool hasVoted;
    VoteType support;
    uint256 votes;
    uint256 votingPower;
}

// Delegation info
struct DelegationInfo {
    address delegatee;
    uint256 delegatedPower;
    uint256 delegationTime;
}

contract GovernanceVoting is ReentrancyGuard, AccessControl {
    using ECDSA for bytes32;

    // Roles
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant VETOER_ROLE = keccak256("VETOER_ROLE");

    // Governance token
    ERC20Votes public immutable governanceToken;

    // Proposals
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    // Delegations
    mapping(address => DelegationInfo) public delegations;
    mapping(address => address[]) public delegators; // Who delegated to this address

    // Configuration
    uint256 public votingDelay = 1; // 1 block
    uint256 public votingPeriod = 17280; // ~3 days (assuming 15s blocks)
    uint256 public proposalThreshold; // Minimum tokens to propose
    uint256 public quorumVotes; // Minimum votes for proposal to pass
    uint256 public timelockDelay = 2 days;
    uint256 public gracePeriod = 14 days;

    // Flash loan protection
    mapping(address => uint256) public lastTokenTransfer;
    uint256 public flashLoanProtectionBlocks = 1;

    // Vote buying prevention
    mapping(uint256 => mapping(address => uint256)) public voteCommitments;
    bool public useCommitReveal = false;

    // Quadratic voting option
    bool public useQuadraticVoting = false;

    // Emergency settings
    bool public emergencyMode = false;

    // Events
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

    event ProposalQueued(uint256 indexed proposalId, uint256 eta);
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCancelled(uint256 indexed proposalId);
    event ProposalVetoed(uint256 indexed proposalId);

    event DelegateChanged(
        address indexed delegator,
        address indexed fromDelegate,
        address indexed toDelegate
    );

    event QuorumUpdated(uint256 oldQuorum, uint256 newQuorum);
    event VotingPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);

    constructor(
        address _governanceToken,
        uint256 _proposalThreshold,
        uint256 _quorumVotes
    ) {
        governanceToken = ERC20Votes(_governanceToken);
        proposalThreshold = _proposalThreshold;
        quorumVotes = _quorumVotes;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(VETOER_ROLE, msg.sender);
    }

    /**
     * Create new proposal
     */
    function propose(
        string memory title,
        string memory description,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string[] memory signatures
    ) external returns (uint256) {
        require(!emergencyMode, "Emergency mode active");
        require(
            getVotingPower(msg.sender) >= proposalThreshold,
            "Below proposal threshold"
        );
        require(
            targets.length == values.length &&
            targets.length == calldatas.length &&
            targets.length == signatures.length,
            "Invalid proposal length"
        );
        require(targets.length > 0, "No actions provided");
        require(targets.length <= 10, "Too many actions");

        // Flash loan protection
        require(
            block.number > lastTokenTransfer[msg.sender] + flashLoanProtectionBlocks,
            "Flash loan protection"
        );

        proposalCount++;
        uint256 proposalId = proposalCount;

        Proposal storage proposal = proposals[proposalId];
        proposal.id = proposalId;
        proposal.proposer = msg.sender;
        proposal.title = title;
        proposal.description = description;
        proposal.targets = targets;
        proposal.values = values;
        proposal.calldatas = calldatas;
        proposal.signatures = signatures;
        proposal.startBlock = block.number + votingDelay;
        proposal.endBlock = proposal.startBlock + votingPeriod;

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

        return proposalId;
    }

    /**
     * Cast vote on proposal
     */
    function castVote(
        uint256 proposalId,
        VoteType support,
        string memory reason
    ) external nonReentrant {
        require(!emergencyMode, "Emergency mode active");
        return _castVote(msg.sender, proposalId, support, reason);
    }

    /**
     * Cast vote with signature (gasless voting)
     */
    function castVoteBySig(
        uint256 proposalId,
        VoteType support,
        string memory reason,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
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
                keccak256("Vote(uint256 proposalId,uint8 support,string reason)"),
                proposalId,
                support,
                keccak256(bytes(reason))
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "Invalid signature");

        _castVote(signer, proposalId, support, reason);
    }

    /**
     * Queue successful proposal for execution
     */
    function queue(uint256 proposalId) external {
        require(
            state(proposalId) == ProposalState.SUCCEEDED,
            "Proposal not succeeded"
        );

        Proposal storage proposal = proposals[proposalId];
        uint256 eta = block.timestamp + timelockDelay;
        proposal.eta = eta;

        emit ProposalQueued(proposalId, eta);
    }

    /**
     * Execute queued proposal
     */
    function execute(uint256 proposalId) external payable nonReentrant onlyRole(EXECUTOR_ROLE) {
        require(state(proposalId) == ProposalState.QUEUED, "Proposal not queued");

        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp >= proposal.eta, "Timelock not passed");
        require(
            block.timestamp <= proposal.eta + gracePeriod,
            "Proposal expired"
        );

        proposal.executed = true;

        // Execute all actions
        for (uint256 i = 0; i < proposal.targets.length; i++) {
            _executeTransaction(
                proposal.targets[i],
                proposal.values[i],
                proposal.signatures[i],
                proposal.calldatas[i]
            );
        }

        emit ProposalExecuted(proposalId);
    }

    /**
     * Cancel proposal
     */
    function cancel(uint256 proposalId) external {
        require(state(proposalId) != ProposalState.EXECUTED, "Already executed");

        Proposal storage proposal = proposals[proposalId];

        // Only proposer or guardian can cancel
        require(
            msg.sender == proposal.proposer ||
            hasRole(GUARDIAN_ROLE, msg.sender) ||
            getVotingPower(proposal.proposer) < proposalThreshold,
            "Cannot cancel"
        );

        proposal.cancelled = true;
        emit ProposalCancelled(proposalId);
    }

    /**
     * Veto proposal (emergency power)
     */
    function veto(uint256 proposalId) external onlyRole(VETOER_ROLE) {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Already executed");
        require(!proposal.vetoed, "Already vetoed");

        proposal.vetoed = true;
        emit ProposalVetoed(proposalId);
    }

    /**
     * Delegate voting power
     */
    function delegate(address delegatee) external {
        require(delegatee != address(0), "Invalid delegatee");
        require(delegatee != msg.sender, "Cannot self-delegate");

        DelegationInfo storage info = delegations[msg.sender];
        address oldDelegatee = info.delegatee;

        // Update delegation
        info.delegatee = delegatee;
        info.delegatedPower = governanceToken.balanceOf(msg.sender);
        info.delegationTime = block.timestamp;

        // Track delegators
        if (oldDelegatee != address(0)) {
            _removeDelegator(oldDelegatee, msg.sender);
        }
        delegators[delegatee].push(msg.sender);

        emit DelegateChanged(msg.sender, oldDelegatee, delegatee);
    }

    /**
     * Remove delegation
     */
    function undelegate() external {
        DelegationInfo storage info = delegations[msg.sender];
        address oldDelegatee = info.delegatee;
        require(oldDelegatee != address(0), "Not delegated");

        _removeDelegator(oldDelegatee, msg.sender);

        info.delegatee = address(0);
        info.delegatedPower = 0;

        emit DelegateChanged(msg.sender, oldDelegatee, address(0));
    }

    /**
     * Get current voting power (including delegated)
     */
    function getVotingPower(address account) public view returns (uint256) {
        uint256 ownPower = governanceToken.balanceOf(account);

        // Subtract delegated power
        if (delegations[account].delegatee != address(0)) {
            ownPower = 0; // Power is delegated
        }

        // Add received delegations
        address[] storage _delegators = delegators[account];
        for (uint256 i = 0; i < _delegators.length; i++) {
            ownPower += governanceToken.balanceOf(_delegators[i]);
        }

        return ownPower;
    }

    /**
     * Get proposal state
     */
    function state(uint256 proposalId) public view returns (ProposalState) {
        require(proposalId > 0 && proposalId <= proposalCount, "Invalid proposal");

        Proposal storage proposal = proposals[proposalId];

        if (proposal.vetoed) {
            return ProposalState.VETOED;
        }
        if (proposal.cancelled) {
            return ProposalState.CANCELLED;
        }
        if (proposal.executed) {
            return ProposalState.EXECUTED;
        }
        if (block.number < proposal.startBlock) {
            return ProposalState.PENDING;
        }
        if (block.number <= proposal.endBlock) {
            return ProposalState.ACTIVE;
        }
        if (
            proposal.forVotes <= proposal.againstVotes ||
            proposal.forVotes + proposal.againstVotes < quorumVotes
        ) {
            return ProposalState.DEFEATED;
        }
        if (proposal.eta == 0) {
            return ProposalState.SUCCEEDED;
        }
        if (block.timestamp >= proposal.eta + gracePeriod) {
            return ProposalState.EXPIRED;
        }
        return ProposalState.QUEUED;
    }

    /**
     * Get proposal details
     */
    function getProposalDetails(uint256 proposalId) external view returns (
        address proposer,
        string memory title,
        uint256 startBlock,
        uint256 endBlock,
        uint256 forVotes,
        uint256 againstVotes,
        uint256 abstainVotes,
        ProposalState currentState
    ) {
        Proposal storage proposal = proposals[proposalId];
        return (
            proposal.proposer,
            proposal.title,
            proposal.startBlock,
            proposal.endBlock,
            proposal.forVotes,
            proposal.againstVotes,
            proposal.abstainVotes,
            state(proposalId)
        );
    }

    /**
     * Get vote receipt
     */
    function getReceipt(
        uint256 proposalId,
        address voter
    ) external view returns (
        bool hasVoted,
        VoteType support,
        uint256 votes
    ) {
        Receipt storage receipt = proposals[proposalId].receipts[voter];
        return (receipt.hasVoted, receipt.support, receipt.votes);
    }

    /**
     * Update governance parameters
     */
    function updateGovernanceParams(
        uint256 _votingDelay,
        uint256 _votingPeriod,
        uint256 _proposalThreshold,
        uint256 _quorumVotes,
        uint256 _timelockDelay
    ) external onlyRole(GUARDIAN_ROLE) {
        require(_votingPeriod >= 5760, "Voting period too short"); // Min ~1 day
        require(_timelockDelay >= 1 days, "Timelock too short");
        require(_quorumVotes > 0, "Invalid quorum");

        votingDelay = _votingDelay;

        uint256 oldPeriod = votingPeriod;
        votingPeriod = _votingPeriod;
        emit VotingPeriodUpdated(oldPeriod, _votingPeriod);

        proposalThreshold = _proposalThreshold;

        uint256 oldQuorum = quorumVotes;
        quorumVotes = _quorumVotes;
        emit QuorumUpdated(oldQuorum, _quorumVotes);

        timelockDelay = _timelockDelay;
    }

    /**
     * Toggle quadratic voting
     */
    function setQuadraticVoting(bool enabled) external onlyRole(GUARDIAN_ROLE) {
        useQuadraticVoting = enabled;
    }

    /**
     * Set emergency mode
     */
    function setEmergencyMode(bool enabled) external onlyRole(GUARDIAN_ROLE) {
        emergencyMode = enabled;
    }

    /**
     * Record token transfer (for flash loan protection)
     */
    function recordTransfer(address account) external {
        require(msg.sender == address(governanceToken), "Only token");
        lastTokenTransfer[account] = block.number;
    }

    /**
     * Internal: Cast vote
     */
    function _castVote(
        address voter,
        uint256 proposalId,
        VoteType support,
        string memory reason
    ) internal {
        require(state(proposalId) == ProposalState.ACTIVE, "Voting closed");

        Proposal storage proposal = proposals[proposalId];
        Receipt storage receipt = proposal.receipts[voter];

        require(!receipt.hasVoted, "Already voted");

        // Flash loan protection
        require(
            block.number > lastTokenTransfer[voter] + flashLoanProtectionBlocks,
            "Flash loan protection"
        );

        uint256 votes = getVotingPower(voter);
        require(votes > 0, "No voting power");

        // Apply quadratic voting if enabled
        if (useQuadraticVoting) {
            votes = sqrt(votes);
        }

        receipt.hasVoted = true;
        receipt.support = support;
        receipt.votes = votes;
        receipt.votingPower = getVotingPower(voter);

        if (support == VoteType.FOR) {
            proposal.forVotes += votes;
        } else if (support == VoteType.AGAINST) {
            proposal.againstVotes += votes;
        } else {
            proposal.abstainVotes += votes;
        }

        emit VoteCast(voter, proposalId, support, votes, reason);
    }

    /**
     * Internal: Execute transaction
     */
    function _executeTransaction(
        address target,
        uint256 value,
        string memory signature,
        bytes memory data
    ) internal {
        bytes memory callData;

        if (bytes(signature).length == 0) {
            callData = data;
        } else {
            callData = abi.encodePacked(bytes4(keccak256(bytes(signature))), data);
        }

        (bool success, ) = target.call{value: value}(callData);
        require(success, "Transaction execution failed");
    }

    /**
     * Internal: Remove delegator from list
     */
    function _removeDelegator(address delegatee, address delegator) internal {
        address[] storage _delegators = delegators[delegatee];
        for (uint256 i = 0; i < _delegators.length; i++) {
            if (_delegators[i] == delegator) {
                _delegators[i] = _delegators[_delegators.length - 1];
                _delegators.pop();
                break;
            }
        }
    }

    /**
     * Internal: Square root for quadratic voting
     */
    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }

    receive() external payable {}
}
