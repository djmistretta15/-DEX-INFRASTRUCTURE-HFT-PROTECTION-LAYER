// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title AtomicSwapCoordinator
 * @notice Trustless cross-chain and cross-party atomic swaps using HTLC
 *
 * HYPOTHESIS: Hash Time-Locked Contracts (HTLC) with optimistic execution
 * will enable trustless swaps with 99% success rate and <2 minute settlement.
 *
 * SUCCESS METRICS:
 * - Swap success rate >99%
 * - Settlement time <2 minutes
 * - Zero fund loss from failed swaps
 * - Gas cost <100k per swap
 * - Support for 50+ token pairs
 *
 * SECURITY CONSIDERATIONS:
 * - Cryptographic hash locks for atomicity
 * - Timelock prevents indefinite fund locking
 * - Preimage revelation ensures fairness
 * - No trusted third party required
 * - Replay protection via unique swap IDs
 */

contract AtomicSwapCoordinator is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // Swap states
    enum SwapState {
        INVALID,
        OPEN,
        CLAIMED,
        REFUNDED,
        EXPIRED
    }

    // Swap structure
    struct Swap {
        bytes32 swapId;
        address initiator;
        address participant;
        address token;
        uint256 amount;
        bytes32 hashLock;
        uint256 timelock;
        SwapState state;
        bytes32 preimage; // Set when claimed
        uint256 createdAt;
    }

    // Multi-hop swap for cross-chain
    struct CrossChainSwap {
        bytes32 swapId;
        address localToken;
        uint256 localAmount;
        uint256 remoteChainId;
        bytes32 remoteSwapId;
        address remoteToken;
        uint256 remoteAmount;
        SwapState state;
        uint256 deadline;
    }

    // Configuration
    uint256 public constant MIN_TIMELOCK = 1 hours;
    uint256 public constant MAX_TIMELOCK = 48 hours;
    uint256 public constant CROSS_CHAIN_TIMELOCK_BUFFER = 2 hours;

    // Storage
    mapping(bytes32 => Swap) public swaps;
    mapping(bytes32 => CrossChainSwap) public crossChainSwaps;
    mapping(address => bytes32[]) public userSwaps;
    mapping(bytes32 => bool) public usedPreimages; // Prevent replay

    // Statistics
    uint256 public totalSwaps;
    uint256 public successfulSwaps;
    uint256 public refundedSwaps;
    uint256 public totalVolume;

    // Events
    event SwapInitiated(
        bytes32 indexed swapId,
        address indexed initiator,
        address indexed participant,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timelock
    );

    event SwapClaimed(
        bytes32 indexed swapId,
        address indexed claimer,
        bytes32 preimage
    );

    event SwapRefunded(
        bytes32 indexed swapId,
        address indexed refundee
    );

    event CrossChainSwapInitiated(
        bytes32 indexed swapId,
        uint256 remoteChainId,
        bytes32 remoteSwapId
    );

    /**
     * @notice Initiate a new atomic swap
     * @param participant Address that can claim the swap
     * @param token ERC20 token to swap
     * @param amount Amount to swap
     * @param hashLock SHA256 hash of the secret preimage
     * @param timelock Unix timestamp after which initiator can refund
     */
    function initiateSwap(
        address participant,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timelock
    ) external nonReentrant returns (bytes32 swapId) {
        require(participant != address(0), "Invalid participant");
        require(participant != msg.sender, "Cannot swap with self");
        require(token != address(0), "Invalid token");
        require(amount > 0, "Amount must be positive");
        require(hashLock != bytes32(0), "Invalid hash lock");

        // Validate timelock
        require(timelock >= block.timestamp + MIN_TIMELOCK, "Timelock too short");
        require(timelock <= block.timestamp + MAX_TIMELOCK, "Timelock too long");

        // Generate unique swap ID
        swapId = keccak256(abi.encodePacked(
            msg.sender,
            participant,
            token,
            amount,
            hashLock,
            block.timestamp,
            block.number
        ));

        require(swaps[swapId].state == SwapState.INVALID, "Swap ID exists");

        // Transfer tokens to contract
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Create swap
        swaps[swapId] = Swap({
            swapId: swapId,
            initiator: msg.sender,
            participant: participant,
            token: token,
            amount: amount,
            hashLock: hashLock,
            timelock: timelock,
            state: SwapState.OPEN,
            preimage: bytes32(0),
            createdAt: block.timestamp
        });

        userSwaps[msg.sender].push(swapId);
        userSwaps[participant].push(swapId);
        totalSwaps++;

        emit SwapInitiated(swapId, msg.sender, participant, token, amount, hashLock, timelock);

        return swapId;
    }

    /**
     * @notice Claim swap by revealing the preimage
     * @param swapId ID of the swap to claim
     * @param preimage Secret that hashes to the hashLock
     */
    function claimSwap(
        bytes32 swapId,
        bytes32 preimage
    ) external nonReentrant {
        Swap storage swap = swaps[swapId];

        require(swap.state == SwapState.OPEN, "Swap not open");
        require(msg.sender == swap.participant, "Not participant");
        require(block.timestamp < swap.timelock, "Swap expired");

        // Verify preimage
        bytes32 hash = sha256(abi.encodePacked(preimage));
        require(hash == swap.hashLock, "Invalid preimage");
        require(!usedPreimages[preimage], "Preimage already used");

        // Update state
        swap.state = SwapState.CLAIMED;
        swap.preimage = preimage;
        usedPreimages[preimage] = true;

        // Transfer tokens to participant
        IERC20(swap.token).safeTransfer(swap.participant, swap.amount);

        successfulSwaps++;
        totalVolume += swap.amount;

        emit SwapClaimed(swapId, msg.sender, preimage);
    }

    /**
     * @notice Refund expired swap to initiator
     * @param swapId ID of the swap to refund
     */
    function refundSwap(bytes32 swapId) external nonReentrant {
        Swap storage swap = swaps[swapId];

        require(swap.state == SwapState.OPEN, "Swap not open");
        require(block.timestamp >= swap.timelock, "Swap not expired");

        // Anyone can call refund, but funds go to initiator
        swap.state = SwapState.REFUNDED;

        // Return tokens to initiator
        IERC20(swap.token).safeTransfer(swap.initiator, swap.amount);

        refundedSwaps++;

        emit SwapRefunded(swapId, swap.initiator);
    }

    /**
     * @notice Initiate cross-chain atomic swap
     * @param localToken Token on this chain
     * @param localAmount Amount to lock locally
     * @param remoteChainId Destination chain ID
     * @param remoteToken Token address on remote chain
     * @param remoteAmount Expected amount on remote chain
     * @param hashLock Hash lock for the swap
     * @param deadline Overall deadline for the swap
     */
    function initiateCrossChainSwap(
        address localToken,
        uint256 localAmount,
        uint256 remoteChainId,
        address remoteToken,
        uint256 remoteAmount,
        bytes32 hashLock,
        uint256 deadline
    ) external nonReentrant returns (bytes32 swapId, bytes32 remoteSwapId) {
        require(localAmount > 0, "Invalid local amount");
        require(remoteAmount > 0, "Invalid remote amount");
        require(deadline > block.timestamp + CROSS_CHAIN_TIMELOCK_BUFFER, "Deadline too soon");

        // Calculate timelocks with buffer for cross-chain latency
        uint256 localTimelock = deadline - CROSS_CHAIN_TIMELOCK_BUFFER;
        uint256 remoteTimelock = deadline;

        // Generate swap IDs
        swapId = keccak256(abi.encodePacked(
            msg.sender,
            localToken,
            localAmount,
            remoteChainId,
            hashLock,
            block.timestamp
        ));

        remoteSwapId = keccak256(abi.encodePacked(
            swapId,
            remoteChainId,
            remoteToken,
            remoteAmount
        ));

        // Lock local tokens
        IERC20(localToken).safeTransferFrom(msg.sender, address(this), localAmount);

        crossChainSwaps[swapId] = CrossChainSwap({
            swapId: swapId,
            localToken: localToken,
            localAmount: localAmount,
            remoteChainId: remoteChainId,
            remoteSwapId: remoteSwapId,
            remoteToken: remoteToken,
            remoteAmount: remoteAmount,
            state: SwapState.OPEN,
            deadline: deadline
        });

        emit CrossChainSwapInitiated(swapId, remoteChainId, remoteSwapId);

        return (swapId, remoteSwapId);
    }

    /**
     * @notice Get swap details
     */
    function getSwap(bytes32 swapId) external view returns (Swap memory) {
        return swaps[swapId];
    }

    /**
     * @notice Get user's swap history
     */
    function getUserSwaps(address user) external view returns (bytes32[] memory) {
        return userSwaps[user];
    }

    /**
     * @notice Check if swap is claimable
     */
    function isClaimable(bytes32 swapId) external view returns (bool) {
        Swap memory swap = swaps[swapId];
        return swap.state == SwapState.OPEN && block.timestamp < swap.timelock;
    }

    /**
     * @notice Check if swap is refundable
     */
    function isRefundable(bytes32 swapId) external view returns (bool) {
        Swap memory swap = swaps[swapId];
        return swap.state == SwapState.OPEN && block.timestamp >= swap.timelock;
    }

    /**
     * @notice Get contract statistics
     */
    function getStatistics() external view returns (
        uint256 _totalSwaps,
        uint256 _successfulSwaps,
        uint256 _refundedSwaps,
        uint256 _totalVolume,
        uint256 _successRate
    ) {
        _totalSwaps = totalSwaps;
        _successfulSwaps = successfulSwaps;
        _refundedSwaps = refundedSwaps;
        _totalVolume = totalVolume;
        _successRate = totalSwaps > 0 ? (successfulSwaps * 10000) / totalSwaps : 0;
    }

    /**
     * @notice Generate hash lock from preimage
     */
    function generateHashLock(bytes32 preimage) external pure returns (bytes32) {
        return sha256(abi.encodePacked(preimage));
    }

    /**
     * @notice Verify preimage matches hash lock
     */
    function verifyPreimage(bytes32 preimage, bytes32 hashLock) external pure returns (bool) {
        return sha256(abi.encodePacked(preimage)) == hashLock;
    }
}

/**
 * @title MultiPartySwap
 * @notice Coordinated multi-party atomic swap for complex trades
 */
contract MultiPartySwap is ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct PartySwap {
        address party;
        address tokenIn;
        uint256 amountIn;
        address tokenOut;
        uint256 amountOut;
        bool deposited;
        bool withdrawn;
    }

    struct MultiSwap {
        bytes32 swapId;
        PartySwap[] parties;
        uint256 deadline;
        bool executed;
        bool cancelled;
        uint256 minParticipants;
    }

    mapping(bytes32 => MultiSwap) public multiSwaps;

    event MultiSwapCreated(bytes32 indexed swapId, uint256 parties);
    event PartyDeposited(bytes32 indexed swapId, address party);
    event MultiSwapExecuted(bytes32 indexed swapId);
    event MultiSwapCancelled(bytes32 indexed swapId);

    /**
     * @notice Create multi-party swap
     */
    function createMultiSwap(
        address[] calldata parties,
        address[] calldata tokensIn,
        uint256[] calldata amountsIn,
        address[] calldata tokensOut,
        uint256[] calldata amountsOut,
        uint256 deadline
    ) external returns (bytes32 swapId) {
        require(parties.length >= 2, "Min 2 parties");
        require(
            parties.length == tokensIn.length &&
            parties.length == amountsIn.length &&
            parties.length == tokensOut.length &&
            parties.length == amountsOut.length,
            "Array length mismatch"
        );
        require(deadline > block.timestamp + 1 hours, "Deadline too soon");

        swapId = keccak256(abi.encodePacked(
            parties,
            tokensIn,
            amountsIn,
            block.timestamp
        ));

        MultiSwap storage swap = multiSwaps[swapId];
        swap.swapId = swapId;
        swap.deadline = deadline;
        swap.minParticipants = parties.length;

        for (uint256 i = 0; i < parties.length; i++) {
            swap.parties.push(PartySwap({
                party: parties[i],
                tokenIn: tokensIn[i],
                amountIn: amountsIn[i],
                tokenOut: tokensOut[i],
                amountOut: amountsOut[i],
                deposited: false,
                withdrawn: false
            }));
        }

        emit MultiSwapCreated(swapId, parties.length);
        return swapId;
    }

    /**
     * @notice Deposit funds for multi-party swap
     */
    function deposit(bytes32 swapId) external nonReentrant {
        MultiSwap storage swap = multiSwaps[swapId];
        require(!swap.executed && !swap.cancelled, "Swap not active");
        require(block.timestamp < swap.deadline, "Deadline passed");

        // Find party
        uint256 partyIndex = type(uint256).max;
        for (uint256 i = 0; i < swap.parties.length; i++) {
            if (swap.parties[i].party == msg.sender && !swap.parties[i].deposited) {
                partyIndex = i;
                break;
            }
        }

        require(partyIndex != type(uint256).max, "Not a party or already deposited");

        PartySwap storage party = swap.parties[partyIndex];
        IERC20(party.tokenIn).safeTransferFrom(msg.sender, address(this), party.amountIn);
        party.deposited = true;

        emit PartyDeposited(swapId, msg.sender);

        // Check if all parties deposited
        bool allDeposited = true;
        for (uint256 i = 0; i < swap.parties.length; i++) {
            if (!swap.parties[i].deposited) {
                allDeposited = false;
                break;
            }
        }

        // Auto-execute if all deposited
        if (allDeposited) {
            _executeMultiSwap(swapId);
        }
    }

    /**
     * @notice Cancel multi-swap if deadline passed
     */
    function cancel(bytes32 swapId) external nonReentrant {
        MultiSwap storage swap = multiSwaps[swapId];
        require(!swap.executed && !swap.cancelled, "Already finalized");
        require(block.timestamp >= swap.deadline, "Deadline not passed");

        swap.cancelled = true;

        // Refund all deposited parties
        for (uint256 i = 0; i < swap.parties.length; i++) {
            if (swap.parties[i].deposited) {
                IERC20(swap.parties[i].tokenIn).safeTransfer(
                    swap.parties[i].party,
                    swap.parties[i].amountIn
                );
            }
        }

        emit MultiSwapCancelled(swapId);
    }

    function _executeMultiSwap(bytes32 swapId) internal {
        MultiSwap storage swap = multiSwaps[swapId];
        swap.executed = true;

        // Distribute outputs to each party
        for (uint256 i = 0; i < swap.parties.length; i++) {
            PartySwap storage party = swap.parties[i];
            IERC20(party.tokenOut).safeTransfer(party.party, party.amountOut);
            party.withdrawn = true;
        }

        emit MultiSwapExecuted(swapId);
    }
}
