// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IThresholdEncryption.sol";

/**
 * @title EncryptedOrderbook
 * @notice MEV-resistant orderbook using threshold encryption
 * @dev Orders are encrypted until batch reveal, preventing frontrunning
 */
contract EncryptedOrderbook {

    struct EncryptedOrder {
        bytes encryptedData;      // Encrypted order details
        bytes32 commitmentHash;   // Commitment to prevent substitution
        address submitter;
        uint256 timestamp;
        uint256 batchId;
        bool revealed;
        bool executed;
    }

    struct DecryptedOrder {
        address trader;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 deadline;
        OrderType orderType;
    }

    enum OrderType { MARKET, LIMIT, STOP_LOSS }

    // State variables
    mapping(bytes32 => EncryptedOrder) public orders;
    mapping(uint256 => bytes32[]) public batchOrders;
    mapping(address => bool) public authorizedRelayers;

    uint256 public currentBatchId;
    uint256 public batchDuration = 2 seconds;
    uint256 public lastBatchTime;

    IThresholdEncryption public encryptionOracle;

    // MEV protection parameters
    uint256 public constant MIN_BATCH_SIZE = 5;
    uint256 public slashAmount = 10 ether;

    // Events
    event OrderSubmitted(bytes32 indexed orderId, uint256 indexed batchId, address submitter);
    event BatchRevealed(uint256 indexed batchId, uint256 orderCount);
    event OrderExecuted(bytes32 indexed orderId, uint256 amountOut);
    event RelayerSlashed(address indexed relayer, uint256 amount, string reason);

    modifier onlyAuthorizedRelayer() {
        require(authorizedRelayers[msg.sender], "Not authorized relayer");
        _;
    }

    constructor(address _encryptionOracle) {
        encryptionOracle = IThresholdEncryption(_encryptionOracle);
        lastBatchTime = block.timestamp;
    }

    /**
     * @notice Submit encrypted order to mempool
     * @param encryptedData Threshold-encrypted order data
     * @param commitmentHash Hash commitment to order parameters
     */
    function submitEncryptedOrder(
        bytes calldata encryptedData,
        bytes32 commitmentHash
    ) external returns (bytes32 orderId) {
        require(encryptedData.length > 0, "Empty order");

        // Generate unique order ID
        orderId = keccak256(abi.encodePacked(
            msg.sender,
            block.timestamp,
            encryptedData,
            commitmentHash
        ));

        // Check for batch rotation
        if (block.timestamp >= lastBatchTime + batchDuration) {
            _rotateBatch();
        }

        // Store encrypted order
        orders[orderId] = EncryptedOrder({
            encryptedData: encryptedData,
            commitmentHash: commitmentHash,
            submitter: msg.sender,
            timestamp: block.timestamp,
            batchId: currentBatchId,
            revealed: false,
            executed: false
        });

        batchOrders[currentBatchId].push(orderId);

        emit OrderSubmitted(orderId, currentBatchId, msg.sender);

        return orderId;
    }

    /**
     * @notice Reveal and match orders after batch finalization
     * @dev Only authorized relayers can trigger batch reveal
     */
    function revealAndMatchBatch(
        uint256 batchId,
        bytes32[] calldata orderIds,
        bytes[] calldata decryptionProofs
    ) external onlyAuthorizedRelayer {
        require(batchId < currentBatchId, "Batch not finalized");
        require(orderIds.length == decryptionProofs.length, "Length mismatch");
        require(orderIds.length >= MIN_BATCH_SIZE, "Batch too small");

        DecryptedOrder[] memory decryptedOrders = new DecryptedOrder[](orderIds.length);

        // Decrypt all orders
        for (uint256 i = 0; i < orderIds.length; i++) {
            EncryptedOrder storage order = orders[orderIds[i]];
            require(order.batchId == batchId, "Wrong batch");
            require(!order.revealed, "Already revealed");

            // Verify and decrypt using threshold encryption
            bytes memory decryptedData = encryptionOracle.verifyAndDecrypt(
                order.encryptedData,
                decryptionProofs[i]
            );

            decryptedOrders[i] = abi.decode(decryptedData, (DecryptedOrder));

            // Verify commitment
            require(
                _verifyCommitment(decryptedOrders[i], order.commitmentHash),
                "Commitment mismatch"
            );

            order.revealed = true;
        }

        // Execute fair ordering matching
        _matchOrders(decryptedOrders, orderIds);

        emit BatchRevealed(batchId, orderIds.length);
    }

    /**
     * @notice Internal matching engine with MEV protection
     */
    function _matchOrders(
        DecryptedOrder[] memory orders,
        bytes32[] calldata orderIds
    ) internal {
        // Sort by timestamp to ensure FIFO within batch
        // This prevents relayer from reordering for MEV
        _sortByTimestamp(orders, orderIds);

        for (uint256 i = 0; i < orders.length; i++) {
            if (_canExecute(orders[i])) {
                uint256 amountOut = _executeSwap(orders[i]);

                EncryptedOrder storage order = orders[orderIds[i]];
                order.executed = true;

                emit OrderExecuted(orderIds[i], amountOut);
            }
        }
    }

    /**
     * @notice Slash relayer for protocol violations
     */
    function slashRelayer(
        address relayer,
        string calldata reason
    ) external {
        require(authorizedRelayers[msg.sender], "Not authorized");

        // Remove authorization
        authorizedRelayers[relayer] = false;

        // Slash collateral (would be staked separately)
        emit RelayerSlashed(relayer, slashAmount, reason);
    }

    // Internal helper functions

    function _rotateBatch() internal {
        currentBatchId++;
        lastBatchTime = block.timestamp;
    }

    function _verifyCommitment(
        DecryptedOrder memory order,
        bytes32 commitment
    ) internal pure returns (bool) {
        bytes32 computed = keccak256(abi.encode(order));
        return computed == commitment;
    }

    function _sortByTimestamp(
        DecryptedOrder[] memory orders,
        bytes32[] calldata orderIds
    ) internal view {
        // Bubble sort by timestamp (gas-optimized for small batches)
        for (uint256 i = 0; i < orders.length - 1; i++) {
            for (uint256 j = 0; j < orders.length - i - 1; j++) {
                if (this.orders(orderIds[j]).timestamp >
                    this.orders(orderIds[j + 1]).timestamp) {
                    // Swap
                    (orders[j], orders[j + 1]) = (orders[j + 1], orders[j]);
                }
            }
        }
    }

    function _canExecute(DecryptedOrder memory order) internal view returns (bool) {
        return block.timestamp <= order.deadline;
    }

    function _executeSwap(DecryptedOrder memory order) internal returns (uint256) {
        // Integration with AMM/orderbook would go here
        // Returns actual output amount
        return order.minAmountOut;
    }

    // Admin functions

    function authorizeRelayer(address relayer) external {
        authorizedRelayers[relayer] = true;
    }

    function setBatchDuration(uint256 duration) external {
        require(duration >= 1 seconds && duration <= 10 seconds, "Invalid duration");
        batchDuration = duration;
    }
}
