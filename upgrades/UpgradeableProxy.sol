// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";

/**
 * @title ProtocolUpgradeController
 * @notice Advanced protocol upgrade system with timelock, multi-sig, and rollback capabilities
 *
 * HYPOTHESIS: Protocol upgrades with 7-day timelock and multi-sig governance will provide
 * security guarantees while maintaining flexibility for critical bug fixes.
 *
 * SUCCESS METRICS:
 * - Zero unauthorized upgrades
 * - <4 hour response time for critical security patches (with emergency council)
 * - 100% successful rollback capability
 * - Full upgrade audit trail with cryptographic proofs
 *
 * SECURITY CONSIDERATIONS:
 * - Storage slot collision prevention using EIP-1967 standard slots
 * - Timelock to prevent flash governance attacks
 * - Multi-sig requirement for execution
 * - Emergency pause capability
 * - Rollback window for reverting problematic upgrades
 */

contract ProtocolUpgradeController is AccessControl, ReentrancyGuard {
    using Address for address;
    using StorageSlot for bytes32;

    // Roles
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant TIMELOCK_ADMIN_ROLE = keccak256("TIMELOCK_ADMIN_ROLE");

    // EIP-1967 standard storage slots for proxy contracts
    bytes32 internal constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 internal constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
    bytes32 internal constant BEACON_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1);

    // Upgrade proposal structure
    struct UpgradeProposal {
        uint256 id;
        address proposer;
        address targetProxy;
        address newImplementation;
        bytes32 codeHash;
        uint256 proposedAt;
        uint256 executionTime;
        bool executed;
        bool cancelled;
        uint256 approvals;
        string description;
        bytes migrationData;
        UpgradeType upgradeType;
    }

    // Types of upgrades
    enum UpgradeType {
        STANDARD,           // 7-day timelock
        SECURITY_PATCH,     // 2-day timelock with security council
        EMERGENCY           // 24-hour with emergency multisig (critical bugs only)
    }

    // Rollback information
    struct RollbackInfo {
        address previousImplementation;
        bytes32 previousCodeHash;
        uint256 upgradeTimestamp;
        uint256 rollbackDeadline;
        bool rolledBack;
    }

    // Storage
    mapping(uint256 => UpgradeProposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public proposalApprovals;
    mapping(address => RollbackInfo) public rollbackRegistry;
    mapping(address => address[]) public implementationHistory;
    mapping(address => bool) public registeredProxies;

    uint256 public proposalCount;
    uint256 public minApprovals = 3;
    uint256 public standardTimelock = 7 days;
    uint256 public securityPatchTimelock = 2 days;
    uint256 public emergencyTimelock = 24 hours;
    uint256 public rollbackWindow = 14 days;

    // Events
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        address targetProxy,
        address newImplementation,
        UpgradeType upgradeType,
        uint256 executionTime
    );
    event ProposalApproved(uint256 indexed proposalId, address indexed approver);
    event ProposalExecuted(uint256 indexed proposalId, address indexed executor);
    event ProposalCancelled(uint256 indexed proposalId, address indexed canceller);
    event UpgradeRolledBack(address indexed proxy, address previousImpl);
    event ProxyRegistered(address indexed proxy, address implementation);
    event EmergencyPause(address indexed proxy);
    event TimelockUpdated(UpgradeType upgradeType, uint256 newDuration);

    // Modifiers
    modifier onlyRegisteredProxy(address proxy) {
        require(registeredProxies[proxy], "Proxy not registered");
        _;
    }

    modifier proposalExists(uint256 proposalId) {
        require(proposalId < proposalCount, "Proposal does not exist");
        _;
    }

    modifier proposalNotExecuted(uint256 proposalId) {
        require(!proposals[proposalId].executed, "Already executed");
        require(!proposals[proposalId].cancelled, "Proposal cancelled");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(TIMELOCK_ADMIN_ROLE, admin);
    }

    /**
     * @notice Register a proxy contract for upgrade management
     * @param proxy Address of the proxy contract
     */
    function registerProxy(address proxy) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(proxy != address(0), "Invalid proxy address");
        require(!registeredProxies[proxy], "Already registered");

        address currentImpl = _getImplementation(proxy);
        require(currentImpl != address(0), "Invalid proxy implementation");

        registeredProxies[proxy] = true;
        implementationHistory[proxy].push(currentImpl);

        rollbackRegistry[proxy] = RollbackInfo({
            previousImplementation: address(0),
            previousCodeHash: bytes32(0),
            upgradeTimestamp: block.timestamp,
            rollbackDeadline: 0,
            rolledBack: false
        });

        emit ProxyRegistered(proxy, currentImpl);
    }

    /**
     * @notice Create an upgrade proposal
     * @param targetProxy Proxy contract to upgrade
     * @param newImplementation New implementation address
     * @param upgradeType Type of upgrade (affects timelock)
     * @param description Human-readable description of changes
     * @param migrationData Optional migration calldata
     */
    function proposeUpgrade(
        address targetProxy,
        address newImplementation,
        UpgradeType upgradeType,
        string calldata description,
        bytes calldata migrationData
    )
        external
        onlyRole(PROPOSER_ROLE)
        onlyRegisteredProxy(targetProxy)
        returns (uint256 proposalId)
    {
        require(newImplementation != address(0), "Invalid implementation");
        require(newImplementation.isContract(), "Implementation must be contract");

        // Verify implementation has required interface
        _verifyImplementationInterface(newImplementation);

        // Calculate execution time based on upgrade type
        uint256 executionTime = _calculateExecutionTime(upgradeType);

        // Get code hash for verification
        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(newImplementation)
        }

        proposalId = proposalCount++;

        proposals[proposalId] = UpgradeProposal({
            id: proposalId,
            proposer: msg.sender,
            targetProxy: targetProxy,
            newImplementation: newImplementation,
            codeHash: codeHash,
            proposedAt: block.timestamp,
            executionTime: executionTime,
            executed: false,
            cancelled: false,
            approvals: 0,
            description: description,
            migrationData: migrationData,
            upgradeType: upgradeType
        });

        emit ProposalCreated(
            proposalId,
            msg.sender,
            targetProxy,
            newImplementation,
            upgradeType,
            executionTime
        );
    }

    /**
     * @notice Approve an upgrade proposal
     * @param proposalId ID of the proposal to approve
     */
    function approveProposal(uint256 proposalId)
        external
        onlyRole(EXECUTOR_ROLE)
        proposalExists(proposalId)
        proposalNotExecuted(proposalId)
    {
        require(!proposalApprovals[proposalId][msg.sender], "Already approved");

        proposalApprovals[proposalId][msg.sender] = true;
        proposals[proposalId].approvals++;

        emit ProposalApproved(proposalId, msg.sender);
    }

    /**
     * @notice Execute an approved upgrade after timelock
     * @param proposalId ID of the proposal to execute
     */
    function executeUpgrade(uint256 proposalId)
        external
        nonReentrant
        onlyRole(EXECUTOR_ROLE)
        proposalExists(proposalId)
        proposalNotExecuted(proposalId)
    {
        UpgradeProposal storage proposal = proposals[proposalId];

        // Verify timelock has passed
        require(block.timestamp >= proposal.executionTime, "Timelock not expired");

        // Verify minimum approvals
        require(proposal.approvals >= minApprovals, "Insufficient approvals");

        // Verify code hash hasn't changed (prevents proxy attacks)
        bytes32 currentCodeHash;
        assembly {
            currentCodeHash := extcodehash(sload(add(proposal.slot, 3)))
        }

        address impl = proposal.newImplementation;
        assembly {
            currentCodeHash := extcodehash(impl)
        }
        require(currentCodeHash == proposal.codeHash, "Implementation code changed");

        // Store rollback information
        address currentImpl = _getImplementation(proposal.targetProxy);
        bytes32 currentHash;
        assembly {
            currentHash := extcodehash(currentImpl)
        }

        rollbackRegistry[proposal.targetProxy] = RollbackInfo({
            previousImplementation: currentImpl,
            previousCodeHash: currentHash,
            upgradeTimestamp: block.timestamp,
            rollbackDeadline: block.timestamp + rollbackWindow,
            rolledBack: false
        });

        // Update history
        implementationHistory[proposal.targetProxy].push(proposal.newImplementation);

        // Execute the upgrade
        _upgradeProxy(proposal.targetProxy, proposal.newImplementation);

        // Run migration if provided
        if (proposal.migrationData.length > 0) {
            (bool success, ) = proposal.targetProxy.call(proposal.migrationData);
            require(success, "Migration failed");
        }

        proposal.executed = true;

        emit ProposalExecuted(proposalId, msg.sender);
    }

    /**
     * @notice Cancel a pending upgrade proposal
     * @param proposalId ID of the proposal to cancel
     */
    function cancelProposal(uint256 proposalId)
        external
        proposalExists(proposalId)
        proposalNotExecuted(proposalId)
    {
        UpgradeProposal storage proposal = proposals[proposalId];

        require(
            msg.sender == proposal.proposer ||
            hasRole(TIMELOCK_ADMIN_ROLE, msg.sender),
            "Not authorized to cancel"
        );

        proposal.cancelled = true;

        emit ProposalCancelled(proposalId, msg.sender);
    }

    /**
     * @notice Rollback an upgrade within the rollback window
     * @param proxy Address of the proxy to rollback
     */
    function rollbackUpgrade(address proxy)
        external
        nonReentrant
        onlyRole(EMERGENCY_ROLE)
        onlyRegisteredProxy(proxy)
    {
        RollbackInfo storage info = rollbackRegistry[proxy];

        require(info.previousImplementation != address(0), "No rollback available");
        require(block.timestamp <= info.rollbackDeadline, "Rollback window expired");
        require(!info.rolledBack, "Already rolled back");

        // Verify the previous implementation still exists and hasn't been tampered with
        bytes32 currentHash;
        assembly {
            let impl := sload(info.slot)
            currentHash := extcodehash(impl)
        }

        address prevImpl = info.previousImplementation;
        assembly {
            currentHash := extcodehash(prevImpl)
        }
        require(currentHash == info.previousCodeHash, "Previous implementation compromised");

        // Execute rollback
        _upgradeProxy(proxy, info.previousImplementation);

        info.rolledBack = true;

        emit UpgradeRolledBack(proxy, info.previousImplementation);
    }

    /**
     * @notice Emergency pause a proxy contract
     * @param proxy Address of the proxy to pause
     */
    function emergencyPause(address proxy)
        external
        onlyRole(EMERGENCY_ROLE)
        onlyRegisteredProxy(proxy)
    {
        // Call pause function on the implementation
        (bool success, ) = proxy.call(
            abi.encodeWithSignature("pause()")
        );
        require(success, "Pause failed");

        emit EmergencyPause(proxy);
    }

    /**
     * @notice Update timelock duration for upgrade type
     * @param upgradeType Type of upgrade
     * @param newDuration New timelock duration in seconds
     */
    function updateTimelock(UpgradeType upgradeType, uint256 newDuration)
        external
        onlyRole(TIMELOCK_ADMIN_ROLE)
    {
        require(newDuration >= 1 hours, "Duration too short");
        require(newDuration <= 30 days, "Duration too long");

        if (upgradeType == UpgradeType.STANDARD) {
            standardTimelock = newDuration;
        } else if (upgradeType == UpgradeType.SECURITY_PATCH) {
            securityPatchTimelock = newDuration;
        } else if (upgradeType == UpgradeType.EMERGENCY) {
            emergencyTimelock = newDuration;
        }

        emit TimelockUpdated(upgradeType, newDuration);
    }

    /**
     * @notice Update minimum approvals required
     * @param newMinApprovals New minimum number of approvals
     */
    function updateMinApprovals(uint256 newMinApprovals)
        external
        onlyRole(TIMELOCK_ADMIN_ROLE)
    {
        require(newMinApprovals >= 2, "Min 2 approvals required");
        require(newMinApprovals <= 10, "Too many approvals required");
        minApprovals = newMinApprovals;
    }

    /**
     * @notice Get implementation history for a proxy
     * @param proxy Address of the proxy
     * @return Array of historical implementations
     */
    function getImplementationHistory(address proxy)
        external
        view
        returns (address[] memory)
    {
        return implementationHistory[proxy];
    }

    /**
     * @notice Get current implementation of a proxy
     * @param proxy Address of the proxy
     * @return Current implementation address
     */
    function getCurrentImplementation(address proxy)
        external
        view
        returns (address)
    {
        return _getImplementation(proxy);
    }

    /**
     * @notice Check if an upgrade can be executed
     * @param proposalId ID of the proposal
     * @return canExecute Whether the upgrade can be executed
     * @return reason Reason if it cannot be executed
     */
    function canExecuteUpgrade(uint256 proposalId)
        external
        view
        returns (bool canExecute, string memory reason)
    {
        if (proposalId >= proposalCount) {
            return (false, "Proposal does not exist");
        }

        UpgradeProposal storage proposal = proposals[proposalId];

        if (proposal.executed) {
            return (false, "Already executed");
        }
        if (proposal.cancelled) {
            return (false, "Proposal cancelled");
        }
        if (block.timestamp < proposal.executionTime) {
            return (false, "Timelock not expired");
        }
        if (proposal.approvals < minApprovals) {
            return (false, "Insufficient approvals");
        }

        return (true, "");
    }

    // Internal functions

    function _calculateExecutionTime(UpgradeType upgradeType)
        internal
        view
        returns (uint256)
    {
        if (upgradeType == UpgradeType.STANDARD) {
            return block.timestamp + standardTimelock;
        } else if (upgradeType == UpgradeType.SECURITY_PATCH) {
            return block.timestamp + securityPatchTimelock;
        } else {
            return block.timestamp + emergencyTimelock;
        }
    }

    function _getImplementation(address proxy) internal view returns (address) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        address impl;
        assembly {
            impl := sload(slot)
        }

        // Try to read from proxy's storage if direct read fails
        if (impl == address(0)) {
            (bool success, bytes memory data) = proxy.staticcall(
                abi.encodeWithSignature("implementation()")
            );
            if (success && data.length >= 32) {
                impl = abi.decode(data, (address));
            }
        }

        return impl;
    }

    function _upgradeProxy(address proxy, address newImplementation) internal {
        // Call upgradeTo on the proxy
        (bool success, ) = proxy.call(
            abi.encodeWithSignature("upgradeTo(address)", newImplementation)
        );

        if (!success) {
            // Try alternative upgrade pattern
            (success, ) = proxy.call(
                abi.encodeWithSignature("upgradeToAndCall(address,bytes)", newImplementation, "")
            );
        }

        require(success, "Upgrade failed");
    }

    function _verifyImplementationInterface(address implementation) internal view {
        // Verify the implementation has required functions
        // This is a basic check - production would have more comprehensive verification

        uint256 codeSize;
        assembly {
            codeSize := extcodesize(implementation)
        }
        require(codeSize > 0, "No code at implementation");
    }
}

/**
 * @title DiamondProxy
 * @notice EIP-2535 Diamond pattern implementation for modular upgrades
 *
 * Allows fine-grained function-level upgrades instead of monolithic contract upgrades
 */
contract DiamondProxy {
    // Facet structure for EIP-2535
    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }

    enum FacetCutAction {
        Add,
        Replace,
        Remove
    }

    // Storage using EIP-2535 diamond storage pattern
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) selectorToFacet;
        mapping(bytes4 => uint96) selectorToFacetIndex;
        bytes4[] selectors;
        mapping(address => uint256) facetAddressIndex;
        address[] facetAddresses;
        address owner;
        address pendingOwner;
    }

    event DiamondCut(FacetCut[] diamondCut, address init, bytes calldata_);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        DiamondStorage storage ds = diamondStorage();
        require(msg.sender == ds.owner, "Not owner");
        _;
    }

    constructor(address _owner) {
        DiamondStorage storage ds = diamondStorage();
        ds.owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Execute diamond cut (add/replace/remove functions)
     * @param _diamondCut Array of facet cuts to execute
     * @param _init Address of contract to execute initialization function
     * @param _calldata Calldata for initialization function
     */
    function diamondCut(
        FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external onlyOwner {
        DiamondStorage storage ds = diamondStorage();

        for (uint256 i = 0; i < _diamondCut.length; i++) {
            FacetCut memory cut = _diamondCut[i];

            if (cut.action == FacetCutAction.Add) {
                _addFunctions(ds, cut.facetAddress, cut.functionSelectors);
            } else if (cut.action == FacetCutAction.Replace) {
                _replaceFunctions(ds, cut.facetAddress, cut.functionSelectors);
            } else if (cut.action == FacetCutAction.Remove) {
                _removeFunctions(ds, cut.functionSelectors);
            }
        }

        emit DiamondCut(_diamondCut, _init, _calldata);

        // Execute initialization if provided
        if (_init != address(0)) {
            require(_init.code.length > 0, "Init address has no code");
            (bool success, bytes memory error) = _init.delegatecall(_calldata);
            if (!success) {
                if (error.length > 0) {
                    assembly {
                        let returndata_size := mload(error)
                        revert(add(32, error), returndata_size)
                    }
                } else {
                    revert("Init function reverted");
                }
            }
        }
    }

    function _addFunctions(
        DiamondStorage storage ds,
        address facetAddress,
        bytes4[] memory selectors
    ) internal {
        require(selectors.length > 0, "No selectors provided");
        require(facetAddress != address(0), "Invalid facet address");
        require(facetAddress.code.length > 0, "Facet has no code");

        // Add facet address if new
        if (ds.facetAddressIndex[facetAddress] == 0 &&
            (ds.facetAddresses.length == 0 || ds.facetAddresses[0] != facetAddress)) {
            ds.facetAddressIndex[facetAddress] = ds.facetAddresses.length;
            ds.facetAddresses.push(facetAddress);
        }

        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            require(ds.selectorToFacet[selector] == address(0), "Selector already added");

            ds.selectorToFacet[selector] = facetAddress;
            ds.selectorToFacetIndex[selector] = uint96(ds.selectors.length);
            ds.selectors.push(selector);
        }
    }

    function _replaceFunctions(
        DiamondStorage storage ds,
        address facetAddress,
        bytes4[] memory selectors
    ) internal {
        require(selectors.length > 0, "No selectors provided");
        require(facetAddress != address(0), "Invalid facet address");
        require(facetAddress.code.length > 0, "Facet has no code");

        // Add facet address if new
        if (ds.facetAddressIndex[facetAddress] == 0 &&
            (ds.facetAddresses.length == 0 || ds.facetAddresses[0] != facetAddress)) {
            ds.facetAddressIndex[facetAddress] = ds.facetAddresses.length;
            ds.facetAddresses.push(facetAddress);
        }

        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            address oldFacet = ds.selectorToFacet[selector];
            require(oldFacet != address(0), "Selector not found");
            require(oldFacet != facetAddress, "Same facet address");

            ds.selectorToFacet[selector] = facetAddress;
        }
    }

    function _removeFunctions(
        DiamondStorage storage ds,
        bytes4[] memory selectors
    ) internal {
        require(selectors.length > 0, "No selectors provided");

        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            require(ds.selectorToFacet[selector] != address(0), "Selector not found");

            // Replace selector with last selector
            uint96 selectorIndex = ds.selectorToFacetIndex[selector];
            uint256 lastSelectorIndex = ds.selectors.length - 1;

            if (selectorIndex != lastSelectorIndex) {
                bytes4 lastSelector = ds.selectors[lastSelectorIndex];
                ds.selectors[selectorIndex] = lastSelector;
                ds.selectorToFacetIndex[lastSelector] = selectorIndex;
            }

            ds.selectors.pop();
            delete ds.selectorToFacet[selector];
            delete ds.selectorToFacetIndex[selector];
        }
    }

    /**
     * @notice Get facet address for a function selector
     * @param selector Function selector
     * @return facet Facet address
     */
    function facetAddress(bytes4 selector) external view returns (address facet) {
        DiamondStorage storage ds = diamondStorage();
        facet = ds.selectorToFacet[selector];
    }

    /**
     * @notice Get all facet addresses
     * @return facetAddresses_ Array of facet addresses
     */
    function facetAddresses() external view returns (address[] memory facetAddresses_) {
        DiamondStorage storage ds = diamondStorage();
        facetAddresses_ = ds.facetAddresses;
    }

    /**
     * @notice Get all selectors for a facet
     * @param _facet Facet address
     * @return facetSelectors_ Array of selectors
     */
    function facetFunctionSelectors(address _facet)
        external
        view
        returns (bytes4[] memory facetSelectors_)
    {
        DiamondStorage storage ds = diamondStorage();
        uint256 count = 0;

        // Count selectors
        for (uint256 i = 0; i < ds.selectors.length; i++) {
            if (ds.selectorToFacet[ds.selectors[i]] == _facet) {
                count++;
            }
        }

        // Populate result
        facetSelectors_ = new bytes4[](count);
        count = 0;
        for (uint256 i = 0; i < ds.selectors.length; i++) {
            if (ds.selectorToFacet[ds.selectors[i]] == _facet) {
                facetSelectors_[count++] = ds.selectors[i];
            }
        }
    }

    // Fallback to delegate calls to facets
    fallback() external payable {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.selectorToFacet[msg.sig];
        require(facet != address(0), "Function not found");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/**
 * @title StorageLayoutManager
 * @notice Manages storage layout to prevent collisions during upgrades
 */
library StorageLayoutManager {
    // Compute storage slot using EIP-1967 pattern
    function computeSlot(string memory key) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(bytes(key))) - 1);
    }

    // Gap pattern for inheritance-safe upgrades
    struct StorageGap {
        uint256[50] __gap;
    }

    // Struct storage pattern
    function getStruct(bytes32 slot) internal pure returns (bytes32 position) {
        return slot;
    }

    // Array storage pattern
    function getArraySlot(bytes32 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(slot));
    }

    // Mapping storage pattern
    function getMappingSlot(bytes32 slot, bytes32 key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, slot));
    }
}

/**
 * @title UpgradeableBase
 * @notice Base contract for upgradeable implementations
 */
abstract contract UpgradeableBase {
    // Storage gap for future upgrades
    uint256[50] private __gap;

    // Initializable pattern
    bool private _initialized;
    bool private _initializing;

    modifier initializer() {
        require(
            _initializing || !_initialized,
            "Already initialized"
        );

        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }

        _;

        if (isTopLevelCall) {
            _initializing = false;
        }
    }

    modifier onlyInitializing() {
        require(_initializing, "Not initializing");
        _;
    }

    function _disableInitializers() internal virtual {
        require(!_initializing, "Already initializing");
        if (!_initialized) {
            _initialized = true;
        }
    }
}

/**
 * @title VersionedImplementation
 * @notice Tracks implementation versions for upgrade validation
 */
abstract contract VersionedImplementation is UpgradeableBase {
    event Upgraded(uint256 previousVersion, uint256 newVersion);

    // Version storage
    uint256 private _version;

    function version() public view returns (uint256) {
        return _version;
    }

    function _setVersion(uint256 newVersion) internal {
        require(newVersion > _version, "Version must increase");
        uint256 oldVersion = _version;
        _version = newVersion;
        emit Upgraded(oldVersion, newVersion);
    }
}
