// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ContractWatch Registry
 * @notice Smart contract security monitoring and threat intelligence platform on BOT Chain
 * @dev Central registry for user profiles, monitored contracts, monitoring rules, and alert records
 */

// ─────────────────────────────────────────────────────────────────────────────
//  Reentrancy Guard
// ─────────────────────────────────────────────────────────────────────────────
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Access Control
// ─────────────────────────────────────────────────────────────────────────────
abstract contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(_owner == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Pausable
// ─────────────────────────────────────────────────────────────────────────────
abstract contract Pausable is Ownable {
    bool private _paused;

    event Paused(address account);
    event Unpaused(address account);

    modifier whenNotPaused() {
        require(!_paused, "Pausable: contract is paused");
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function pause() external onlyOwner {
        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        _paused = false;
        emit Unpaused(msg.sender);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ContractWatch Main Contract
// ─────────────────────────────────────────────────────────────────────────────
contract ContractWatch is ReentrancyGuard, Pausable {

    // ── Constants ──────────────────────────────────────────────────────────
    uint256 public constant MAX_CONTRACTS_PER_USER = 50;
    uint256 public constant MAX_ALERTS_PER_CONTRACT = 500;
    uint8   public constant SEVERITY_LOW      = 1;
    uint8   public constant SEVERITY_MEDIUM   = 2;
    uint8   public constant SEVERITY_CRITICAL = 3;

    // ── Structs ────────────────────────────────────────────────────────────

    struct UserProfile {
        address wallet;
        string  username;
        string  email;          // stored as keccak256 hash off-chain; raw display only
        uint256 registeredAt;
        uint256 totalContracts;
        uint256 totalAlerts;
        bool    exists;
        bool    isPremium;
    }

    struct MonitoredContract {
        uint256 id;
        address contractAddress;
        string  networkName;
        uint256 networkChainId;
        string  name;
        string  description;
        address addedBy;
        uint256 addedAt;
        uint256 lastCheckedAt;
        bool    active;
        bool    exists;
    }

    struct MonitoringConfig {
        bool watchOwnershipChanges;
        bool watchMinting;
        bool watchLargeWithdrawals;
        bool watchAdminOps;
        bool watchUpgrades;
        bool watchAbnormalActivity;
        bool watchTokenMovements;
        uint256 largeWithdrawalThreshold;   // in wei
        uint256 abnormalTxThreshold;        // number of txs per block considered abnormal
    }

    struct SecurityAlert {
        uint256 id;
        uint256 contractId;
        string  alertType;
        string  description;
        string  txHash;         // the trigger transaction (if known)
        uint8   severity;       // 1=low, 2=medium, 3=critical
        uint256 detectedAt;
        bool    acknowledged;
        address acknowledgedBy;
        uint256 acknowledgedAt;
    }

    struct SecurityReport {
        uint256 id;
        uint256 contractId;
        address reportedBy;
        string  reportTitle;
        string  reportContent;
        uint8   severity;
        uint256 createdAt;
        uint256 upvotes;
    }

    // ── State ──────────────────────────────────────────────────────────────

    // Platform stats
    uint256 public totalUsers;
    uint256 public totalMonitoredContracts;
    uint256 public totalAlerts;
    uint256 public totalReports;

    // User registry
    mapping(address => UserProfile) private _users;
    address[] private _userAddresses;

    // Contract registry  — contractId => MonitoredContract
    uint256 private _nextContractId;
    mapping(uint256 => MonitoredContract)   private _contracts;
    mapping(uint256 => MonitoringConfig)    private _configs;
    mapping(address => uint256[])           private _userContractIds;  // user => contractIds[]

    // Alert registry
    uint256 private _nextAlertId;
    mapping(uint256 => SecurityAlert)       private _alerts;
    mapping(uint256 => uint256[])           private _contractAlerts; // contractId => alertIds[]
    mapping(address => uint256[])           private _userAlerts;     // user => alertIds[]

    // Report registry
    uint256 private _nextReportId;
    mapping(uint256 => SecurityReport)      private _reports;
    mapping(uint256 => uint256[])           private _contractReports; // contractId => reportIds[]

    // Admin whitelist
    mapping(address => bool) private _admins;

    // ── Events ─────────────────────────────────────────────────────────────

    event UserRegistered(address indexed wallet, string username, uint256 timestamp);
    event UserUpdated(address indexed wallet, string username, uint256 timestamp);
    event UserUpgraded(address indexed wallet, bool isPremium, uint256 timestamp);

    event ContractRegistered(
        uint256 indexed contractId,
        address indexed contractAddress,
        address indexed addedBy,
        string name,
        uint256 chainId,
        uint256 timestamp
    );
    event ContractDeactivated(uint256 indexed contractId, address indexed by, uint256 timestamp);
    event ContractChecked(uint256 indexed contractId, uint256 timestamp);
    event MonitoringConfigUpdated(uint256 indexed contractId, address indexed by, uint256 timestamp);

    event AlertCreated(
        uint256 indexed alertId,
        uint256 indexed contractId,
        address indexed targetUser,
        string alertType,
        uint8 severity,
        uint256 timestamp
    );
    event AlertAcknowledged(
        uint256 indexed alertId,
        address indexed acknowledgedBy,
        uint256 timestamp
    );

    event ReportCreated(
        uint256 indexed reportId,
        uint256 indexed contractId,
        address indexed reportedBy,
        string reportTitle,
        uint8 severity,
        uint256 timestamp
    );
    event ReportUpvoted(uint256 indexed reportId, address indexed voter, uint256 timestamp);

    event AdminAdded(address indexed admin, uint256 timestamp);
    event AdminRemoved(address indexed admin, uint256 timestamp);

    // ── Modifiers ──────────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(_admins[msg.sender] || msg.sender == owner(), "ContractWatch: not admin");
        _;
    }

    modifier userExists(address wallet) {
        require(_users[wallet].exists, "ContractWatch: user not registered");
        _;
    }

    modifier contractExists(uint256 contractId) {
        require(_contracts[contractId].exists, "ContractWatch: contract not found");
        _;
    }

    modifier contractOwner(uint256 contractId) {
        require(
            _contracts[contractId].addedBy == msg.sender || _admins[msg.sender] || msg.sender == owner(),
            "ContractWatch: not contract owner"
        );
        _;
    }

    // ── Constructor ────────────────────────────────────────────────────────

    constructor() {
        _nextContractId = 1;
        _nextAlertId    = 1;
        _nextReportId   = 1;
        _admins[msg.sender] = true;
        emit AdminAdded(msg.sender, block.timestamp);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  USER MANAGEMENT
    // ══════════════════════════════════════════════════════════════════════

    /**
     * @notice Register a new user profile
     * @param username  Display name (must be non-empty)
     * @param email     Contact email (optional; kept as plain string — advise off-chain hashing for PII)
     */
    function registerUser(string calldata username, string calldata email)
        external
        whenNotPaused
        nonReentrant
    {
        require(!_users[msg.sender].exists, "ContractWatch: already registered");
        require(bytes(username).length > 0, "ContractWatch: username required");
        require(bytes(username).length <= 50, "ContractWatch: username too long");

        _users[msg.sender] = UserProfile({
            wallet:         msg.sender,
            username:       username,
            email:          email,
            registeredAt:   block.timestamp,
            totalContracts: 0,
            totalAlerts:    0,
            exists:         true,
            isPremium:      false
        });

        _userAddresses.push(msg.sender);
        totalUsers++;

        emit UserRegistered(msg.sender, username, block.timestamp);
    }

    /**
     * @notice Update your own profile
     */
    function updateProfile(string calldata username, string calldata email)
        external
        whenNotPaused
        userExists(msg.sender)
    {
        require(bytes(username).length > 0, "ContractWatch: username required");
        require(bytes(username).length <= 50, "ContractWatch: username too long");

        _users[msg.sender].username = username;
        _users[msg.sender].email    = email;

        emit UserUpdated(msg.sender, username, block.timestamp);
    }

    /**
     * @notice Get the caller's own profile
     */
    function getMyProfile() external view returns (UserProfile memory) {
        return _users[msg.sender];
    }

    /**
     * @notice Get any user profile (public data)
     */
    function getUserProfile(address wallet) external view returns (UserProfile memory) {
        return _users[wallet];
    }

    /**
     * @notice Check whether a wallet is already registered
     */
    function isRegistered(address wallet) external view returns (bool) {
        return _users[wallet].exists;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  CONTRACT MONITORING
    // ══════════════════════════════════════════════════════════════════════

    /**
     * @notice Register a smart contract for security monitoring
     */
    function registerContract(
        address contractAddress,
        string  calldata networkName,
        uint256 networkChainId,
        string  calldata name,
        string  calldata description
    )
        external
        whenNotPaused
        nonReentrant
        userExists(msg.sender)
        returns (uint256 contractId)
    {
        require(contractAddress != address(0), "ContractWatch: zero address");
        require(bytes(name).length > 0,        "ContractWatch: name required");
        require(bytes(name).length <= 100,     "ContractWatch: name too long");
        require(bytes(description).length <= 500, "ContractWatch: description too long");
        require(
            _userContractIds[msg.sender].length < MAX_CONTRACTS_PER_USER,
            "ContractWatch: contract limit reached"
        );

        contractId = _nextContractId++;

        _contracts[contractId] = MonitoredContract({
            id:              contractId,
            contractAddress: contractAddress,
            networkName:     networkName,
            networkChainId:  networkChainId,
            name:            name,
            description:     description,
            addedBy:         msg.sender,
            addedAt:         block.timestamp,
            lastCheckedAt:   block.timestamp,
            active:          true,
            exists:          true
        });

        // Default monitoring config — watch everything by default
        _configs[contractId] = MonitoringConfig({
            watchOwnershipChanges:   true,
            watchMinting:            true,
            watchLargeWithdrawals:   true,
            watchAdminOps:           true,
            watchUpgrades:           true,
            watchAbnormalActivity:   true,
            watchTokenMovements:     true,
            largeWithdrawalThreshold: 1 ether,
            abnormalTxThreshold:     100
        });

        _userContractIds[msg.sender].push(contractId);
        _users[msg.sender].totalContracts++;
        totalMonitoredContracts++;

        emit ContractRegistered(contractId, contractAddress, msg.sender, name, networkChainId, block.timestamp);
    }

    /**
     * @notice Update monitoring configuration for a contract
     */
    function updateMonitoringConfig(
        uint256 contractId,
        bool watchOwnershipChanges,
        bool watchMinting,
        bool watchLargeWithdrawals,
        bool watchAdminOps,
        bool watchUpgrades,
        bool watchAbnormalActivity,
        bool watchTokenMovements,
        uint256 largeWithdrawalThreshold,
        uint256 abnormalTxThreshold
    )
        external
        whenNotPaused
        contractExists(contractId)
        contractOwner(contractId)
    {
        _configs[contractId] = MonitoringConfig({
            watchOwnershipChanges:   watchOwnershipChanges,
            watchMinting:            watchMinting,
            watchLargeWithdrawals:   watchLargeWithdrawals,
            watchAdminOps:           watchAdminOps,
            watchUpgrades:           watchUpgrades,
            watchAbnormalActivity:   watchAbnormalActivity,
            watchTokenMovements:     watchTokenMovements,
            largeWithdrawalThreshold: largeWithdrawalThreshold,
            abnormalTxThreshold:     abnormalTxThreshold
        });

        emit MonitoringConfigUpdated(contractId, msg.sender, block.timestamp);
    }

    /**
     * @notice Deactivate (stop monitoring) a contract
     */
    function deactivateContract(uint256 contractId)
        external
        whenNotPaused
        contractExists(contractId)
        contractOwner(contractId)
    {
        _contracts[contractId].active = false;
        _users[_contracts[contractId].addedBy].totalContracts--;
        totalMonitoredContracts--;

        emit ContractDeactivated(contractId, msg.sender, block.timestamp);
    }

    /**
     * @notice Update the last-checked timestamp (called by the frontend monitor)
     */
    function markContractChecked(uint256 contractId)
        external
        whenNotPaused
        contractExists(contractId)
        contractOwner(contractId)
    {
        _contracts[contractId].lastCheckedAt = block.timestamp;
        emit ContractChecked(contractId, block.timestamp);
    }

    /**
     * @notice Get a single monitored contract
     */
    function getContract(uint256 contractId)
        external
        view
        contractExists(contractId)
        returns (MonitoredContract memory, MonitoringConfig memory)
    {
        return (_contracts[contractId], _configs[contractId]);
    }

    /**
     * @notice Get all contract IDs owned by a user
     */
    function getUserContractIds(address wallet) external view returns (uint256[] memory) {
        return _userContractIds[wallet];
    }

    /**
     * @notice Get the caller's contract IDs
     */
    function getMyContractIds() external view returns (uint256[] memory) {
        return _userContractIds[msg.sender];
    }

    // ══════════════════════════════════════════════════════════════════════
    //  ALERT MANAGEMENT
    // ══════════════════════════════════════════════════════════════════════

    /**
     * @notice Record a security alert (called by the frontend after detecting an event)
     * @dev Frontend queries BOT Chain RPC; this stores the confirmed alert on-chain
     */
    function createAlert(
        uint256 contractId,
        string  calldata alertType,
        string  calldata description,
        string  calldata txHash,
        uint8   severity
    )
        external
        whenNotPaused
        nonReentrant
        contractExists(contractId)
        contractOwner(contractId)
        returns (uint256 alertId)
    {
        require(severity >= SEVERITY_LOW && severity <= SEVERITY_CRITICAL, "ContractWatch: invalid severity");
        require(bytes(alertType).length > 0, "ContractWatch: alertType required");
        require(bytes(description).length <= 1000, "ContractWatch: description too long");
        require(
            _contractAlerts[contractId].length < MAX_ALERTS_PER_CONTRACT,
            "ContractWatch: alert limit reached"
        );

        alertId = _nextAlertId++;

        _alerts[alertId] = SecurityAlert({
            id:             alertId,
            contractId:     contractId,
            alertType:      alertType,
            description:    description,
            txHash:         txHash,
            severity:       severity,
            detectedAt:     block.timestamp,
            acknowledged:   false,
            acknowledgedBy: address(0),
            acknowledgedAt: 0
        });

        address contractOwnerAddr = _contracts[contractId].addedBy;
        _contractAlerts[contractId].push(alertId);
        _userAlerts[contractOwnerAddr].push(alertId);
        _users[contractOwnerAddr].totalAlerts++;
        totalAlerts++;

        emit AlertCreated(alertId, contractId, contractOwnerAddr, alertType, severity, block.timestamp);
    }

    /**
     * @notice Acknowledge (dismiss) an alert
     */
    function acknowledgeAlert(uint256 alertId)
        external
        whenNotPaused
        userExists(msg.sender)
    {
        SecurityAlert storage alert = _alerts[alertId];
        require(alert.id != 0,       "ContractWatch: alert not found");
        require(!alert.acknowledged, "ContractWatch: already acknowledged");

        // Only the contract owner or an admin may acknowledge
        uint256 cid = alert.contractId;
        require(
            _contracts[cid].addedBy == msg.sender || _admins[msg.sender] || msg.sender == owner(),
            "ContractWatch: not authorised"
        );

        alert.acknowledged   = true;
        alert.acknowledgedBy = msg.sender;
        alert.acknowledgedAt = block.timestamp;

        emit AlertAcknowledged(alertId, msg.sender, block.timestamp);
    }

    /**
     * @notice Get a single alert
     */
    function getAlert(uint256 alertId) external view returns (SecurityAlert memory) {
        require(_alerts[alertId].id != 0, "ContractWatch: alert not found");
        return _alerts[alertId];
    }

    /**
     * @notice Get all alert IDs for a contract
     */
    function getContractAlertIds(uint256 contractId) external view returns (uint256[] memory) {
        return _contractAlerts[contractId];
    }

    /**
     * @notice Get all alert IDs belonging to the caller
     */
    function getMyAlertIds() external view returns (uint256[] memory) {
        return _userAlerts[msg.sender];
    }

    // ══════════════════════════════════════════════════════════════════════
    //  SECURITY REPORTS
    // ══════════════════════════════════════════════════════════════════════

    /**
     * @notice Submit a user-generated security report for a monitored contract
     */
    function createReport(
        uint256 contractId,
        string  calldata reportTitle,
        string  calldata reportContent,
        uint8   severity
    )
        external
        whenNotPaused
        nonReentrant
        contractExists(contractId)
        userExists(msg.sender)
        returns (uint256 reportId)
    {
        require(severity >= SEVERITY_LOW && severity <= SEVERITY_CRITICAL, "ContractWatch: invalid severity");
        require(bytes(reportTitle).length > 0 && bytes(reportTitle).length <= 200, "ContractWatch: invalid title");
        require(bytes(reportContent).length > 0 && bytes(reportContent).length <= 2000, "ContractWatch: content too long");

        reportId = _nextReportId++;

        _reports[reportId] = SecurityReport({
            id:            reportId,
            contractId:    contractId,
            reportedBy:    msg.sender,
            reportTitle:   reportTitle,
            reportContent: reportContent,
            severity:      severity,
            createdAt:     block.timestamp,
            upvotes:       0
        });

        _contractReports[contractId].push(reportId);
        totalReports++;

        emit ReportCreated(reportId, contractId, msg.sender, reportTitle, severity, block.timestamp);
    }

    /**
     * @notice Upvote a security report
     */
    function upvoteReport(uint256 reportId)
        external
        whenNotPaused
        userExists(msg.sender)
    {
        require(_reports[reportId].id != 0, "ContractWatch: report not found");
        require(_reports[reportId].reportedBy != msg.sender, "ContractWatch: cannot upvote own report");

        _reports[reportId].upvotes++;
        emit ReportUpvoted(reportId, msg.sender, block.timestamp);
    }

    /**
     * @notice Get a single report
     */
    function getReport(uint256 reportId) external view returns (SecurityReport memory) {
        require(_reports[reportId].id != 0, "ContractWatch: report not found");
        return _reports[reportId];
    }

    /**
     * @notice Get all report IDs for a contract
     */
    function getContractReportIds(uint256 contractId) external view returns (uint256[] memory) {
        return _contractReports[contractId];
    }

    // ══════════════════════════════════════════════════════════════════════
    //  ADMIN FUNCTIONS
    // ══════════════════════════════════════════════════════════════════════

    function addAdmin(address admin) external onlyOwner {
        require(!_admins[admin], "ContractWatch: already admin");
        _admins[admin] = true;
        emit AdminAdded(admin, block.timestamp);
    }

    function removeAdmin(address admin) external onlyOwner {
        require(_admins[admin], "ContractWatch: not admin");
        _admins[admin] = false;
        emit AdminRemoved(admin, block.timestamp);
    }

    function isAdmin(address addr) external view returns (bool) {
        return _admins[addr];
    }

    function setPremium(address wallet, bool premium) external onlyAdmin {
        require(_users[wallet].exists, "ContractWatch: user not found");
        _users[wallet].isPremium = premium;
        emit UserUpgraded(wallet, premium, block.timestamp);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  PLATFORM STATS
    // ══════════════════════════════════════════════════════════════════════

    function getPlatformStats()
        external
        view
        returns (
            uint256 _totalUsers,
            uint256 _totalContracts,
            uint256 _totalAlerts,
            uint256 _totalReports
        )
    {
        return (totalUsers, totalMonitoredContracts, totalAlerts, totalReports);
    }
}
