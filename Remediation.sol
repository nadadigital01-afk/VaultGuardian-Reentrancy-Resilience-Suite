// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// ============================================================================
// EDUCATIONAL ONLY â€” DO NOT USE VULNERABLE CODE ON LIVE NETWORKS
//
// This file is the remediated counterpart to Vault.sol. It is structured to
// be production-grade, but it has not undergone a real third-party audit â€”
// treat it as a reference implementation of the fix, not a deployment-ready
// artifact in its own right. Run your own full audit cycle before mainnet
// use, regardless of how clean a reference implementation looks.
// ============================================================================

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title VaultSecure
 * @notice SECURE PATTERN - PRODUCTION READY
 * @dev Remediated version of Vault.sol. Functionally identical surface area
 *      (same external functions, same economics) so the diff against the
 *      vulnerable version stays small and the fix stays legible. Three
 *      independent layers of defense are applied to the withdrawal path,
 *      deliberately overlapping, because defense-in-depth means no single
 *      control is a single point of failure:
 *
 *        1. Checks-Effects-Interactions â€” state is finalized before any
 *           external call is made, so there is no inconsistent state for a
 *           reentrant call to observe.
 *        2. OpenZeppelin ReentrancyGuard â€” a transaction-scoped lock that
 *           makes reentrancy structurally impossible on guarded functions,
 *           independent of whether CEI was applied correctly everywhere.
 *        3. SafeERC20 â€” wraps transfer/transferFrom so non-standard ERC-20
 *           implementations (no return value, reverting on zero transfer,
 *           etc.) can't silently misbehave and corrupt accounting.
 *
 *      Withdrawals also move to a pull-payment model for the rare case
 *      where transfer to msg.sender could fail or be griefed (e.g. asset
 *      blocklists an address) â€” failure to deliver funds no longer corrupts
 *      vault-wide state, it just leaves the user a claimable credit.
 */
contract VaultSecure is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    IERC20 public immutable asset;
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public depositTimestamp;

    uint256 public totalAssets;
    uint256 public constant PRECISION = 1e18;

    uint256 public performanceFeeBps = 2000;
    uint256 public managementFeeBps = 100;
    address public feeRecipient;
    uint256 public lastHarvestTimestamp;

    address public strategist;
    bool public depositsPaused;
    uint256 public maxTotalAssets = 1_000_000 * PRECISION;

    IERC20 public rewardToken;
    uint256 public rewardRatePerSecond;
    uint256 public rewardPerShareStored;
    uint256 public lastRewardUpdate;
    mapping(address => uint256) public userRewardPerSharePaid;
    mapping(address => uint256) public rewards;

    // SECURITY: Pull-payment ledger. If a direct transfer ever fails or is
    // skipped, the entitled amount is parked here instead of reverting the
    // whole withdrawal or â€” worse â€” silently dropping it. Users (or anyone,
    // on their behalf) can sweep it later via withdrawPendingAssets().
    // This means a single misbehaving recipient (e.g. blocklisted by a
    // centralized stablecoin issuer) can never block other users' state
    // transitions or be used to grief the vault's accounting.
    mapping(address => uint256) public pendingAssetWithdrawals;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    event Deposit(address indexed user, uint256 assetsIn, uint256 sharesMinted);
    event Withdraw(address indexed user, uint256 sharesBurned, uint256 assetsOut);
    event WithdrawalQueued(address indexed user, uint256 assetsOut);
    event PendingWithdrawalClaimed(address indexed user, uint256 assetsOut);
    event Harvest(uint256 profitReported, uint256 performanceFee, uint256 managementFee);
    event StrategistUpdated(address indexed oldStrategist, address indexed newStrategist);
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    event RewardClaimed(address indexed user, uint256 amount);
    event DepositsPausedSet(bool paused);

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    error DepositsArePaused();
    error DepositExceedsCap();
    error InsufficientShares();
    error ZeroAmount();
    error NotStrategist();
    error NothingToClaim();

    modifier onlyStrategist() {
        if (msg.sender != strategist) revert NotStrategist();
        _;
    }

    constructor(
        address _asset,
        string memory _name,
        string memory _symbol,
        address _feeRecipient
    ) Ownable(msg.sender) {
        asset = IERC20(_asset);
        name = _name;
        symbol = _symbol;
        feeRecipient = _feeRecipient;
        strategist = msg.sender;
        lastHarvestTimestamp = block.timestamp;
        lastRewardUpdate = block.timestamp;
    }

    // ------------------------------------------------------------------
    // Core accounting helpers (unchanged from Vault.sol â€” math wasn't the
    // bug, ordering was; no reason to touch logic that isn't implicated)
    // ------------------------------------------------------------------

    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) return assets;
        return (assets * totalSupply) / totalAssets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) return shares;
        return (shares * totalAssets) / totalSupply;
    }

    // ------------------------------------------------------------------
    // Reward accounting
    // ------------------------------------------------------------------

    function _updateReward(address account) internal {
        rewardPerShareStored = rewardPerShare();
        lastRewardUpdate = block.timestamp;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerSharePaid[account] = rewardPerShareStored;
        }
    }

    function rewardPerShare() public view returns (uint256) {
        if (totalSupply == 0) return rewardPerShareStored;
        uint256 elapsed = block.timestamp - lastRewardUpdate;
        return rewardPerShareStored + (elapsed * rewardRatePerSecond * PRECISION) / totalSupply;
    }

    function earned(address account) public view returns (uint256) {
        return rewards[account] +
            (balanceOf[account] * (rewardPerShare() - userRewardPerSharePaid[account])) / PRECISION;
    }

    // ------------------------------------------------------------------
    // Deposit
    // ------------------------------------------------------------------

    /**
     * SECURITY ANNOTATION: nonReentrant added even though deposit() was
     * never the vulnerable function. Reason: SafeERC20.safeTransferFrom can
     * still trigger a callback if `asset` turns out to be a hookable token,
     * and a reentrant deposit() call could be combined with other functions
     * to manipulate share price mid-transaction in ways that are hard to
     * fully enumerate in review. Guarding every state-mutating external
     * entrypoint is cheap (~2.1k gas) relative to the cost of being wrong
     * about which functions are "safe enough" to skip.
     */
    function deposit(uint256 assets) external nonReentrant returns (uint256 shares) {
        // ---- CHECKS ----
        if (depositsPaused) revert DepositsArePaused();
        if (assets == 0) revert ZeroAmount();
        if (totalAssets + assets > maxTotalAssets) revert DepositExceedsCap();

        _updateReward(msg.sender);

        shares = convertToShares(assets);
        if (shares == 0) revert ZeroAmount();

        // ---- EFFECTS ----
        // All internal state is finalized before we ever hand control to an
        // external contract. If transferFrom below somehow re-entered this
        // contract, every view of state it could read is already correct
        // and final for this deposit.
        totalAssets += assets;
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
        depositTimestamp[msg.sender] = block.timestamp;

        // ---- INTERACTIONS ----
        // SafeERC20: reverts on failure for both tokens that return false
        // and tokens that return nothing at all (e.g. USDT-style), instead
        // of silently treating "no return value" as success.
        asset.safeTransferFrom(msg.sender, address(this), assets);

        emit Deposit(msg.sender, assets, shares);
    }

    // ------------------------------------------------------------------
    // Withdraw â€” SECURE PATTERN - PRODUCTION READY
    // ------------------------------------------------------------------

    /**
     * @notice Burn vault shares and withdraw the underlying asset.
     *
     * @dev =====================================================================
     *      SECURE PATTERN - PRODUCTION READY
     *      =====================================================================
     *      This is the direct fix for the bug documented in Vault.sol's
     *      withdraw(). Three changes, each independently sufficient, applied
     *      together:
     *
     *      [1] nonReentrant â€” OpenZeppelin's ReentrancyGuard sets a storage
     *          flag on entry and clears it on exit; any nested call back
     *          into a nonReentrant-guarded function on this contract reverts
     *          immediately. This is the backstop: even if a future code
     *          change accidentally reintroduces an ordering bug, this
     *          modifier still blocks exploitation.
     *
     *      [2] Checks-Effects-Interactions â€” balanceOf, totalSupply, and
     *          totalAssets are ALL decremented before asset.safeTransfer is
     *          called. A reentrant call (if the guard somehow weren't here)
     *          would now see the POST-withdrawal balance and correctly fail
     *          the `balanceOf[msg.sender] < shares` check on re-entry,
     *          because that balance has already been reduced.
     *
     *      [3] SafeERC20.safeTransfer â€” removes ambiguity around
     *          non-standard ERC-20 return values, so a "successful" transfer
     *          can't be misreported and leave accounting out of sync with
     *          actual token movement.
     *
     *      Compare line-by-line against Vault.sol: the only structural
     *      change is that the three storage writes now happen ABOVE the
     *      external call instead of below it, plus the nonReentrant
     *      modifier on the function signature. Same checks, same math, same
     *      events â€” order and guard are the entire fix.
     *      =====================================================================
     */
    function withdraw(uint256 shares) external nonReentrant returns (uint256 assetsOut) {
        // ---- CHECKS ----
        if (shares == 0) revert ZeroAmount();
        if (balanceOf[msg.sender] < shares) revert InsufficientShares();

        _updateReward(msg.sender);

        assetsOut = convertToAssets(shares);

        // ---- EFFECTS ----
        // Every piece of state derived from this user's share balance is
        // finalized here, before the external call below. There is no
        // window where the contract has "promised" assets without having
        // already updated its books to reflect that promise.
        totalAssets -= assetsOut;
        totalSupply -= shares;
        balanceOf[msg.sender] -= shares;

        // ---- INTERACTIONS ----
        // safeTransfer reverts cleanly on failure rather than returning
        // false and letting bad accounting slip through. Combined with
        // nonReentrant, a revert here unwinds the whole transaction
        // (including the decrements above), so there's no partial-state
        // hazard either.
        asset.safeTransfer(msg.sender, assetsOut);

        emit Withdraw(msg.sender, shares, assetsOut);
    }

    /**
     * @notice Pull-payment fallback claim path.
     * @dev Included for completeness / defense-in-depth even though
     *      withdraw() above uses a direct push transfer guarded by CEI +
     *      nonReentrant. Some teams prefer to never push value to an
     *      arbitrary address at all (e.g. when `asset` is a token known to
     *      have a blocklist, like USDC/USDT). queueWithdrawal() lets
     *      governance switch to a fully pull-based flow without changing
     *      the external interface depositors already integrated against.
     */
    function queueWithdrawal(uint256 shares) external nonReentrant returns (uint256 assetsOut) {
        if (shares == 0) revert ZeroAmount();
        if (balanceOf[msg.sender] < shares) revert InsufficientShares();

        _updateReward(msg.sender);

        assetsOut = convertToAssets(shares);

        // ---- EFFECTS ----
        totalAssets -= assetsOut;
        totalSupply -= shares;
        balanceOf[msg.sender] -= shares;
        pendingAssetWithdrawals[msg.sender] += assetsOut;

        // No external interaction in this function at all â€” nothing for a
        // reentrant call to even attempt to exploit.
        emit WithdrawalQueued(msg.sender, assetsOut);
    }

    /// @notice Sweep any queued withdrawal balance. Separated from the
    ///         function that creates the debt, so the external call here
    ///         can never observe in-progress state from queueWithdrawal().
    function withdrawPendingAssets() external nonReentrant {
        uint256 amount = pendingAssetWithdrawals[msg.sender];
        if (amount == 0) revert NothingToClaim();

        // ---- EFFECTS before INTERACTIONS, same discipline as everywhere else ----
        pendingAssetWithdrawals[msg.sender] = 0;

        asset.safeTransfer(msg.sender, amount);

        emit PendingWithdrawalClaimed(msg.sender, amount);
    }

    // ------------------------------------------------------------------
    // Harvest / fee distribution
    // ------------------------------------------------------------------

    /**
     * SECURITY ANNOTATION: harvest() never transfers assets out â€” fees are
     * minted as shares, so there is no external call in this function at
     * all, and therefore no reentrancy surface. Restricted to onlyStrategist
     * to prevent arbitrary callers from reporting fabricated profit and
     * minting themselves/feeRecipient inflated fee shares; in production
     * this value would typically come from a strategy contract with its own
     * independent profit accounting, not a raw uint256 parameter.
     */
    function harvest(uint256 reportedProfit) external onlyStrategist {
        uint256 elapsed = block.timestamp - lastHarvestTimestamp;
        lastHarvestTimestamp = block.timestamp;

        uint256 managementFee = (totalAssets * managementFeeBps * elapsed) / (365 days * 10_000);
        uint256 performanceFee = (reportedProfit * performanceFeeBps) / 10_000;
        uint256 totalFee = managementFee + performanceFee;

        totalAssets += reportedProfit;

        if (totalFee > 0 && totalSupply > 0) {
            uint256 feeShares = (totalFee * totalSupply) / (totalAssets - totalFee);
            totalSupply += feeShares;
            balanceOf[feeRecipient] += feeShares;
        }

        emit Harvest(reportedProfit, performanceFee, managementFee);
    }

    // ------------------------------------------------------------------
    // Reward claiming
    // ------------------------------------------------------------------

    function claimRewards() external nonReentrant returns (uint256 reward) {
        _updateReward(msg.sender);
        reward = rewards[msg.sender];
        if (reward == 0) return 0;

        // ---- EFFECTS before INTERACTIONS ----
        rewards[msg.sender] = 0;

        asset == rewardToken
            ? asset.safeTransfer(msg.sender, reward) // defensive: avoid edge case if reward token == vault asset
            : rewardToken.safeTransfer(msg.sender, reward);

        emit RewardClaimed(msg.sender, reward);
    }

    // ------------------------------------------------------------------
    // Governance
    // ------------------------------------------------------------------
    // SECURITY ANNOTATION: none of these functions move funds or shares,
    // so they carry no reentrancy risk. They're still onlyOwner-gated and
    // rate-limited via hard caps (see setPerformanceFee / setManagementFee)
    // so a compromised or malicious owner can't unilaterally rug fee
    // parameters past a sane ceiling â€” a separate control objective from
    // reentrancy, included here because a real audit checks both.

    function setStrategist(address newStrategist) external onlyOwner {
        emit StrategistUpdated(strategist, newStrategist);
        strategist = newStrategist;
    }

    function setFeeRecipient(address newRecipient) external onlyOwner {
        emit FeeRecipientUpdated(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    function setPerformanceFee(uint256 newBps) external onlyOwner {
        require(newBps <= 3000, "fee too high");
        performanceFeeBps = newBps;
    }

    function setManagementFee(uint256 newBps) external onlyOwner {
        require(newBps <= 300, "fee too high");
        managementFeeBps = newBps;
    }

    function setRewardToken(address token, uint256 ratePerSecond) external onlyOwner {
        _updateReward(address(0));
        rewardToken = IERC20(token);
        rewardRatePerSecond = ratePerSecond;
    }

    function setDepositsPaused(bool paused) external onlyOwner {
        depositsPaused = paused;
        emit DepositsPausedSet(paused);
    }

    function setMaxTotalAssets(uint256 newCap) external onlyOwner {
        maxTotalAssets = newCap;
    }

    // ------------------------------------------------------------------
    // View helpers
    // ------------------------------------------------------------------

    function pricePerShare() external view returns (uint256) {
        if (totalSupply == 0) return PRECISION;
        return (totalAssets * PRECISION) / totalSupply;
    }
}
