// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// ============================================================================
// EDUCATIONAL ONLY â€” DO NOT USE VULNERABLE CODE ON LIVE NETWORKS
//
// This contract contains a deliberately introduced reentrancy vulnerability.
// It exists solely to teach vulnerability identification and exploitation
// mechanics in a controlled, local environment. Every transfer of value in
// this file uses MOCK tokens on a local chain (Hardhat/Foundry, chainid
// 31337). Do not deploy this bytecode to any network with real value.
// ============================================================================

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title Vault
 * @notice Single-asset yield vault with performance fees and a basic
 *         governance-controlled strategy allocation. Modeled loosely on the
 *         share-accounting pattern used by Yearn v1/v2 vaults.
 * @dev    THIS VERSION IS INTENTIONALLY VULNERABLE. See withdraw() below.
 *         Compare against Remediation.sol for the corrected implementation.
 *
 *         I'm leaving the vulnerable code path completely intact rather than
 *         pseudo-coding it, because half of what makes reentrancy hard to
 *         spot in review is that the surrounding code looks completely
 *         normal â€” fee math, event emission, share burns, all present and
 *         correct. The bug is one line out of order, not a missing feature.
 */
contract Vault is Ownable {
    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    IERC20 public immutable asset;          // underlying deposit token (mock ERC20 in tests)
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    uint256 public totalSupply;             // total vault shares outstanding
    mapping(address => uint256) public balanceOf;     // shares per user
    mapping(address => uint256) public depositTimestamp; // for time-locked bonus yield

    uint256 public totalAssets;             // asset units currently tracked by the vault
    uint256 public constant PRECISION = 1e18;

    // Fee configuration â€” basis points, 10_000 = 100%
    uint256 public performanceFeeBps = 2000;   // 20% of yield goes to feeRecipient
    uint256 public managementFeeBps = 100;     // 1% annualized, accrued on harvest
    address public feeRecipient;
    uint256 public lastHarvestTimestamp;

    // Governance / strategy
    address public strategist;
    bool public depositsPaused;
    uint256 public maxTotalAssets = 1_000_000 * PRECISION; // deposit cap

    // Simple reward accounting for a secondary incentive token (e.g. governance token emissions)
    IERC20 public rewardToken;
    uint256 public rewardRatePerSecond;
    uint256 public rewardPerShareStored;
    uint256 public lastRewardUpdate;
    mapping(address => uint256) public userRewardPerSharePaid;
    mapping(address => uint256) public rewards;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    event Deposit(address indexed user, uint256 assetsIn, uint256 sharesMinted);
    event Withdraw(address indexed user, uint256 sharesBurned, uint256 assetsOut);
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
    error TransferFailed();

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
    // Core accounting helpers
    // ------------------------------------------------------------------

    /// @dev Converts a quantity of underlying assets to vault shares at the
    ///      current exchange rate. Rounds down â€” always round in the
    ///      protocol's favor on mint to avoid share-price manipulation via
    ///      dust deposits.
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) return assets; // 1:1 on first deposit
        return (assets * totalSupply) / totalAssets;
    }

    /// @dev Converts shares back to underlying assets. Rounds down on
    ///      withdrawal for the same reason â€” protocol-favorable rounding.
    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) return shares;
        return (shares * totalAssets) / totalSupply;
    }

    // ------------------------------------------------------------------
    // Reward accounting (standard synthetix-style staking math)
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
     * @notice Deposit underlying asset and receive vault shares.
     * @dev Deposit follows Checks-Effects-Interactions correctly â€” the
     *      external transferFrom happens, then we mint. Deposits are the
     *      "safe" half of this contract; the bug lives in withdraw().
     *      I'm including the full deposit flow anyway so the contract
     *      reads as a complete, realistic vault rather than a stripped-down
     *      vulnerability demo â€” that realism is what makes the audit
     *      exercise representative of real-world code review.
     */
    function deposit(uint256 assets) external returns (uint256 shares) {
        if (depositsPaused) revert DepositsArePaused();
        if (assets == 0) revert ZeroAmount();
        if (totalAssets + assets > maxTotalAssets) revert DepositExceedsCap();

        _updateReward(msg.sender);

        shares = convertToShares(assets);
        if (shares == 0) revert ZeroAmount();

        // Effects before interaction where possible
        totalAssets += assets;
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
        depositTimestamp[msg.sender] = block.timestamp;

        // Interaction: pull funds from depositor
        bool ok = asset.transferFrom(msg.sender, address(this), assets);
        if (!ok) revert TransferFailed();

        emit Deposit(msg.sender, assets, shares);
    }

    // ------------------------------------------------------------------
    // Withdraw â€” VULNERABLE PATTERN - FOR EDUCATIONAL ANALYSIS ONLY
    // ------------------------------------------------------------------

    /**
     * @notice Burn vault shares and withdraw the underlying asset.
     *
     * @dev =====================================================================
     *      VULNERABLE PATTERN - FOR EDUCATIONAL ANALYSIS ONLY
     *      =====================================================================
     *
     *      WHERE:
     *      The external call `asset.transfer(msg.sender, assetsOut)` executes
     *      BEFORE `balanceOf[msg.sender] -= shares` and `totalSupply -= shares`
     *      are updated. This violates Checks-Effects-Interactions: state is
     *      mutated AFTER an external call, not before it.
     *
     *      WHY IT'S DANGEROUS:
     *      `asset.transfer` looks like a simple value transfer, but if `asset`
     *      is (or proxies to, or is upgraded to) a token with a transfer hook
     *      â€” an ERC-777, an ERC-20 with a callback extension, or simply a
     *      contract address controlled by the attacker masquerading as the
     *      configured asset in a test/fork â€” control flow can be handed back
     *      to the caller mid-execution. At that point in the function,
     *      `balanceOf[msg.sender]` still reflects the PRE-withdrawal share
     *      balance, because the deduction hasn't happened yet. The contract
     *      has already "promised" the assets are gone (intent), but the
     *      ledger hasn't caught up (state). Any code that runs during that
     *      window sees a contract that is internally inconsistent.
     *
     *      HOW AN ATTACKER COULD EXPLOIT IT (educational description only):
     *      1. Attacker deploys a malicious contract that holds vault shares
     *         and implements a callback that gets invoked during token
     *         transfer (e.g. a `tokensReceived` hook, or â€” in the classic
     *         ETH-vault version of this bug â€” a `receive()`/`fallback()`
     *         that fires on `.call{value: x}("")`).
     *      2. Attacker calls `withdraw(shares)` once, normally.
     *      3. Execution reaches `asset.transfer(...)`. Before that call
     *         returns, the attacker's callback fires.
     *      4. Inside the callback, the attacker calls `withdraw(shares)`
     *         again. Because `balanceOf[msg.sender]` was never decremented
     *         in step 2 (the decrement is below the transfer call), the
     *         require/check at the top of withdraw() still passes â€” the
     *         contract believes the attacker still owns the same shares.
     *      5. This repeats recursively (bounded only by gas) until the
     *         vault's asset balance is drained or the call stack limit is
     *         hit, at which point the stack unwinds and the share-balance
     *         decrements from every nested call finally apply â€” but by then
     *         the attacker has already received far more in `transfer`
     *         calls than their original share balance entitled them to.
     *      6. Net effect: attacker withdraws N times against a balance that
     *         should only have permitted withdrawal once, stealing the
     *         difference from every other depositor's principal.
     *
     *      This is structurally identical to the 2016 DAO exploit â€” the
     *      difference is only which token standard provides the reentry
     *      hook. Plain OZ ERC-20 `transfer` has no hook, so this exact
     *      gadget would not fire against a vanilla ERC-20 today; it
     *      becomes live the moment `asset` is a hookable token, the vault
     *      adds NFT/ERC-1155 collateral, or this pattern is copy-pasted
     *      into a function that moves native ETH via `.call`. Treating
     *      "the token I picked has no hook" as a safety guarantee is itself
     *      the audit finding â€” see SecurityReport.md.
     *
     *      See Remediation.sol `withdraw()` for the corrected ordering and
     *      the added `nonReentrant` guard, which closes this class of bug
     *      regardless of what hooks the configured asset happens to have.
     *      =====================================================================
     */
    function withdraw(uint256 shares) external returns (uint256 assetsOut) {
        if (shares == 0) revert ZeroAmount();
        if (balanceOf[msg.sender] < shares) revert InsufficientShares();

        _updateReward(msg.sender);

        assetsOut = convertToAssets(shares);

        // --- VULNERABLE: external interaction happens before state update ---
        // Checks-Effects-Interactions is violated here. The correct order is
        // Checks -> Effects (decrement balances) -> Interactions (transfer).
        // This function does Checks -> Interactions -> Effects.
        bool ok = asset.transfer(msg.sender, assetsOut);
        if (!ok) revert TransferFailed();

        // By the time we reach these lines on a reentrant call, the outer
        // call's decrements haven't happened yet, so this is "effectively"
        // decrementing a balance that the inner call already drained
        // against â€” but only on the way back out of the recursion.
        totalAssets -= assetsOut;
        totalSupply -= shares;
        balanceOf[msg.sender] -= shares;
        // --- END VULNERABLE BLOCK ---

        emit Withdraw(msg.sender, shares, assetsOut);
    }

    // ------------------------------------------------------------------
    // Harvest / fee distribution
    // ------------------------------------------------------------------

    /**
     * @notice Strategist reports profit since last harvest. Performance and
     *         management fees are minted as new shares to feeRecipient
     *         rather than transferred as assets, so harvesting never has to
     *         pull liquidity out of the strategy.
     */
    function harvest(uint256 reportedProfit) external onlyStrategist {
        uint256 elapsed = block.timestamp - lastHarvestTimestamp;
        lastHarvestTimestamp = block.timestamp;

        // Management fee accrues continuously regardless of profit, same as
        // most real fund structures â€” it pays for keeper/strategist upkeep.
        uint256 managementFee = (totalAssets * managementFeeBps * elapsed) / (365 days * 10_000);
        uint256 performanceFee = (reportedProfit * performanceFeeBps) / 10_000;
        uint256 totalFee = managementFee + performanceFee;

        totalAssets += reportedProfit;

        if (totalFee > 0 && totalSupply > 0) {
            // Mint fee shares at the POST-profit share price so existing
            // depositors aren't diluted by the profit itself, only by the
            // fee skim. Order matters: totalAssets above must already
            // include reportedProfit before this conversion.
            uint256 feeShares = (totalFee * totalSupply) / (totalAssets - totalFee);
            totalSupply += feeShares;
            balanceOf[feeRecipient] += feeShares;
        }

        emit Harvest(reportedProfit, performanceFee, managementFee);
    }

    // ------------------------------------------------------------------
    // Reward claiming
    // ------------------------------------------------------------------

    function claimRewards() external returns (uint256 reward) {
        _updateReward(msg.sender);
        reward = rewards[msg.sender];
        if (reward == 0) return 0;

        rewards[msg.sender] = 0; // effect before interaction â€” this path is safe
        bool ok = rewardToken.transfer(msg.sender, reward);
        if (!ok) revert TransferFailed();

        emit RewardClaimed(msg.sender, reward);
    }

    // ------------------------------------------------------------------
    // Governance
    // ------------------------------------------------------------------

    function setStrategist(address newStrategist) external onlyOwner {
        emit StrategistUpdated(strategist, newStrategist);
        strategist = newStrategist;
    }

    function setFeeRecipient(address newRecipient) external onlyOwner {
        emit FeeRecipientUpdated(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    function setPerformanceFee(uint256 newBps) external onlyOwner {
        require(newBps <= 3000, "fee too high"); // hard cap 30%, governance can't rug via fees
        performanceFeeBps = newBps;
    }

    function setManagementFee(uint256 newBps) external onlyOwner {
        require(newBps <= 300, "fee too high"); // hard cap 3% annualized
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
