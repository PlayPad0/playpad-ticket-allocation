pragma solidity ^0.8.0;

import "hardhat/console.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

library Roles {
    struct Role {
        mapping(address => bool) bearer;
    }

    function add(Role storage role, address account) internal {
        require(!has(role, account));
        role.bearer[account] = true;
    }

    function remove(Role storage role, address account) internal {
        require(has(role, account));
        role.bearer[account] = false;
    }

    function has(Role storage role, address account)
        internal
        view
        returns (bool)
    {
        require(account != address(0));
        return role.bearer[account];
    }
}

library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(
            address(this).balance >= amount,
            "Address: insufficient balance"
        );

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{value: amount}("");
        require(
            success,
            "Address: unable to send value, recipient may have reverted"
        );
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain`call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data)
        internal
        returns (bytes memory)
    {
        return functionCall(target, data, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return
            functionCallWithValue(
                target,
                data,
                value,
                "Address: low-level call with value failed"
            );
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(
            address(this).balance >= value,
            "Address: insufficient balance for call"
        );
        require(isContract(target), "Address: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.call{value: value}(
            data
        );
        return _verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data)
        internal
        view
        returns (bytes memory)
    {
        return
            functionStaticCall(
                target,
                data,
                "Address: low-level static call failed"
            );
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function _verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) private pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                // solhint-disable-next-line no-inline-assembly
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}

library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(token.transfer.selector, to, value)
        );
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(token.transferFrom.selector, from, to, value)
        );
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(token.approve.selector, spender, value)
        );
    }

    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(
            value
        );
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(
                token.approve.selector,
                spender,
                newAllowance
            )
        );
    }

    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(
            value,
            "SafeERC20: decreased allowance below zero"
        );
        _callOptionalReturn(
            token,
            abi.encodeWithSelector(
                token.approve.selector,
                spender,
                newAllowance
            )
        );
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(
            data,
            "SafeERC20: low-level call failed"
        );
        if (returndata.length > 0) {
            // Return data is optional
            // solhint-disable-next-line max-line-length
            require(
                abi.decode(returndata, (bool)),
                "SafeERC20: ERC20 operation did not succeed"
            );
        }
    }
}

contract PlayPadIdoContract is ReentrancyGuard, Ownable {
    //Deployed by Main Contract
    PlayPadIdoFactory deployerContract;
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    IERC20 public immutable busdToken; //Stable coin token contract address
    IERC20 public saleToken; //Sale token contract address
    bool public contractStatus; //Contract running status
    uint256 public startTime; //IDO participation start time
    uint256 public endTime; //IDO participation end time
    uint256 public lockTime; //unlock date to get claim
    uint256[] public claimRoundsDate; //all claim rounds
    uint256 public totalClaimPercent; //total to be claim percent
    uint256 private MERKLE_ROOT; // MERKLE ROOT
    address[] public investors;

    /**
    -> Merkle root data structure
    * userAddress --
    * timestamp
    * userTotalVesting
    * userLevel
    */

    //whitelisted user data per user
    struct whitelistedInvestorData {
        uint256 totalBuyingAmountUsd;
        uint256 totalBuyingAmountToken;
        uint256 claimRound;
        uint256 lastClaimDate;
        uint256 claimedValue;
    }

    struct saleStruct {
        uint256 hardcap;
        uint256 totalSellAmountToken;
        uint256 totalSoldAmountToken;
        uint256 totalSoldAmountUsd;
        uint256 maxBuyValue;
        uint256 minBuyValue;
    }

    //claim round periods
    struct roundDatas {
        uint256 roundStartDate;
        uint256 roundPercent;
    }
    //mappings to reach relevant information
    mapping(address => whitelistedInvestorData) public _investorData;
    mapping(uint256 => roundDatas) public _roundDatas;
    mapping(uint256 => saleStruct) public _sales; //0 -> whitelist sale details, 1 -> holders round details

    constructor(
        IERC20 _busdAddress,
        IERC20 _saleToken,
        bool _contractStatus,
        uint256 _startTime,
        uint256 _endTime
    ) public {
        require(
            _startTime < _endTime,
            "start block must be less than finish block"
        );
        require(
            _endTime > block.timestamp,
            "finish block must be more than current block"
        );
        busdToken = _busdAddress;
        saleToken = _saleToken;
        contractStatus = _contractStatus;
        startTime = _startTime;
        endTime = _endTime;
    }

    event NewBuying(
        address indexed investorAddress,
        uint256 amount,
        uint256 timestamp,
        uint256 totalSoldAmountUsd
    );

    //modifier to change contract status
    modifier mustNotPaused() {
        require(!contractStatus, "Paused!");
        _;
    }

    // function to change status of contract
    function changePause(bool _contractStatus) public onlyOwner nonReentrant {
        contractStatus = _contractStatus;
    }

    function changeSaleTokenAddress(IERC20 _contractAddress)
        external
        onlyOwner
        nonReentrant
    {
        saleToken = _contractAddress;
    }

    function changeStartTime(uint256 _startTime)
        external
        nonReentrant
        onlyOwner
    {
        startTime = _startTime;
    }

    function changeFinishTime(uint256 _finishTime)
        external
        nonReentrant
        onlyOwner
    {
        endTime = _finishTime;
    }

    function setSaleDetails(
        uint256 _hardcap,
        uint256 _totalSellAmountToken,
        uint256 _maxBuyAmount,
        uint256 _minBuyAmount,
        uint256 _saleRound
    ) external onlyOwner nonReentrant {
        saleStruct memory saleDetails = _sales[_saleRound];
        saleDetails.hardcap = _hardcap;
        saleDetails.totalSellAmountToken = _totalSellAmountToken;
        saleDetails.maxBuyValue = _maxBuyAmount;
        saleDetails.minBuyValue = _minBuyAmount;
    }

    //calculate token amount according to deposit amount
    function calculateTokenAmount(uint256 amount, uint256 _saleRound)
        public
        view
        returns (uint256)
    {
        saleStruct memory _saleDetails = _sales[_saleRound];
        return
            (_saleDetails.totalSellAmountToken.mul(amount)).div(
                _saleDetails.hardcap
            );
    }

    function returnUserInfo(address _addresss)
        public
        view
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            uint256
        )
    {
        whitelistedInvestorData storage investor = _investorData[_addresss];
        return (
            investor.totalBuyingAmountUsd,
            investor.totalBuyingAmountToken,
            investor.claimRound,
            investor.lastClaimDate,
            investor.claimedValue
        );
    }

    function returnAllUsers()
        public
        view
        returns (whitelistedInvestorData[] memory)
    {
        whitelistedInvestorData[] memory users = new whitelistedInvestorData[](
            investors.length
        );
        for (uint256 i = 0; i < investors.length; i++) {
            whitelistedInvestorData memory user = _investorData[investors[i]];
            users[i] = user;
        }
        return users;
    }

    //buys token if passing controls
    function buyToken(
        uint256[3] calldata _data,
        uint256[] memory _proof,
        uint256 busdAmount
    ) external nonReentrant mustNotPaused {
        require(block.timestamp >= startTime);
        require(block.timestamp <= endTime);
        whitelistedInvestorData storage investor = _investorData[msg.sender];
        uint256 userTotalVesting = _data[1];
        uint256 userLevel = _data[2];
        uint256 userLeaf = uint256(
            keccak256(abi.encodePacked(msg.sender, _data))
        );
        require(verifyMerkle(userLeaf, _proof), "leaf is not correct");
        saleStruct memory saleDetails = _sales[userLevel];
        require(
            userTotalVesting >= investor.totalBuyingAmountUsd.add(busdAmount),
            "Opps you cannot buy more than your allocation"
        );
        require(
            saleDetails.hardcap >=
                saleDetails.totalSoldAmountUsd.add(busdAmount),
            "hardcap value exceed"
        );
        require(
            saleDetails.maxBuyValue >=
                investor.totalBuyingAmountUsd.add(busdAmount),
            "you cannot buy more total limit at total"
        );
        require(
            busdAmount >= saleDetails.minBuyValue,
            "you cannot buy less than min limit"
        );
        require(busdToken.transferFrom(msg.sender, address(this), busdAmount));
        uint256 totalTokenAmount = calculateTokenAmount(busdAmount, userLevel);
        if (investor.totalBuyingAmountUsd == 0) {
            investors.push(msg.sender);
        }
        saleDetails.totalSoldAmountUsd = saleDetails.totalSoldAmountUsd.add(
            busdAmount
        );
        saleDetails.totalSoldAmountToken = saleDetails.totalSoldAmountToken.add(
            busdAmount
        );
        investor.totalBuyingAmountUsd = investor.totalBuyingAmountUsd.add(
            busdAmount
        );
        investor.totalBuyingAmountToken = investor.totalBuyingAmountToken.add(
            totalTokenAmount
        );

        emit NewBuying(
            msg.sender,
            busdAmount,
            block.timestamp,
            saleDetails.totalSoldAmountUsd
        );
    }

    //emergency withdraw function in worst cases
    function emergencyWithdrawAllBusd() external nonReentrant onlyOwner {
        require(
            busdToken.transfer(msg.sender, busdToken.balanceOf(address(this)))
        );
    }

    //change lock time to prevent missing values
    function changeLockTime(uint256 _lockTime) external nonReentrant onlyOwner {
        lockTime = _lockTime;
    }

    //emergency withdraw for tokens in worst cases
    function withdrawTokens() external nonReentrant onlyOwner {
        require(
            saleToken.transfer(msg.sender, saleToken.balanceOf(address(this)))
        );
    }

    //claim tokens according to claim periods
    function claimTokens(uint256[3] calldata _data, uint256[] memory _proof)
        external
        nonReentrant
    {
        require(block.timestamp >= lockTime, "bad lock time");
        uint256 userLeaf = uint256(
            keccak256(abi.encodePacked(msg.sender, _data))
        );
        require(verifyMerkle(userLeaf, _proof), "leaf is not correct");
        whitelistedInvestorData memory investor = _investorData[msg.sender];
        uint256 investorRoundNumber = investor.claimRound;
        roundDatas storage roundDetail = _roundDatas[investorRoundNumber];
        require(
            roundDetail.roundStartDate != 0,
            "Claim rounds are not available yet."
        );
        require(
            block.timestamp >= roundDetail.roundStartDate,
            "round didn't start yet"
        );
        require(
            investor.totalBuyingAmountToken >=
                investor.claimedValue.add(
                    investor
                        .totalBuyingAmountToken
                        .mul(roundDetail.roundPercent)
                        .div(100)
                ),
            "already you got all your tokens"
        );
        require(
            saleToken.transfer(
                msg.sender,
                investor
                    .totalBuyingAmountToken
                    .mul(roundDetail.roundPercent)
                    .div(100)
            ),
            "bad transfer"
        );
        investor.claimRound = investor.claimRound.add(1);
        investor.lastClaimDate = block.timestamp;
        investor.claimedValue = investor.claimedValue.add(
            investor.totalBuyingAmountToken.mul(roundDetail.roundPercent).div(
                100
            )
        );
    }

    //add new claim round
    function addNewClaimRound(
        uint256 _roundNumber,
        uint256 _roundStartDate,
        uint256 _claimPercent
    ) external nonReentrant onlyOwner {
        require(_claimPercent > 0);
        totalClaimPercent = totalClaimPercent.add(_claimPercent);
        roundDatas storage roundDetail = _roundDatas[_roundNumber];
        roundDetail.roundStartDate = _roundStartDate;
        roundDetail.roundPercent = _claimPercent;
        claimRoundsDate.push(_roundStartDate);
    }

    function changeMaxMinBuyLimit(
        uint256 _maxBuyLimit,
        uint256 _minBuyLimit,
        uint256 _saleRoundNumber
    ) external onlyOwner nonReentrant {
        saleStruct memory saleDetails = _sales[_saleRoundNumber];
        saleDetails.maxBuyValue = _maxBuyLimit;
        saleDetails.minBuyValue = _minBuyLimit;
    }

    function pairHash(uint256 _a, uint256 _b) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(_a ^ _b)));
    }

    // Verify a Merkle proof
    function verifyMerkle(uint256 _value, uint256[] memory _proof)
        public
        view
        returns (bool)
    {
        uint256 temp = _value;
        uint256 i;

        for (i = 0; i < _proof.length; i++) {
            temp = pairHash(temp, _proof[i]);
        }

        return temp == MERKLE_ROOT;
    }

    function getMerkleRoot() external view returns (uint256) {
        return MERKLE_ROOT;
    }

    function setMerkleRoot(uint256 _merkleRoot)
        external
        onlyOwner
        nonReentrant
    {
        MERKLE_ROOT = _merkleRoot;
    }
}
