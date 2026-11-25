// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IReserveToken {
    function decimals() external view returns (uint8);
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

/// @notice Independent test reserve for one six-decimal USDC and BSV asset pair.
/// @dev A designated signer attests BSV validity and finality off chain. The
/// vault verifies the attestation and consumes the corresponding burn event.
contract TestUsdcReserve {
    error Unauthorized();
    error InvalidConfiguration();
    error InvalidDeposit();
    error InvalidRedemption();
    error UnsupportedChain();
    error DepositPaused();
    error ReleasePaused();
    error AlreadySettled(bytes32 burnId);
    error InvalidSignature();
    error InsufficientReserve();
    error InexactTransfer();
    error ReentrantCall();

    event Deposit(
        uint64 indexed nonce,
        address indexed depositor,
        bytes32 indexed assetId,
        uint32 reserveDomain,
        uint32 bsvNetwork,
        address reserveAsset,
        uint64 quantity,
        bytes owner
    );

    event Release(
        bytes32 indexed burnId,
        bytes32 indexed burnTxid,
        address indexed recipient,
        uint32 burnVout,
        uint64 quantity,
        uint64 fee,
        bytes32 attestationDigest
    );

    event ReleaseSignerChanged(address indexed previous, address indexed current, uint64 epoch);
    event PauseGuardianChanged(address indexed previous, address indexed current);
    event DepositPauseChanged(bool paused);
    event ReleasePauseChanged(bool paused);
    event AdminTransferProposed(address indexed proposed);
    event AdminTransferred(address indexed previous, address indexed current);

    struct Configuration {
        uint256 chainId;
        uint32 reserveDomain;
        uint32 bsvNetwork;
        bytes32 assetId;
        IReserveToken token;
        address admin;
        address pauseGuardian;
        address releaseSigner;
        address feeRecipient;
    }

    struct Redemption {
        uint32 bsvNetwork;
        bytes32 burnTxid;
        uint32 burnVout;
        bytes32 burnBlockHash;
        bytes32 assetId;
        uint32 reserveDomain;
        address recipient;
        uint64 quantity;
        uint64 fee;
        uint64 signerEpoch;
    }

    bytes32 public constant REDEMPTION_TYPEHASH = keccak256(
        "Redemption(uint32 bsvNetwork,bytes32 burnTxid,uint32 burnVout,bytes32 burnBlockHash,"
        "bytes32 assetId,uint32 reserveDomain,address recipient,uint64 quantity,uint64 fee,uint64 signerEpoch)"
    );

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("BSV USDC Test Reserve");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant BURN_EVENT_TYPEHASH =
        keccak256("BurnEvent(uint32 bsvNetwork,bytes32 burnTxid,uint32 burnVout)");
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 private constant SECP256K1_FIELD = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

    IReserveToken public immutable token;
    uint256 public immutable deploymentChainId;
    uint32 public immutable reserveDomain;
    uint32 public immutable bsvNetwork;
    bytes32 public immutable assetId;
    address public immutable feeRecipient;

    address public admin;
    address public pendingAdmin;
    address public pauseGuardian;
    address public releaseSigner;
    uint64 public signerEpoch = 1;
    bool public depositsPaused;
    bool public releasesPaused;

    uint64 public depositNonce;
    uint256 public totalDeposited;
    uint256 public totalReleased;
    uint256 public totalReleaseFees;
    mapping(bytes32 burnId => bytes32 digest) public settledDigest;
    mapping(bytes32 burnId => bool) public settled;
    bool private entered;

    constructor(Configuration memory config) {
        if (config.chainId != block.chainid) revert UnsupportedChain();
        if (
            config.assetId == bytes32(0) || address(config.token).code.length == 0 || config.admin == address(0)
                || config.pauseGuardian == address(0) || config.releaseSigner == address(0)
                || config.feeRecipient == address(0) || config.feeRecipient == address(this)
                || config.token.decimals() != 6
        ) revert InvalidConfiguration();

        deploymentChainId = config.chainId;
        reserveDomain = config.reserveDomain;
        bsvNetwork = config.bsvNetwork;
        assetId = config.assetId;
        token = config.token;
        admin = config.admin;
        pauseGuardian = config.pauseGuardian;
        releaseSigner = config.releaseSigner;
        feeRecipient = config.feeRecipient;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier onDeploymentChain() {
        if (block.chainid != deploymentChainId) revert UnsupportedChain();
        _;
    }

    modifier nonReentrant() {
        if (entered) revert ReentrantCall();
        entered = true;
        _;
        entered = false;
    }

    function netReserve() public view returns (uint256) {
        return totalDeposited - totalReleased;
    }

    function deposit(uint64 quantity, bytes calldata owner)
        external
        onDeploymentChain
        nonReentrant
        returns (uint64 nonce)
    {
        if (depositsPaused) revert DepositPaused();
        if (quantity == 0 || !_isCompressedOwner(owner)) revert InvalidDeposit();

        uint256 beforeBalance = token.balanceOf(address(this));
        if (!token.transferFrom(msg.sender, address(this), quantity)) revert InexactTransfer();
        if (token.balanceOf(address(this)) != beforeBalance + quantity) revert InexactTransfer();

        nonce = ++depositNonce;
        totalDeposited += quantity;
        emit Deposit(nonce, msg.sender, assetId, reserveDomain, bsvNetwork, address(token), quantity, owner);
    }

    function burnId(uint32 network, bytes32 txid, uint32 vout) public pure returns (bytes32) {
        return keccak256(abi.encode(BURN_EVENT_TYPEHASH, network, txid, vout));
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function releaseDigest(Redemption calldata redemption) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(REDEMPTION_TYPEHASH, redemption));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
    }

    function release(Redemption calldata redemption, bytes calldata signature)
        external
        onDeploymentChain
        nonReentrant
        returns (bytes32 id)
    {
        if (releasesPaused) revert ReleasePaused();
        if (
            redemption.bsvNetwork != bsvNetwork || redemption.reserveDomain != reserveDomain
                || redemption.assetId != assetId || redemption.burnTxid == bytes32(0)
                || redemption.burnBlockHash == bytes32(0) || redemption.recipient == address(0)
                || redemption.recipient == address(this) || redemption.quantity <= redemption.fee
                || redemption.signerEpoch != signerEpoch
        ) revert InvalidRedemption();

        id = burnId(redemption.bsvNetwork, redemption.burnTxid, redemption.burnVout);
        if (settled[id]) revert AlreadySettled(id);
        bytes32 digest = releaseDigest(redemption);
        if (releaseSigner == address(0) || _recover(digest, signature) != releaseSigner) {
            revert InvalidSignature();
        }
        if (redemption.quantity > netReserve()) revert InsufficientReserve();

        settled[id] = true;
        settledDigest[id] = digest;
        totalReleased += redemption.quantity;
        totalReleaseFees += redemption.fee;
        _payExact(redemption.recipient, redemption.quantity - redemption.fee);
        if (redemption.fee != 0) _payExact(feeRecipient, redemption.fee);
        emit Release(
            id,
            redemption.burnTxid,
            redemption.recipient,
            redemption.burnVout,
            redemption.quantity,
            redemption.fee,
            digest
        );
    }

    /// @notice Set zero to revoke release signing. Each rotation invalidates prior epochs.
    function setReleaseSigner(address next) external onlyAdmin {
        address previous = releaseSigner;
        releaseSigner = next;
        ++signerEpoch;
        emit ReleaseSignerChanged(previous, next, signerEpoch);
    }

    /// @notice Set zero to revoke the emergency pause role.
    function setPauseGuardian(address next) external onlyAdmin {
        address previous = pauseGuardian;
        pauseGuardian = next;
        emit PauseGuardianChanged(previous, next);
    }

    function setDepositsPaused(bool paused) external {
        _authorizePause(paused);
        depositsPaused = paused;
        emit DepositPauseChanged(paused);
    }

    function setReleasesPaused(bool paused) external {
        _authorizePause(paused);
        releasesPaused = paused;
        emit ReleasePauseChanged(paused);
    }

    function proposeAdmin(address next) external onlyAdmin {
        pendingAdmin = next;
        emit AdminTransferProposed(next);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert Unauthorized();
        address previous = admin;
        admin = msg.sender;
        pendingAdmin = address(0);
        emit AdminTransferred(previous, msg.sender);
    }

    function _authorizePause(bool paused) private view {
        if (msg.sender != admin && !(msg.sender == pauseGuardian && paused)) revert Unauthorized();
    }

    function _payExact(address recipient, uint256 quantity) private {
        uint256 beforeVault = token.balanceOf(address(this));
        uint256 beforeRecipient = token.balanceOf(recipient);
        if (!token.transfer(recipient, quantity)) revert InexactTransfer();
        if (
            token.balanceOf(address(this)) + quantity != beforeVault
                || token.balanceOf(recipient) != beforeRecipient + quantity
        ) revert InexactTransfer();
    }

    /// @dev secp256k1 has cofactor one. Check that x is in the field and that
    /// x^3 + 7 has a square root. The prefix selects its parity.
    function _isCompressedOwner(bytes calldata owner) private view returns (bool) {
        if (owner.length != 33 || (owner[0] != 0x02 && owner[0] != 0x03)) return false;
        uint256 x = uint256(bytes32(owner[1:33]));
        uint256 p = SECP256K1_FIELD;
        if (x >= p) return false;
        uint256 ySquared = addmod(mulmod(mulmod(x, x, p), x, p), 7, p);
        (bool ok, bytes memory result) =
            address(0x05).staticcall(abi.encode(uint256(32), uint256(32), uint256(32), ySquared, (p + 1) / 4, p));
        if (!ok || result.length != 32) return false;
        uint256 y = abi.decode(result, (uint256));
        return y != 0 && mulmod(y, y, p) == ySquared;
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r = bytes32(signature[:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert InvalidSignature();
        return ecrecover(digest, v, r, s);
    }
}
