# Base Sepolia 源链候选

2026-11-24。用户提出考虑 Coinbase 的 Base；目前无已部署储备合约、测试钱包或 RPC 配置。此页是实施候选，不是部署或测试网验收记录。

选 Base Sepolia（EIP-155 chain ID 84532）作为首个公开源链测试环境。Circle 已支持 Base 及其测试网的 CCTP。BSV 不在其支持域清单中，因此本项目的 BSV 铸造及释放仍属于自建储备桥；CCTP 用于受支持链向 Base 调拨原生 USDC。这与现有交接稿的职责划分一致。

第一条路径：测试 USDC 存入独立储备合约 → 认证存款 → BSV 铸造 → 转账及行政操作 → BSV 销毁达到确认要求 → Base 储备一次性释放。先在本地 EVM 用同一合约跑恢复和重放负例，再部署公开测试网。尚未实施合约、部署、资助或任何公开链交易。

源链适配器应分别固定 EIP-155 chain ID、桥自定义储备域、CCTP 域和 USDC 合约身份，不能把这几个编号混用。入金事件身份包含链、储备合约、交易及日志位置，收款人/资产/净数量均来自认证事件。快速回执不等于跨链铸造最终性；确认策略需明确 safe/finalized 及跨链动作后的深重组暂停规则。

外部准备：独立测试签名器、少量 Base Sepolia ETH、Circle 测试 USDC、合约部署、可补扫的 RPC。生产签名仍通过外部 signer；测试部署不接触主网资金。

核验来源：

- [Base eth_chainId](https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_chainId)
- [Circle CCTP 支持链和域](https://developers.circle.com/cctp/concepts/supported-chains-and-domains)
- [Circle USDC 合约地址](https://developers.circle.com/stablecoins/usdc-contract-addresses)

部署时重新核对地址和链 ID，不根据文档中的旧缓存直接签名。
