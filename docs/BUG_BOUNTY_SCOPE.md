# Kleidi Bug Bounty Scope — Critical Severity

**Program Type:** Immunefi Bug Bounty
**Max Bounty:** $50,000
**Audit History:** Alex from Recon week long audit (no Critical, High or Medium findings), Code4rena (October 2024, no Critical or High findings)
**Deployed Chains:** Ethereum Mainnet, Base, Optimism
**Scope Version:** 1.0
**Last Updated:** 2026-02-03

---

## In-Scope Impacts

Only the following impacts are eligible for the bug bounty. Each impact must be demonstrated with a valid proof-of-concept.

This program covers Critical severity only. Lower-severity findings (High, Medium, Low, Informational) are not eligible regardless of impact.

Proofs of concept must be submitted as a runnable Foundry test that demonstrates the vulnerability.

All findings must demonstrate impact against a system deployed through the InstanceDeployer contract. Contracts deployed outside of the InstanceDeployer are out of scope.

### 1. Direct Theft of User Funds

Any attack path that allows an unauthorized party to transfer tokens or ETH out of a Kleidi Timelock or its associated Safe, without the consent of the Safe owners.

Attack surface includes:
- Permissionless execution of timelocked proposals
- Hot signer whitelisted execution paths
- Low-level call forwarding from the Timelock to target contracts
- Calldata validation logic that gates whitelisted execution
- Byte-range extraction used during calldata validation

### 2. Permanent Freezing of Funds

Any attack path that renders funds in the Timelock or Safe permanently irrecoverable — i.e., no combination of Safe owners, recovery spells, or guardian actions can retrieve the funds.

Attack surface includes:
- Proposal creation and removal paths (including slot exhaustion and state corruption)
- Expiration period and delay mutation
- Guardian pause mechanism and its interaction with proposal lifecycle
- Safe transaction guard that restricts self-calls

### 3. Bypass of Timelock Delay

Any attack path that allows execution of a timelocked operation before `minDelay` has elapsed. Whitelisted calldata is excluded from this since it is intended for immediate execution.

Attack surface includes:
- Readiness and expiration checks (timestamp comparisons)
- Pre- and post-execution guards
- Proposal creation paths (slot exhaustion, state corruption)
- Permissionless execution — anyone can execute a ready proposal

### 4. Unauthorized Safe Reconfiguration

Any attack path that allows an unauthorized party to add/remove Safe owners, change the signing threshold, add/remove modules, or change the Guard — outside of the intended timelocked proposal flow or authorized recovery spell execution.

Attack surface includes:
- Guard enforcement that restricts Safe self-calls (owner rotation, module changes) to the timelocked path
- Access control role management
- Direct (non-timelocked) hot signer removal by Safe
- Guardian rotation (timelocked)
- Calldata whitelist mutation (adding, removing, and clearing checks, including datahash removal)

### 5. Recovery Mechanism Compromise

Any attack path that allows unauthorized activation of a recovery spell, or that prevents a legitimately-configured recovery spell from executing when needed.

Attack surface includes:
- Signature-gated recovery execution that bypasses the timelock
- EIP-712 digest computation for recovery signatures
- Factory deployment of recovery spells with parameter validation

---

## In-Scope Assets

### Core Contracts

| Contract | Path | Description |
|----------|------|-------------|
| Timelock | `src/Timelock.sol` | Core timelock with proposal lifecycle, calldata whitelisting, access control |
| ConfigurablePause | `src/ConfigurablePause.sol` | Guardian pause mechanism, inherited by Timelock |
| Guard | `src/Guard.sol` | Safe transaction guard restricting self-calls and delegatecalls |
| InstanceDeployer | `src/InstanceDeployer.sol` | Deterministic deployment of Safe + Timelock + modules |
| RecoverySpell | `src/RecoverySpell.sol` | Emergency owner rotation via EIP-712 signatures |
| RecoverySpellFactory | `src/RecoverySpellFactory.sol` | Factory for deterministic RecoverySpell deployment |
| TimelockFactory | `src/TimelockFactory.sol` | Factory for deterministic Timelock deployment |
| BytesHelper | `src/BytesHelper.sol` | Byte slicing utilities for calldata validation |
| AddressCalculation | `src/views/AddressCalculation.sol` | View-only address prediction (CREATE2) |
| Create2Helper | `src/utils/Create2Helper.sol` | CREATE2 deployment utilities |
| Constants | `src/utils/Constants.sol` | Shared constants (`MIN_DELAY`, `MAX_DELAY`, etc.) |

**Note:** `BytesHelper.getFirstWord()` is explicitly out of scope.

### Deployed Addresses (same across all chains via CREATE2)

| Contract | Address |
|----------|---------|
| InstanceDeployer | `0xE138136bFF8c6A9337805DE19177E3b29fef2783` |
| TimelockFactory | `0xCe90BA68BbcdCCe9aed1fCDDcb114d1DCdBc68C9` |
| RecoverySpellFactory | `0x56b6d03b995022A612aF6a212C74902f233F52Cc` |
| Guard | `0xFE49DD6d0CD41C4EC8F151C79f2d4019f5C5AD18` |
| AddressCalculation | `0xd1db2c4A9d2BEBd56d42E59F2d90F4136164faD6` |
| BytesHelper | `0x146dfd96Da039FDE3B58D5964feF8E8357df2028` |

**Chains:** Ethereum Mainnet (1), Base (8453), Optimism (10)

### External Dependencies (not in scope, but relevant for interaction bugs)

| Dependency | Version |
|------------|---------|
| Gnosis Safe (safe-smart-account) | v1.4.1 |
| OpenZeppelin Contracts | v4.8.0+ |
| Multicall3 | `0xcA11bde05977b3631167028862bE2a173976CA11` |

### Compiler Configuration

- **Solidity:** 0.8.25
- **EVM Target:** Cancun
- **Optimizer:** Enabled, 300 runs

---

## Known Issues (Out of Scope)

The following are documented known issues and acknowledged findings. Reports that redescribe these issues will be closed as out of scope. Novel exploit chains that use a known issue as one component but achieve a distinct, previously-undocumented impact are eligible if they demonstrate critical impact as described in this program.

### From `KNOWN_ISSUES.md` and Inline Documentation

| # | Issue | Source |
|---|-------|--------|
| KI-1 | **Malicious cold signers** can execute transactions to compromise the system if neither recovery spells nor guardian are configured. | `KNOWN_ISSUES.md` |
| KI-2 | **Malicious hot signers** can deploy a compromised system instance on a new chain with malicious calldata checks or recovery spells. | `KNOWN_ISSUES.md` |
| KI-3 | **DEX whitelisting** enables hot signers to steal funds via high slippage and sandwich attacks. DEXs are not whitelisted by default. | `KNOWN_ISSUES.md` |
| KI-4 | **Malicious protocol whitelisting** enables hot signers to lose funds if a malicious or misconfigured protocol is whitelisted. | `KNOWN_ISSUES.md` |
| KI-5 | **Fee-on-transfer tokens** may cause unexpected balance discrepancies. | `KNOWN_ISSUES.md` |
| KI-6 | **EVM Shanghai requirement** — system does not work on pre-Shanghai chains. | `KNOWN_ISSUES.md` |
| KI-7 | **Known ABI requirement** — dynamic ABIs are not supported; dynamic calldata (arrays) cannot be checked by the calldata whitelisting mechanism. | `KNOWN_ISSUES.md` |
| KI-8 | **Unchecked token transfer return values** — the call is checked, but the return value of the transfer itself is not. The Timelock has no accounting mechanism. | `KNOWN_ISSUES.md` |
| KI-9 | **Unused salt** in `DeploymentParams` struct is not used in `createSystemInstance`. Not a security concern. | `KNOWN_ISSUES.md` |
| KI-10 | **No enforcement of separate signers** — hot, cold, and recovery signers are not enforced to be different addresses. Frontend prevents this. | `KNOWN_ISSUES.md` |
| KI-11 | **Unbounded expiration period** — `updateExpirationPeriod()` lacks an upper bound, theoretically allowing DoS. Requires full Safe compromise and is recoverable via `cancel()` or `pause()`. | `KNOWN_ISSUES.md`, `Timelock.sol:985` |
| KI-12 | **Malicious guardian pause** — guardian can cancel all in-flight proposals and lock funds for the pause duration (1–30 days). | `Timelock.sol:37-39` |
| KI-13 | **Module bypass of pause** — recovery spells and other Safe modules bypass all pause restrictions because module transactions are not checked against the Guard. | `Timelock.sol:40-44` |
| KI-14 | **Incorrectly formed whitelisted calldata** — owner must ensure no calldata allows unauthorized transfers (e.g., `approve` to arbitrary address). No native asset balance checks are enshrined. | `Timelock.sol:45-52` |
| KI-15 | **Recovery spell delay vs timelock delay** — the recovery spell delay must be shorter than the timelock delay, but this is not enforced on-chain. | `RecoverySpell.sol:96-100` |
| KI-16 | **Raw ETH draining** — value is not checked for hot signer calls. If a whitelisted protocol accepts excess ETH without refund, the Timelock's ETH can be drained. Mitigated by using WETH and not whitelisting protocols that do not refund excess ETH. | `EDGECASES.md` |
| KI-17 | **Guardian + recovery signer collusion** — if both are malicious, they can collude to take over the system. Mitigated by keeping them unaware of each other. | `EDGECASES.md` |
| KI-18 | **Timelock removed before Guard disabled** — renders the Safe unable to rotate signers, add/remove modules. Configuration sequencing issue. | `EDGECASES.md` |
| KI-19 | **Future token standards** — the system is immutable and does not support token standards developed after deployment. | `EDGECASES.md` |

### From Code4rena October 2024 Audit

| # | Finding | Severity | Status | Rationale |
|---|---------|----------|--------|-----------|
| C4-M01 | Gas griefing via mass proposal creation with compromised threshold keys | Medium | Acknowledged | Requires compromised Safe threshold keys, mitigated with social recovery. The 100-proposal cap bounds impact, and proposals can be cancelled or cleaned up. |
| C4-M02 | Off-by-one in calldata byte-range validation | Medium | Acknowledged | The inclusive range semantics (`end - start + 1`) are consistent between validation and extraction. Both sides use the same boundary, so no validation bypass occurs. |
| C4-M03 | Reducing expiration period causes post-execution check to revert on in-flight proposals | Medium | Acknowledged | Since the expiration period update is itself timelocked, affected proposals can be rescheduled. Temporary, recoverable impact. |
| C4-L01–L04+ | Low-risk and non-critical findings (typos, NatSpec, code duplication, retroactive expiration) | Low | Acknowledged | — |

Full report: [code4rena.com/reports/2024-10-kleidi](https://code4rena.com/reports/2024-10-kleidi)

### From Internal Audit Log

All findings documented in `AUDIT_LOG.md` (August–September 2024) have been remediated and are out of scope. These include: pause duration re-extension, RecoverySpell signature malleability, calldatacheck duplicate/overlap logic, empty calldatacheck arrays, and selfAddressCheck removal.

---

## Trust Assumptions

These are the baseline trust assumptions of the Kleidi system. Bugs that require violating these assumptions to demonstrate impact are **out of scope**.

| Assumption | Description |
|------------|-------------|
| **Safe multisig is not compromised** | The M-of-N cold signers controlling the Safe are assumed to be honest and operationally secure. A compromised Safe can already drain all funds through timelocked proposals. |
| **Hot signers are trusted within their scope** | Hot signers can only execute whitelisted calldata. They are trusted to not act maliciously within their whitelisted scope. Bugs in the whitelist enforcement mechanism itself ARE in scope. |
| **Guardian is non-malicious** | The pause guardian is assumed to act in good faith. A malicious guardian can temporarily freeze funds (documented in KI-12). |
| **Recovery signers are non-malicious** | Recovery spell signers are assumed to be trusted parties who will only activate recovery in legitimate emergencies. |
| **Calldata whitelist is correctly configured** | Safe owners are responsible for not whitelisting dangerous calldata (e.g., `approve` to arbitrary addresses). Bugs in how the whitelist is *enforced* ARE in scope; bugs in how it is *configured* are not. |
| **Deployment parameters are correct** | The system is deployed via `InstanceDeployer` with correct parameters. Misconfiguration at deployment time is out of scope. |
| **External dependencies are correct** | Gnosis Safe v1.4.1, OpenZeppelin v4.8.x, and Multicall3 are assumed to function as documented. Bugs in Kleidi's *integration* with these dependencies ARE in scope if their impact meets critical threshold. |
| **Recovery delay Config** | Deployers are assumed to configure recovery spell delays shorter than the timelock or guardian pause delay. The lack of on-chain enforcement is a known issue (KI-15). |
| **L2 sequencers are reliable** | L2 sequencers (Optimism, Base) are assumed to operate correctly and provide accurate `block.timestamp` values. Sequencer downtime affecting proposal timing is not a Kleidi-specific issue. |
---

## Out of Scope

The following categories are explicitly out of scope regardless of impact:

- Gas optimizations and efficiency improvements
- Removal of the guard, removal of the timelock as a Safe module, or other configuration changes that require a timelocked proposal
- Social engineering, phishing, or other off-chain attacks
- Informational and best-practice findings
- Centralization risks (the trust assumptions above are accepted by design)
- Findings that require a compromised Safe multisig as a precondition (the Safe having full control is by design)
- Frontend, backend, or off-chain infrastructure vulnerabilities
- Vulnerabilities in third-party dependencies (Gnosis Safe, OpenZeppelin, Multicall3) unless the bug is in Kleidi's integration with them
- Theoretical attacks without a concrete proof-of-concept
- `BytesHelper.getFirstWord()` function, unused in the codebase
- `SystemDeploy.s.sol` deployment script
- Test files, proof-of-concept contracts (`src/poc/`), and interface files (`src/interface/`)
- Issues on testnet deployments (Base Sepolia, Optimism Sepolia)
- All known issues and prior audit findings enumerated in the Known Issues section above
- Findings against contracts not deployed through the InstanceDeployer contract
- Bypasses of the whitelisted calldata mechanism that target the Safe address (the Timelock enforces that the Safe cannot be a whitelisted target)
- Gas griefing of the pause mechanism's proposal cancellation (gas limits on all deployed chains are sufficient for the maximum 100 proposals)
