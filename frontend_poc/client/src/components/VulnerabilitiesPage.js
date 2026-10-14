import React, { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import { Activity, AlertTriangle, BookOpen, Bug, CheckCircle, ChevronRight, Code, Database, Lock, Search, Shield, Target, X } from "lucide-react";

const codeExamples = {
  reentrancy: [
    `function withdraw(uint256 amount) external {\n    require(balances[msg.sender] >= amount);\n    (bool ok,) = msg.sender.call{value: amount}("");\n    require(ok);\n    balances[msg.sender] -= amount;\n}`,
    `function withdraw(uint256 amount) external nonReentrant {\n    require(balances[msg.sender] >= amount);\n    balances[msg.sender] -= amount;\n    (bool ok,) = msg.sender.call{value: amount}("");\n    require(ok);\n}`,
  ],
  access: [
    `function setOwner(address newOwner) external {\n    owner = newOwner;\n}`,
    `function setOwner(address newOwner) external onlyOwner {\n    require(newOwner != address(0));\n    owner = newOwner;\n}`,
  ],
  overflow: [
    `uint8 public count;\nfunction add(uint8 amount) external {\n    count += amount;\n}`,
    `uint256 public count;\nfunction add(uint256 amount) external {\n    count += amount; // Solidity 0.8+ checks overflow\n}`,
  ],
  calls: [
    `function send(address target) external {\n    target.call(abi.encodeWithSignature("ping()"));\n}`,
    `function send(address target) external {\n    (bool ok,) = target.call(abi.encodeWithSignature("ping()"));\n    require(ok, "external call failed");\n}`,
  ],
  delegatecall: [
    `function execute(address implementation, bytes calldata data) external {\n    implementation.delegatecall(data);\n}`,
    `function execute(bytes calldata data) external onlyOwner {\n    (bool ok,) = trustedImplementation.delegatecall(data);\n    require(ok, "delegatecall failed");\n}`,
  ],
  dos: [
    `function payAll() external {\n    for (uint i; i < users.length; i++) {\n        payable(users[i]).transfer(1 ether);\n    }\n}`,
    `function withdraw() external {\n    uint256 amount = credits[msg.sender];\n    credits[msg.sender] = 0;\n    payable(msg.sender).transfer(amount);\n}`,
  ],
  timestamp: [
    `function isWinner() external view returns (bool) {\n    return block.timestamp % 10 == 0;\n}`,
    `function isWinner() external view returns (bool) {\n    return vrfRandomWord == winnerWord;\n}`,
  ],
  frontrun: [
    `function buy(uint256 price) external {\n    token.transfer(msg.sender, price);\n}`,
    `function buy(uint256 maxPrice, uint256 deadline) external {\n    require(block.timestamp <= deadline);\n    require(currentPrice <= maxPrice, "slippage");\n    token.transfer(msg.sender, currentPrice);\n}`,
  ],
  flashloan: [
    `function borrow(uint256 amount) external {\n    require(collateral[msg.sender] >= oracle.price() * amount);\n    token.transfer(msg.sender, amount);\n}`,
    `function borrow(uint256 amount) external {\n    uint256 price = twapOracle.consult(address(token));\n    require(collateral[msg.sender] >= price * amount);\n    token.transfer(msg.sender, amount);\n}`,
  ],
  oracle: [
    `function value() external view returns (uint256) {\n    return pair.getReserves().reserve0;\n}`,
    `function value() external view returns (uint256) {\n    return chainlinkFeed.latestAnswer();\n}`,
  ],
  events: [
    `uint256 public fee;\nfunction setFee(uint256 newFee) external onlyOwner {\n    fee = newFee;\n}`,
    `event FeeUpdated(uint256 previousFee, uint256 newFee);\nuint256 public fee;\nfunction setFee(uint256 newFee) external onlyOwner {\n    emit FeeUpdated(fee, newFee);\n    fee = newFee;\n}`,
  ],
  validation: [
    `function transferTo(address recipient, uint256 amount) external {\n    balances[recipient] += amount;\n}`,
    `function transferTo(address recipient, uint256 amount) external {\n    require(recipient != address(0), "invalid recipient");\n    require(amount > 0, "amount is zero");\n    balances[recipient] += amount;\n}`,
  ],
};

const vulnerabilities = [
  { id: "reentrancy", icon: Activity, name: "Reentrancy", severity: "Critical", score: 9.8, keywords: ["recursive", "withdraw", "dao", "external call"], description: "An external call re-enters a contract before its state has been safely updated.", cause: "State changes happen after an untrusted external call, allowing nested execution.", consequences: ["Loss of funds", "Drained vaults", "Broken accounting"], scenario: "An attacker withdraws to a contract whose fallback repeatedly calls withdraw before its balance is reduced.", prevention: ["Checks-Effects-Interactions", "ReentrancyGuard", "Pull payments"], incident: "The DAO exploit (2016) demonstrated how recursive withdrawals can drain pooled funds." },
  { id: "access", icon: Lock, name: "Access Control", severity: "Critical", score: 9.6, keywords: ["owner", "authorization", "permissions", "roles"], description: "Sensitive operations are reachable by an unauthorized account.", cause: "Administrative functions lack role checks or use an unsafe authorization pattern.", consequences: ["Ownership takeover", "Unauthorized minting", "Contract manipulation"], scenario: "An attacker calls an unprotected owner-update or upgrade function and takes control of protocol settings.", prevention: ["Access modifiers", "Role based access", "Avoid tx.origin"], incident: "The Parity multisig incidents exposed the impact of flawed authorization and initialization." },
  { id: "overflow", icon: AlertTriangle, name: "Integer Overflow / Underflow", severity: "High", score: 8.5, keywords: ["arithmetic", "integer", "balance", "solidity 0.8"], description: "Arithmetic wraps to an unexpected value when numeric bounds are exceeded.", cause: "Older compiler versions or unchecked blocks perform arithmetic without validation.", consequences: ["Incorrect balances", "Bypassed limits", "Loss of funds"], scenario: "A token balance underflows from zero to a huge number and lets an attacker transfer more than owned.", prevention: ["Solidity 0.8+", "Checked arithmetic", "Careful unchecked usage"], incident: "The 2018 batchOverflow token bug enabled attackers to create enormous token balances." },
  { id: "calls", icon: Code, name: "Unchecked Low-Level Calls", severity: "High", score: 8.2, keywords: ["call", "send", "return value", "failure"], description: "A contract ignores whether a low-level call, send, or delegatecall actually succeeded.", cause: "The boolean success value returned by an external interaction is discarded.", consequences: ["Inconsistent state", "Locked assets", "Failed settlement"], scenario: "The contract marks a payment complete even though the recipient call failed.", prevention: ["Check return values", "Use try/catch", "Handle failures explicitly"], incident: "Unchecked call patterns have repeatedly caused failed payouts and accounting failures in production contracts." },
  { id: "delegatecall", icon: Database, name: "Delegatecall Injection", severity: "High", score: 8.8, keywords: ["proxy", "implementation", "storage", "upgrade"], description: "Attacker-controlled code executes in the storage context of the calling contract.", cause: "delegatecall targets or calldata are accepted without a strict trust boundary.", consequences: ["Ownership takeover", "Storage corruption", "Arbitrary execution"], scenario: "An attacker supplies a malicious implementation that overwrites the owner storage slot.", prevention: ["Whitelist implementations", "Secure upgrade controls", "Never delegatecall untrusted addresses"], incident: "Several proxy and wallet exploits have abused delegatecall storage collisions." },
  { id: "dos", icon: Bug, name: "Denial of Service", severity: "Medium", score: 7.4, keywords: ["dos", "loop", "revert", "availability"], description: "A contract operation can be permanently or repeatedly prevented from completing.", cause: "Unbounded loops, push payments, or a single failing recipient block critical execution.", consequences: ["Permanent DoS", "Locked assets", "Unavailable protocol"], scenario: "One reverting recipient causes a looped payout function to revert for every user.", prevention: ["Pull over push", "Bounded loops", "Graceful failure handling"], incident: "Auction and payout contracts have been frozen by deliberately reverting recipients." },
  { id: "timestamp", icon: Activity, name: "Timestamp Dependence", severity: "Medium", score: 6.8, keywords: ["block timestamp", "randomness", "validator", "lottery"], description: "Critical logic relies on a block timestamp that validators can influence within a small range.", cause: "block.timestamp is used for randomness or exact financial outcomes.", consequences: ["Contract manipulation", "Unfair outcomes", "Predictable randomness"], scenario: "A validator chooses a favorable timestamp to win a timestamp-based lottery.", prevention: ["Use VRF for randomness", "Use tolerances", "Avoid timestamp for critical entropy"], incident: "Timestamp-based games and lotteries have repeatedly been exploitable by block producers." },
  { id: "frontrun", icon: Target, name: "Front Running", severity: "High", score: 8.1, keywords: ["mempool", "sandwich", "mev", "transaction ordering"], description: "An attacker observes a pending transaction and submits a better-positioned transaction first.", cause: "Transactions expose valuable intent in the public mempool without slippage or commit protections.", consequences: ["Value extraction", "Unfair pricing", "Transaction reordering"], scenario: "A bot buys before a user trade and sells immediately afterward at the manipulated price.", prevention: ["Slippage limits", "Commit-reveal", "Private order flow"], incident: "DEX sandwich attacks are a common real-world form of transaction-order dependence." },
  { id: "flashloan", icon: Shield, name: "Flash Loan Attack", severity: "Critical", score: 9.4, keywords: ["flash", "liquidity", "twap", "lending"], description: "Large uncollateralized temporary liquidity is used to manipulate a protocol within one transaction.", cause: "A protocol trusts a spot price or instantaneous balance that can be changed with borrowed liquidity.", consequences: ["Loss of funds", "Price manipulation", "Bad debt"], scenario: "An attacker flash-borrows assets, moves a pool price, borrows against inflated collateral, and repays the loan.", prevention: ["TWAP oracles", "Circuit breakers", "Liquidity-aware limits"], incident: "Cream Finance and bZx suffered flash-loan-assisted exploits." },
  { id: "oracle", icon: Shield, name: "Oracle Manipulation", severity: "Critical", score: 9.2, keywords: ["price feed", "chainlink", "spot price", "beanstalk"], description: "A protocol accepts an inaccurate external price or market signal.", cause: "A manipulable on-chain spot price is used as a trusted oracle without validation.", consequences: ["Loss of funds", "Bad debt", "Incorrect liquidations"], scenario: "An attacker skews a low-liquidity pair reserve, then borrows or liquidates using the false valuation.", prevention: ["Reliable feeds", "TWAP", "Staleness and deviation checks"], incident: "Beanstalk and multiple lending protocols have suffered oracle-driven losses." },
  { id: "events", icon: Activity, name: "Missing Events", severity: "Low", score: 3.5, keywords: ["logging", "transparency", "indexing", "monitoring"], description: "Important state changes occur without emitting Solidity events, making activity difficult to track off-chain.", cause: "State-mutating functions update storage without an accompanying event declaration and emit statement.", consequences: ["Reduced transparency", "Harder auditing", "Poor off-chain indexing", "Difficult event monitoring"], scenario: "A privileged account changes a fee without an event, so users and monitoring systems cannot reliably detect the update.", prevention: ["Emit events for important state changes", "Index key event parameters", "Document event semantics"], incident: "This is a common production-quality issue: well-designed protocols use events so explorers, indexers, and users can audit state changes." },
  { id: "validation", icon: AlertTriangle, name: "Missing Input Validation", severity: "Low", score: 4.1, keywords: ["require", "parameters", "address zero", "sanitization"], description: "Function parameters are accepted without validating user input, allowing unexpected or invalid values.", cause: "Functions process addresses, amounts, or configuration values without checking basic invariants first.", consequences: ["Unexpected execution", "Poor user experience", "Wasted gas", "Incorrect state updates"], scenario: "A user submits the zero address as a recipient; the contract accepts it and creates an unusable state update.", prevention: ["Validate parameters with require()", "Reject zero addresses", "Validate bounds before processing"], incident: "Input-validation failures are frequently identified in audits because they can create invalid states even without a direct exploit." },
];

const bestPractices = [
  [Shield, "Checks Effects Interactions", "Update state before interacting with untrusted contracts."], [Lock, "ReentrancyGuard", "Protect sensitive external-call paths with a reentrancy lock."], [Shield, "Access Modifiers", "Restrict administrative actions to explicit roles."], [Database, "Pull Payments", "Let recipients withdraw funds instead of pushing transfers."], [Code, "Input Validation", "Validate addresses, ranges, and protocol invariants."], [Activity, "Oracle Validation", "Use robust sources with freshness and deviation checks."], [AlertTriangle, "Upgrade Carefully", "Secure implementation and initialization paths."], [Target, "Least Privilege", "Give each role only the authority it needs."], [Shield, "Emergency Pause", "Provide a controlled pause for incident response."], [CheckCircle, "Latest Solidity Compiler", "Use maintained compiler releases and their safety checks."],
];

const severityClass = (severity) => `severity-${severity.toLowerCase()}`;

const VulnerabilityModal = ({ item, onClose }) => {
  const [vulnerableCode, secureCode] = codeExamples[item.id];
  return <div className="vulnerability-modal-backdrop" role="presentation" onMouseDown={onClose}>
    <article className="vulnerability-modal" role="dialog" aria-modal="true" aria-labelledby="vulnerability-title" onMouseDown={(event) => event.stopPropagation()}>
      <button className="modal-close" type="button" onClick={onClose} aria-label="Close details"><X size={21} /></button>
      <header className="modal-header"><item.icon size={30} /><div><span className={`severity-badge ${severityClass(item.severity)}`}>{item.severity}</span><h2 id="vulnerability-title">{item.name}</h2></div></header>
      <section><h3><BookOpen size={18} /> Description</h3><p>{item.description}</p></section>
      <section><h3><AlertTriangle size={18} /> Root Cause</h3><p>{item.cause}</p></section>
      <section><h3><Bug size={18} /> Potential Consequences</h3><ul>{item.consequences.map((entry) => <li key={entry}>{entry}</li>)}</ul></section>
      <section><h3><Target size={18} /> Attack Scenario</h3><p>{item.scenario}</p></section>
      <section className="modal-code"><h3><Code size={18} /> Vulnerable Solidity Code</h3><SyntaxHighlighter language="solidity" style={vscDarkPlus} customStyle={{ margin: 0, borderRadius: "10px" }}>{vulnerableCode}</SyntaxHighlighter></section>
      <section className="modal-code"><h3><CheckCircle size={18} /> Secure Solidity Code</h3><SyntaxHighlighter language="solidity" style={vscDarkPlus} customStyle={{ margin: 0, borderRadius: "10px" }}>{secureCode}</SyntaxHighlighter></section>
      <section><h3><Shield size={18} /> Prevention</h3><ul>{item.prevention.map((entry) => <li key={entry}>{entry}</li>)}</ul></section>
      <section><h3><Activity size={18} /> Real World Incident</h3><p>{item.incident}</p></section>
      <section><h3><BookOpen size={18} /> References</h3><div className="reference-links"><a href="https://docs.openzeppelin.com/contracts/" target="_blank" rel="noreferrer">OpenZeppelin Docs</a><a href="https://docs.soliditylang.org/" target="_blank" rel="noreferrer">Solidity Docs</a><a href="https://swcregistry.io/" target="_blank" rel="noreferrer">SWC Registry</a><a href="https://owasp.org/www-project-smart-contract-top-10/" target="_blank" rel="noreferrer">OWASP Smart Contract Top 10</a></div></section>
    </article>
  </div>;
};

const VulnerabilitiesPage = () => {
  const [selected, setSelected] = useState(null);
  const [activeFilter, setActiveFilter] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const filters = ["All", "Critical", "High", "Medium", "Low"];
  const normalizedQuery = searchQuery.trim().toLowerCase();
  const visibleVulnerabilities = vulnerabilities.filter((item) => {
    const severityMatches = activeFilter === "All" || item.severity === activeFilter;
    const searchableText = [item.name, item.description, ...item.keywords].join(" ").toLowerCase();
    return severityMatches && (!normalizedQuery || searchableText.includes(normalizedQuery));
  });
  return <section className="knowledge-page">
    <header className="knowledge-heading"><h1>🛡️ About Smart Contract Vulnerabilities</h1></header>
    <div className="knowledge-controls"><label className="knowledge-search"><Search size={20} /><input type="search" placeholder="Search Vulnerability..." aria-label="Search Vulnerability" value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} /></label><div className="severity-filters" aria-label="Severity filters">{filters.map((filter) => <button key={filter} type="button" className={`${activeFilter === filter ? "is-active" : ""} severity-filter-${filter.toLowerCase()}`} onClick={() => setActiveFilter(filter)}>{filter === "All" ? "All" : <><span className={`filter-dot ${severityClass(filter)}`} />{filter}</>}</button>)}</div></div>
    {visibleVulnerabilities.length ? <div className="vulnerability-grid">{visibleVulnerabilities.map((item) => { const Icon = item.icon; return <article className={`knowledge-card ${severityClass(item.severity)}`} key={item.id}><div className="knowledge-card-top"><span className="knowledge-icon"><Icon size={25} /></span><span className={`severity-badge ${severityClass(item.severity)}`}>{item.severity}</span></div><h2>{item.name}</h2><p>{item.description}</p><div className="risk-score"><div><span>Risk Score</span><strong>{item.score} <small>/ 10</small></strong></div><div className="risk-track"><i style={{ width: `${item.score * 10}%` }} /></div></div><button type="button" className="learn-more" onClick={() => setSelected(item)}>Learn More <ChevronRight size={17} /></button></article>; })}</div> : <div className="knowledge-empty">No vulnerabilities found.</div>}
    <section className="best-practices"><header><span><CheckCircle size={25} /></span><div><h2>Solidity Security Best Practices</h2><p>Build stronger contracts by applying these defensive patterns from the start.</p></div></header><div className="practices-grid">{bestPractices.map(([Icon, title, text]) => <article key={title}><Icon size={23} /><h3>{title}</h3><p>{text}</p></article>)}</div></section>
    {selected && <VulnerabilityModal item={selected} onClose={() => setSelected(null)} />}
  </section>;
};

export default VulnerabilitiesPage;
