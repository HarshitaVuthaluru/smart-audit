"""
Phase 6 Evaluation Dataset — Established Ground Truth
Manually established from source code inspection + contract_vulns.json line annotations.

Evaluation set: 12 out-of-sample contracts from known_vulnerabilities/dataset/
These are NOT in the Phase 5 regression set.
RAG membership is noted per contract.

Ground truth format: (contract_file, function_name_base, expected_category)
"""

PHASE6_GROUND_TRUTH = [
    # -------- REENTRANCY (4 contracts) --------
    {
        "contract_name": "etherstore.sol",
        "path": "known_vulnerabilities/dataset/reentrancy/etherstore.sol",
        "in_rag": False,
        "functions_gt": [("withdrawFunds", "reentrancy")],
        "evidence": "Line 27: msg.sender.call.value() before balances update at line 28",
        "source": "sigp/solidity-security-blog"
    },
    {
        "contract_name": "etherbank.sol",
        "path": "known_vulnerabilities/dataset/reentrancy/etherbank.sol",
        "in_rag": False,
        "functions_gt": [("withdrawBalance", "reentrancy")],
        "evidence": "Line 21: msg.sender.call.value() before userBalances zeroed at line 22",
        "source": "EthBench"
    },
    {
        "contract_name": "simple_dao.sol",
        "path": "known_vulnerabilities/dataset/reentrancy/simple_dao.sol",
        "in_rag": False,
        "functions_gt": [("withdraw", "reentrancy")],
        "evidence": "Line 19: msg.sender.call.value() before credit decrement at line 20",
        "source": "blockchain.unica.it"
    },
    {
        "contract_name": "reentrancy_simple.sol",
        "path": "known_vulnerabilities/dataset/reentrancy/reentrancy_simple.sol",
        "in_rag": False,
        "functions_gt": [("withdrawBalance", "reentrancy")],
        "evidence": "Line 24: msg.sender.call.value() before userBalance zeroed at line 27",
        "source": "trailofbits/not-so-smart-contracts"
    },
    # -------- ACCESS CONTROL (3 contracts) --------
    {
        "contract_name": "simple_suicide.sol",
        "path": "known_vulnerabilities/dataset/access_control/simple_suicide.sol",
        "in_rag": True,  # in_rag from chroma metadata
        "functions_gt": [("sudicideAnyone", "access_control")],
        "evidence": "Lines 12-13: unprotected selfdestruct callable by anyone",
        "source": "SWC-registry"
    },
    {
        "contract_name": "unprotected0.sol",
        "path": "known_vulnerabilities/dataset/access_control/unprotected0.sol",
        "in_rag": False,
        "functions_gt": [("changeOwner", "access_control")],
        "evidence": "Line 25: changeOwner callable without onlyowner modifier",
        "source": "trailofbits/not-so-smart-contracts"
    },
    {
        "contract_name": "phishable.sol",
        "path": "known_vulnerabilities/dataset/access_control/phishable.sol",
        "in_rag": False,
        "functions_gt": [("withdrawAll", "access_control")],
        "evidence": "Line 20: tx.origin authentication (phishable) allows any authorized UI to drain funds",
        "source": "sigp/solidity-security-blog"
    },
    # -------- BAD RANDOMNESS (2 contracts) --------
    {
        "contract_name": "random_number_generator.sol",
        "path": "known_vulnerabilities/dataset/bad_randomness/random_number_generator.sol",
        "in_rag": False,
        "functions_gt": [("random", "bad_randomness")],
        "evidence": "Lines 12,18,20,22: block.timestamp/block.number/blockhash used as randomness seeds",
        "source": "SWC-registry"
    },
    {
        "contract_name": "old_blockhash.sol",
        "path": "known_vulnerabilities/dataset/bad_randomness/old_blockhash.sol",
        "in_rag": False,
        "functions_gt": [("settle", "bad_randomness")],
        "evidence": "Line 35: blockhash used as game answer (predictable after 256 blocks returns 0)",
        "source": "SWC-registry / capturetheether.com"
    },
    # -------- UNCHECKED LOW LEVEL CALLS (2 contracts) --------
    {
        "contract_name": "mishandled.sol",
        "path": "known_vulnerabilities/dataset/unchecked_low_level_calls/mishandled.sol",
        "in_rag": True,  # mishandled.sol is in chroma sources
        "functions_gt": [("withdrawBalance", "unchecked_low_level_calls")],
        "evidence": "Line 14: msg.sender.send() return value not checked",
        "source": "EthBench"
    },
    {
        "contract_name": "unchecked_return_value.sol",
        "path": "known_vulnerabilities/dataset/unchecked_low_level_calls/unchecked_return_value.sol",
        "in_rag": False,
        "functions_gt": [("callnotchecked", "unchecked_low_level_calls")],
        "evidence": "Line 17: callee.call() return value not checked",
        "source": "SWC-registry"
    },
    # -------- ARITHMETIC (1 contract) --------
    {
        "contract_name": "integer_overflow_minimal.sol",
        "path": "known_vulnerabilities/dataset/arithmetic/integer_overflow_minimal.sol",
        "in_rag": False,
        "functions_gt": [("run", "arithmetic")],
        "evidence": "Line 17: count -= input without overflow check (Solidity <0.8)",
        "source": "SWC-registry"
    },
]

if __name__ == "__main__":
    print(f"Phase 6 evaluation set: {len(PHASE6_GROUND_TRUTH)} contracts")
    total_gt = sum(len(c['functions_gt']) for c in PHASE6_GROUND_TRUTH)
    print(f"Total expected findings: {total_gt}")
    in_rag = sum(1 for c in PHASE6_GROUND_TRUTH if c['in_rag'])
    out_rag = sum(1 for c in PHASE6_GROUND_TRUTH if not c['in_rag'])
    print(f"Contracts IN RAG corpus: {in_rag}")
    print(f"Contracts OUT OF RAG corpus (strict out-of-sample): {out_rag}")
    cats = {}
    for c in PHASE6_GROUND_TRUTH:
        for fn, cat in c['functions_gt']:
            cats[cat] = cats.get(cat, 0) + 1
    print("Category distribution:", cats)
