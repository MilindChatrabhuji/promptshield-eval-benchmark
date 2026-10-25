# PromptShield: Frontier AI Adversarial & Red-Teaming Benchmark

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](https://python.org)
[![Dataset: Ground--Truth](https://img.shields.io/badge/Ground--Truth-Verified-orange.svg)](data/)

**PromptShield** is a curated adversarial red-teaming benchmark and evaluation harness for LLM applications, agentic frameworks, and AI guardrails. 

It provides deterministic, 100% human-verified ground-truth classifications across critical frontier LLM threat vectors:
- **Instruction Overrides & Direct Prompt Injections**
- **Delimiter Cloaking & Context Escapes**
- **Roleplay Subversion & Persona Hijacking**
- **Covert Data Exfiltration & Token Smuggling**
- **System Tool & Function-Calling Abuse**

---

## 📦 What's Included

1. **Free Evaluation Suite (`data/promptshield_sample_v1.jsonl`)**: 25 verified adversarial test vectors across multiple threat categories.
2. **Deterministic Evaluation Harness (`promptshield/evaluator.py`)**: Python engine to test your custom LLM guardrails or regex filters and measure Accuracy, Precision, Recall, and F1 Score against the ground truth.
3. **Automated Unit Tests (`tests/test_evaluator.py`)**: Pre-configured test suite verifying evaluation metric consistency.

---

## 🚀 Quickstart

### Installation

```bash
git clone https://github.com/MilindChatrabhuji/promptshield-eval-benchmark.git
cd promptshield-eval-benchmark
pip install -r requirements.txt
```

### Running an Evaluation

```python
from promptshield import PromptShieldEvaluator, baseline_heuristic_filter

# 1. Initialize with benchmark vectors
evaluator = PromptShieldEvaluator("data/promptshield_sample_v1.jsonl")

# 2. Test your custom guardrail or baseline filter
# (filter_fn takes input string, returns True if blocked/flagged)
results = evaluator.evaluate_filter(baseline_heuristic_filter)

# 3. Inspect accuracy and defense metrics
print(f"Total Samples    : {results.total_samples}")
print(f"Accuracy         : {results.accuracy_percent}%")
print(f"Precision        : {results.precision_percent}%")
print(f"Recall           : {results.recall_percent}%")
print(f"F1 Score         : {results.f1_score}")
```

Run tests with `pytest`:
```bash
pytest tests/
```

---

## 🛡️ Enterprise & Full Ground-Truth Dataset (110+ Vectors)

The full **PromptShield Enterprise Benchmark** contains **110+ verified multi-vector ground-truth samples** with threat severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`), deterministic rule signatures, and attack categorization.

- **License**: Commercial Enterprise AI Safety License (Perpetual, Royalty-Free)
- **Price**: **$49.00 USD** (One-time commercial license)
- **Instant Delivery**: Downloadable JSONL with complete metadata and test vectors.
- **Get Full License**: [Purchase on Polar.sh](https://polar.sh/MilindChatrabhuji/products/promptshield-benchmark)

---

## 📄 License

This open-source evaluation preview and test harness is licensed under the [MIT License](LICENSE).
The full 110+ commercial dataset is licensed under the PromptShield Enterprise Evaluation License.
