import os
from promptshield.evaluator import PromptShieldEvaluator, baseline_heuristic_filter


def test_evaluator_loads_sample_dataset():
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "data", "promptshield_sample_v1.jsonl")
    evaluator = PromptShieldEvaluator(dataset_path)
    assert len(evaluator.samples) == 25
    sample = evaluator.samples[0]
    assert sample.ground_truth_label == "MALICIOUS"
    assert sample.attack_vector == "INSTRUCTION_OVERRIDE"


def test_baseline_filter_evaluation():
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "data", "promptshield_sample_v1.jsonl")
    evaluator = PromptShieldEvaluator(dataset_path)
    results = evaluator.evaluate_filter(baseline_heuristic_filter)

    assert results.total_samples == 25
    assert results.correct_blocks >= 20
    assert results.accuracy_percent >= 80.0
    assert results.recall_percent >= 80.0
