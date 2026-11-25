"""Evaluate CyberIntel AI and write a report to eval/results/latest.md.

Run from backend/ with (venv) active, while Qdrant is running and after /ingest:

    python -m scripts.evaluate                          # retrieval metrics for every search mode
    python -m scripts.evaluate --chunk-sizes 800,1000,1200   # + chunk size experiment
    python -m scripts.evaluate --answers                # + answer grounding (uses Gemini)
    python -m scripts.evaluate --chunk-sizes 400,800,1200 --answers   # everything
"""
import argparse
import logging

from app.evaluation.runner import chunk_size_experiment, evaluate_answers, evaluate_retrieval, write_report

logging.basicConfig(level=logging.WARNING)


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate CyberIntel AI retrieval and answers")
    ap.add_argument("--chunk-sizes", default="", help="comma-separated sizes to compare, e.g. 400,800,1200")
    ap.add_argument("--answers", action="store_true", help="also generate answers and check grounding (uses Gemini)")
    args = ap.parse_args()

    print("1/3  Evaluating retrieval for every search mode (about 2 minutes)...")
    retrieval = evaluate_retrieval()
    k = retrieval["k"]
    print(f"\n{'Mode':<24}{'Hit@1':>8}{f'Hit@{k}':>8}{'MRR':>8}")
    print("-" * 48)
    best = max(retrieval["configs"].items(), key=lambda kv: (kv[1]["mrr"], kv[1]["hit@1"]))[0]
    for name, r in retrieval["configs"].items():
        mark = "  <- best" if name == best else ""
        print(f"{name:<24}{r['hit@1']:>8.2f}{r[f'hit@{k}']:>8.2f}{r['mrr']:>8.2f}{mark}")

    sizes = None
    if args.chunk_sizes:
        size_list = [int(s) for s in args.chunk_sizes.split(",") if s.strip()]
        print(f"\n2/3  Chunk size experiment {size_list} (temporary collections)...")
        sizes = chunk_size_experiment(size_list)
        names = [n for n in next(iter(sizes.values())) if n != "chunks"]
        print(f"\nMRR by chunk size")
        print(f"{'Size':<8}{'Chunks':>8}" + "".join(f"{n:>18}" for n in names))
        for size, r in sizes.items():
            print(f"{size:<8}{r['chunks']:>8}" + "".join(f"{r[n]['mrr']:>18.2f}" for n in names))
    else:
        print("\n2/3  Chunk size experiment skipped (add --chunk-sizes 400,800,1200)")

    answers = None
    if args.answers:
        print("\n3/3  Generating answers and checking grounding (this calls Gemini, ~1 minute)...")
        answers = evaluate_answers()
        print(f"  answerable questions answered correctly: {answers['answerable_correct_rate']}")
        print(f"  unanswerable questions refused:           {answers['unanswerable_refusal_rate']}")
        print(f"  answers with hallucinated CVE IDs:        {answers['hallucinated_cve_answers']}")
        print(f"  LLM failures (all models busy):           {answers['llm_failures']}")
    else:
        print("\n3/3  Answer grounding skipped (add --answers)")

    path = write_report(retrieval, sizes, answers)
    print(f"\nReport written to {path}  (and eval/results/latest.md)")


if __name__ == "__main__":
    main()
