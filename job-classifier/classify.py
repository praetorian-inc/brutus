#!/usr/bin/env python3
"""Classify job titles into departments using the trained model.

Single title:
    python classify.py --title "Director of Information Technology"

Batch (one title per line in the input file):
    python classify.py --input titles.txt --output results.csv --threshold 0.6

Batch output is a CSV with columns: title, department, confidence.

Any title whose top probability is below ``--threshold`` is labeled ``Unknown``
regardless of the argmax prediction — Unknown is a confidence decision, not a
learned class. ``--verbose`` prints the full probability distribution across all
classes, which is handy for debugging ambiguous titles.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import joblib
import numpy as np

from categories import UNKNOWN_LABEL, normalize

try:
    from sentence_transformers import SentenceTransformer
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("sentence-transformers not installed. Run: pip install -r requirements.txt")

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("tqdm not installed. Run: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "model"
CLASSIFIER_PATH = MODEL_DIR / "classifier.pkl"
LABELS_PATH = MODEL_DIR / "labels.json"


class Classifier:
    """Loads the trained model once and predicts on demand."""

    def __init__(self) -> None:
        if not CLASSIFIER_PATH.exists() or not LABELS_PATH.exists():
            sys.exit("model artifacts not found in model/. Run train.py first.")
        self.clf = joblib.load(CLASSIFIER_PATH)
        with LABELS_PATH.open(encoding="utf-8") as fh:
            meta = json.load(fh)
        self.classes: list[str] = meta["classes"]
        self.unknown_label: str = meta.get("unknown_label", UNKNOWN_LABEL)
        self.embedder = SentenceTransformer(meta["embedding_model"])

    def _embed(self, titles: list[str]) -> np.ndarray:
        normalized = [normalize(t) for t in titles]
        return np.asarray(
            self.embedder.encode(normalized, normalize_embeddings=True)
        )

    def predict(self, titles: list[str], threshold: float,
                show_progress: bool = False) -> list[dict]:
        """Return per-title dicts: title, department, confidence, probabilities."""
        if not titles:
            return []
        embeddings = self._embed(titles)
        proba = self.clf.predict_proba(embeddings)
        results = []
        iterator = zip(titles, proba)
        if show_progress:
            iterator = tqdm(iterator, total=len(titles), desc="classifying")
        for title, dist in iterator:
            top_idx = int(np.argmax(dist))
            confidence = float(dist[top_idx])
            argmax_label = self.clf.classes_[top_idx]
            label = argmax_label if confidence >= threshold else self.unknown_label
            results.append({
                "title": title,
                "department": label,
                "confidence": confidence,
                "argmax": argmax_label,
                "probabilities": {
                    str(cls): float(p)
                    for cls, p in zip(self.clf.classes_, dist)
                },
            })
        return results


def print_verbose(result: dict) -> None:
    print(f"\nTitle: {result['title']}")
    print(f"  -> {result['department']}  (confidence {result['confidence']:.3f})")
    if result["department"] == UNKNOWN_LABEL:
        print(f"     argmax was {result['argmax']} but below threshold")
    print("  probability distribution:")
    for cls, p in sorted(result["probabilities"].items(),
                         key=lambda kv: kv[1], reverse=True):
        bar = "#" * int(round(p * 40))
        print(f"    {cls:<22} {p:0.3f} {bar}")


def read_titles(path: Path) -> list[str]:
    if not path.exists():
        sys.exit(f"input file not found: {path}")
    with path.open(encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--title", help="classify a single job title")
    group.add_argument("--input", type=Path, help="file of titles (one per line)")
    parser.add_argument("--output", type=Path,
                        help="output CSV for batch mode (default: stdout)")
    parser.add_argument("--threshold", type=float, default=0.6,
                        help="min top-probability to accept; else Unknown "
                             "(default: 0.6)")
    parser.add_argument("--verbose", action="store_true",
                        help="print the full probability distribution")
    args = parser.parse_args()

    clf = Classifier()

    if args.title is not None:
        result = clf.predict([args.title], args.threshold)[0]
        if args.verbose:
            print_verbose(result)
        else:
            print(f"{result['department']}  (confidence {result['confidence']:.3f})")
        return

    titles = read_titles(args.input)
    results = clf.predict(titles, args.threshold, show_progress=bool(args.output))

    if args.verbose:
        for result in results:
            print_verbose(result)

    if args.output:
        with args.output.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["title", "department", "confidence"])
            for r in results:
                writer.writerow([r["title"], r["department"],
                                 f"{r['confidence']:.4f}"])
        print(f"Wrote {len(results)} rows to {args.output}")
    elif not args.verbose:
        writer = csv.writer(sys.stdout)
        writer.writerow(["title", "department", "confidence"])
        for r in results:
            writer.writerow([r["title"], r["department"],
                             f"{r['confidence']:.4f}"])


if __name__ == "__main__":
    main()
