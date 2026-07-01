#!/usr/bin/env python3
"""Train the job-title -> department classifier.

Pipeline:
  1. Load ``data/titles.csv`` (columns: title, department).
  2. Normalize titles (lowercase, strip punctuation, expand abbreviations).
  3. Embed with the ``all-MiniLM-L6-v2`` sentence-transformer.
  4. Train ``LogisticRegression(max_iter=1000, class_weight='balanced')``.
  5. Evaluate on a stratified 80/20 split and print a classification report.
  6. Serialize ``model/classifier.pkl`` and ``model/labels.json`` with joblib.

    python train.py
    python train.py --data data/titles.csv --test-size 0.2

The ``Unknown`` bucket is never trained — any such rows are dropped here. Unknown
is a post-hoc threshold decision made in classify.py, not a learned class.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from categories import DEPARTMENT_NAMES, UNKNOWN_LABEL, normalize

try:
    from sentence_transformers import SentenceTransformer
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("sentence-transformers not installed. Run: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA = ROOT / "data" / "titles.csv"
MODEL_DIR = ROOT / "model"
CLASSIFIER_PATH = MODEL_DIR / "classifier.pkl"
LABELS_PATH = MODEL_DIR / "labels.json"
EMBED_MODEL = "all-MiniLM-L6-v2"


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        sys.exit(f"training data not found: {path}\nRun generate_data.py first.")
    df = pd.read_csv(path)
    missing = {"title", "department"} - set(df.columns)
    if missing:
        sys.exit(f"{path} is missing required columns: {sorted(missing)}")

    df = df.dropna(subset=["title", "department"]).copy()
    df["title"] = df["title"].astype(str).str.strip()
    df["department"] = df["department"].astype(str).str.strip()

    # Drop the post-hoc bucket and anything outside the trainable taxonomy.
    valid = set(DEPARTMENT_NAMES)
    before = len(df)
    df = df[df["department"] != UNKNOWN_LABEL]
    df = df[df["department"].isin(valid)]
    dropped = before - len(df)
    if dropped:
        print(f"Dropped {dropped} rows outside the trainable taxonomy.")

    # Normalize and drop rows that normalize to nothing / become duplicates.
    df["normalized"] = df["title"].map(normalize)
    df = df[df["normalized"].str.len() > 0]
    df = df.drop_duplicates(subset=["normalized", "department"])
    return df.reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = load_dataset(args.data)
    print(f"Loaded {len(df)} usable examples across "
          f"{df['department'].nunique()} departments.")

    # Guard: stratified split needs at least 2 examples per class.
    counts = df["department"].value_counts()
    too_small = counts[counts < 2]
    if not too_small.empty:
        sys.exit(f"These departments have <2 examples, cannot stratify: "
                 f"{too_small.to_dict()}")

    print(f"Embedding with {EMBED_MODEL} ...")
    embedder = SentenceTransformer(EMBED_MODEL)
    X = embedder.encode(
        df["normalized"].tolist(),
        show_progress_bar=True,
        normalize_embeddings=True,
    )
    X = np.asarray(X)
    y = df["department"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n=== Classification report (held-out 20%) ===")
    print(classification_report(y_test, y_pred, digits=3, zero_division=0))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, CLASSIFIER_PATH)
    labels = {
        "classes": clf.classes_.tolist(),
        "embedding_model": EMBED_MODEL,
        "unknown_label": UNKNOWN_LABEL,
    }
    with LABELS_PATH.open("w", encoding="utf-8") as fh:
        json.dump(labels, fh, indent=2)

    print(f"\nSaved classifier -> {CLASSIFIER_PATH}")
    print(f"Saved labels     -> {LABELS_PATH}")


if __name__ == "__main__":
    main()
