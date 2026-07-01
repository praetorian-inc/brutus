#!/usr/bin/env python3
"""Train a pure-Go-portable n-gram + linear classifier and export it.

This is the Go-friendly sibling of train.py. Instead of a sentence-transformer,
it turns each title into a sparse character n-gram TF-IDF vector, then trains the
same LogisticRegression head. Everything it needs at inference time
(vocabulary, IDF weights, coefficients, the abbreviation map) is exported to a
single JSON file that the Go package embeds — no CGo, no model download.

It uses the SAME preprocessing and the SAME stratified split as train.py so the
printed accuracy is directly comparable to the transformer model. Pass
--compare to also train the MiniLM model on the identical split for a true
side-by-side.

    python train_go.py                 # train + export + n-gram report
    python train_go.py --compare       # also print the transformer baseline

Outputs:
    model/go_model.json   runtime model embedded by the Go package
    model/go_parity.json  golden samples for the Go cross-language test
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from categories import ABBREVIATIONS, UNKNOWN_LABEL
from train import DEFAULT_DATA, EMBED_MODEL, load_dataset

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "model"
GO_MODEL_PATH = MODEL_DIR / "go_model.json"
GO_PARITY_PATH = MODEL_DIR / "go_parity.json"

NGRAM_MIN, NGRAM_MAX = 3, 5
MAX_FEATURES = 5000
DEFAULT_THRESHOLD = 0.5

# Titles used to lock Go<->Python parity. Chosen to span departments, seniority,
# abbreviations, punctuation, regional variants, and clear Unknown-bait.
PARITY_TITLES = [
    "Director of Information Technology",
    "Sr. Staff Software Engineer, Platform",
    "SOC Analyst II",
    "VP of Demand Gen",
    "Chief of Staff to the CEO",
    "Chartered Accountant",
    "CISO",
    "Help Desk Technician (Tier 1)",
    "General Counsel & Corporate Secretary",
    "Talent Acquisition Partner, EMEA",
    "Regional Sales Director",
    "Head of Growth",
    "Managing Director",
    "Network Engineer III",
    "Data Protection Officer",
    "Penguin Wrangler",
    "asdf qwerty zxcv",
]


def build_report(y_true, y_pred, title: str) -> None:
    print(f"\n=== {title} ===")
    print(f"accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print(classification_report(y_true, y_pred, digits=3, zero_division=0))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--compare", action="store_true",
                        help="also train MiniLM on the same split for comparison")
    args = parser.parse_args()

    df = load_dataset(args.data)
    print(f"Loaded {len(df)} usable examples across "
          f"{df['department'].nunique()} departments.")

    # Identical split to train.py (same seed / stratify) => comparable numbers.
    idx_train, idx_test = train_test_split(
        np.arange(len(df)),
        test_size=args.test_size,
        random_state=args.seed,
        stratify=df["department"].to_numpy(),
    )
    norm = df["normalized"].to_numpy()
    y = df["department"].to_numpy()

    # --- n-gram TF-IDF pipeline ------------------------------------------------
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(NGRAM_MIN, NGRAM_MAX),
        max_features=MAX_FEATURES,
        lowercase=True,          # idempotent: normalize() already lowercased
        norm="l2",
        use_idf=True,
        smooth_idf=True,
        sublinear_tf=False,
    )
    X_train = vectorizer.fit_transform(norm[idx_train])
    X_test = vectorizer.transform(norm[idx_test])

    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(X_train, y[idx_train])

    y_pred = clf.predict(X_test)
    build_report(y[idx_test], y_pred, "n-gram + LogisticRegression (Go-portable)")
    print(f"Vocabulary size: {len(vectorizer.vocabulary_)}")

    if args.compare:
        from sentence_transformers import SentenceTransformer
        print(f"\nEmbedding with {EMBED_MODEL} for side-by-side comparison ...")
        embedder = SentenceTransformer(EMBED_MODEL)
        emb = np.asarray(embedder.encode(norm.tolist(),
                                         normalize_embeddings=True,
                                         show_progress_bar=False))
        tclf = LogisticRegression(max_iter=1000, class_weight="balanced")
        tclf.fit(emb[idx_train], y[idx_train])
        build_report(y[idx_test], tclf.predict(emb[idx_test]),
                     f"{EMBED_MODEL} + LogisticRegression (transformer baseline)")

    # --- export runtime model --------------------------------------------------
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    vocab = {term: int(idx) for term, idx in vectorizer.vocabulary_.items()}
    model = {
        "version": 1,
        "classes": clf.classes_.tolist(),
        "unknown_label": UNKNOWN_LABEL,
        "ngram_min": NGRAM_MIN,
        "ngram_max": NGRAM_MAX,
        "norm": "l2",
        "default_threshold": DEFAULT_THRESHOLD,
        "abbreviations": dict(ABBREVIATIONS),
        "vocabulary": vocab,
        "idf": vectorizer.idf_.tolist(),
        "coef": clf.coef_.tolist(),         # [n_classes][n_features]
        "intercept": clf.intercept_.tolist(),  # [n_classes]
    }
    with GO_MODEL_PATH.open("w", encoding="utf-8") as fh:
        json.dump(model, fh)
    print(f"\nExported runtime model -> {GO_MODEL_PATH} "
          f"({GO_MODEL_PATH.stat().st_size // 1024} KB)")

    # --- export parity fixture -------------------------------------------------
    proba = clf.predict_proba(vectorizer.transform(
        [__import__("categories").normalize(t) for t in PARITY_TITLES]
    ))
    samples = []
    for raw, dist in zip(PARITY_TITLES, proba):
        top = int(np.argmax(dist))
        samples.append({
            "raw": raw,
            "normalized": __import__("categories").normalize(raw),
            "argmax": clf.classes_[top],
            "confidence": float(dist[top]),
            "probabilities": {
                str(c): float(p) for c, p in zip(clf.classes_, dist)
            },
        })
    with GO_PARITY_PATH.open("w", encoding="utf-8") as fh:
        json.dump({"samples": samples}, fh, indent=2)
    print(f"Exported parity fixture -> {GO_PARITY_PATH} ({len(samples)} samples)")


if __name__ == "__main__":
    main()
