#!/usr/bin/env python3
"""Bootstrap loop: relabel low-confidence predictions with Claude, then retrain.

Given a ``results.csv`` produced by a batch ``classify.py`` run, this:
  1. Loads the rows and keeps those with confidence < --min-confidence (0.75).
  2. Sends those titles back to Claude in batches asking for the correct
     department (same taxonomy as the classifier).
  3. Appends the new (title, department) labels to ``data/titles.csv``.
  4. Re-runs train.py so the model tightens on the hard cases.

    python refine.py --results results.csv
    python refine.py --results results.csv --min-confidence 0.75 --no-train

Requires ``ANTHROPIC_API_KEY``. Titles the model can only mark ``Unknown`` are
skipped rather than appended — Unknown is never a training label.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd

from categories import ALL_LABELS, DEPARTMENT_NAMES, UNKNOWN_LABEL

try:
    import anthropic
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("anthropic SDK not installed. Run: pip install -r requirements.txt")

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - dependency guard
    sys.exit("tqdm not installed. Run: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent
DATA_CSV = ROOT / "data" / "titles.csv"
TRAIN_SCRIPT = ROOT / "train.py"
DEFAULT_MODEL = "claude-sonnet-4-6"
BATCH_SIZE = 50

SYSTEM_PROMPT = (
    "You are labeling job titles for a classifier. Assign each title to exactly "
    "one of these departments:\n"
    + "\n".join(f"- {name}" for name in DEPARTMENT_NAMES)
    + f"\n- {UNKNOWN_LABEL} (only if the title genuinely fits none of the above)\n\n"
    "Respond ONLY with a JSON array of objects, one per input title, in the same "
    'order, each like {"title": <string>, "department": <string>}. '
    "No preamble, no markdown fences."
)

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def load_low_confidence(results_path: Path, min_confidence: float) -> list[str]:
    if not results_path.exists():
        sys.exit(f"results file not found: {results_path}")
    df = pd.read_csv(results_path)
    missing = {"title", "confidence"} - set(df.columns)
    if missing:
        sys.exit(f"{results_path} missing columns: {sorted(missing)}")
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce")
    low = df[df["confidence"] < min_confidence]
    titles = [str(t).strip() for t in low["title"].tolist() if str(t).strip()]
    # Dedupe while preserving order.
    seen: set[str] = set()
    unique = []
    for t in titles:
        k = t.lower()
        if k not in seen:
            seen.add(k)
            unique.append(t)
    return unique


def parse_labels(raw: str) -> list[dict]:
    cleaned = _FENCE_RE.sub("", raw).strip()
    data = json.loads(cleaned)
    if not isinstance(data, list):
        raise ValueError("response was not a JSON array")
    return data


def label_batch(
    client: "anthropic.Anthropic",
    model: str,
    titles: list[str],
    max_retries: int = 5,
) -> list[tuple[str, str]]:
    """Return (title, department) pairs for one batch, with backoff retry."""
    user_prompt = (
        "Label these job titles. Return a JSON array of "
        f"{len(titles)} objects in the same order.\n\n"
        + json.dumps(titles, ensure_ascii=False)
    )
    valid = set(ALL_LABELS)
    delay = 2.0
    last_err: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=8000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            text = "".join(b.text for b in resp.content if b.type == "text")
            labeled = parse_labels(text)
            out: list[tuple[str, str]] = []
            for item in labeled:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title", "")).strip()
                dept = str(item.get("department", "")).strip()
                if title and dept in valid:
                    out.append((title, dept))
            return out
        except (anthropic.APIStatusError, anthropic.APIConnectionError) as err:
            last_err = err
            status = getattr(err, "status_code", None)
            if status is not None and 400 <= status < 500 and status != 429:
                raise
        except (json.JSONDecodeError, ValueError) as err:
            last_err = err
        if attempt < max_retries:
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"failed to label batch after {max_retries} attempts: {last_err}")


def append_labels(pairs: list[tuple[str, str]]) -> int:
    """Append new, non-duplicate, non-Unknown labels to data/titles.csv."""
    existing: set[str] = set()
    if DATA_CSV.exists():
        prev = pd.read_csv(DATA_CSV)
        for t in prev.get("title", []):
            existing.add(str(t).lower().strip())

    added = 0
    DATA_CSV.parent.mkdir(parents=True, exist_ok=True)
    write_header = not DATA_CSV.exists()
    with DATA_CSV.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if write_header:
            writer.writerow(["title", "department"])
        for title, dept in pairs:
            if dept == UNKNOWN_LABEL:
                continue  # never a training label
            key = title.lower().strip()
            if key and key not in existing:
                existing.add(key)
                writer.writerow([title, dept])
                added += 1
    return added


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True,
                        help="results.csv from a batch classify run")
    parser.add_argument("--min-confidence", type=float, default=0.75,
                        help="relabel rows below this confidence (default: 0.75)")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--no-train", action="store_true",
                        help="append labels but skip re-running train.py")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set in the environment.")

    titles = load_low_confidence(args.results, args.min_confidence)
    if not titles:
        print("No low-confidence rows to refine. Nothing to do.")
        return
    print(f"Relabeling {len(titles)} low-confidence titles "
          f"(<{args.min_confidence}) in batches of {BATCH_SIZE} ...")

    client = anthropic.Anthropic()
    all_pairs: list[tuple[str, str]] = []
    for start in tqdm(range(0, len(titles), BATCH_SIZE), desc="batches"):
        batch = titles[start:start + BATCH_SIZE]
        all_pairs.extend(label_batch(client, args.model, batch))

    added = append_labels(all_pairs)
    print(f"Appended {added} new labeled examples to {DATA_CSV}")

    if added and not args.no_train:
        print("\nRe-running training ...")
        subprocess.run([sys.executable, str(TRAIN_SCRIPT)], check=True)
    elif not added:
        print("No new labels added; skipping retraining.")


if __name__ == "__main__":
    main()
