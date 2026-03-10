from __future__ import annotations

import argparse
import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SamplingPlan:
    dataset: str
    sample_ratio: float
    seed: int
    # Future: strata_keys, per-stratum quotas, etc.


def _clamp_ratio(r: float) -> float:
    if not (0.0 < r <= 1.0):
        raise ValueError(f"sample_ratio must be in (0, 1], got {r}")
    return r


def sample_indices(total: int, ratio: float, seed: int) -> list[int]:
    ratio = _clamp_ratio(ratio)
    if total < 0:
        raise ValueError(f"total must be >= 0, got {total}")
    if total == 0:
        return []
    k = max(1, int(math.floor(total * ratio)))
    rng = random.Random(seed)
    return sorted(rng.sample(range(total), k=min(k, total)))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="QASecClaw dataset sampler (default: 5%%). "
        "Placeholder for future stratified sampling."
    )
    p.add_argument("--dataset", required=True, help="Dataset identifier (e.g., loghub-hdfs)")
    p.add_argument("--total", type=int, required=True, help="Total number of items available")
    p.add_argument("--sample-ratio", type=float, default=0.05, help="Sampling ratio (default: 0.05)")
    p.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducibility")
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional output path; writes JSON with indices and metadata",
    )
    args = p.parse_args(argv)

    plan = SamplingPlan(dataset=args.dataset, sample_ratio=float(args.sample_ratio), seed=int(args.seed))
    indices = sample_indices(total=int(args.total), ratio=plan.sample_ratio, seed=plan.seed)

    payload: dict[str, Any] = {
        "dataset": plan.dataset,
        "sample_ratio": plan.sample_ratio,
        "seed": plan.seed,
        "total": int(args.total),
        "sampled": len(indices),
        "indices": indices,
    }

    if args.out is None:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

