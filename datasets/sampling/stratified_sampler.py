from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pandas as pd
from sklearn.model_selection import train_test_split


DEFAULT_SAMPLE_RATIO: Final[float] = 0.05
DEFAULT_SEED: Final[int] = 1337


@dataclass(frozen=True)
class StratifiedSampler:
    """
    Generic stratified sampler for tabular datasets.
    """

    input_path: Path
    stratify_column: str
    sample_ratio: float = DEFAULT_SAMPLE_RATIO
    seed: int = DEFAULT_SEED

    def load(self) -> pd.DataFrame:
        if self.input_path.suffix.lower() in {".parquet", ".pq"}:
            df = pd.read_parquet(self.input_path)
        else:
            df = pd.read_csv(self.input_path)
        if self.stratify_column not in df.columns:
            raise KeyError(
                f"Column '{self.stratify_column}' not found in dataset "
                f"({self.input_path}); available columns: {list(df.columns)}"
            )
        return df

    def sample(self) -> pd.DataFrame:
        df = self.load()
        y = df[self.stratify_column]

        logging.info("Full dataset size: %d rows", len(df))
        self._log_distribution("before", y)

        sampled_df = self._stratified_sample(df, y)

        logging.info("Sampled dataset size: %d rows", len(sampled_df))
        self._log_distribution("after", sampled_df[self.stratify_column])

        return sampled_df

    def _stratified_sample(self, df: pd.DataFrame, y: pd.Series) -> pd.DataFrame:
        if not (0.0 < self.sample_ratio < 1.0):
            raise ValueError(f"sample_ratio must be in (0, 1), got {self.sample_ratio}")

        # train_test_split with test_size = sample_ratio to get the sample
        _, df_sample = train_test_split(
            df,
            test_size=self.sample_ratio,
            random_state=self.seed,
            stratify=y,
        )
        return df_sample

    def _log_distribution(self, label: str, y: pd.Series) -> None:
        counts = y.value_counts().sort_index()
        probs = y.value_counts(normalize=True).sort_index()

        logging.info("Class distribution %s sampling (column=%s):", label, self.stratify_column)
        for cls, count in counts.items():
            logging.info("  %s: count=%d, frac=%.4f", cls, count, probs.loc[cls])


def _sample_owasp_benchmark(
    input_path: Path,
    output_path: Path,
    sample_ratio: float,
    seed: int,
    stratify_column: str | None,
) -> None:
    # Typical OWASP Benchmark label column (placeholder; adjust to actual schema as needed)
    column = stratify_column or "CWE_category"
    sampler = StratifiedSampler(
        input_path=input_path,
        stratify_column=column,
        sample_ratio=sample_ratio,
        seed=seed,
    )
    sampled = sampler.sample()
    _write_sample(sampled, output_path)


def _sample_defects4j(
    input_path: Path,
    output_path: Path,
    sample_ratio: float,
    seed: int,
    stratify_column: str | None,
) -> None:
    # Placeholder: many Defects4J tables use 'bug_id' or a binary fault label.
    column = stratify_column or "bug_id"
    sampler = StratifiedSampler(
        input_path=input_path,
        stratify_column=column,
        sample_ratio=sample_ratio,
        seed=seed,
    )
    sampled = sampler.sample()
    _write_sample(sampled, output_path)


def _sample_loghub(
    input_path: Path,
    output_path: Path,
    sample_ratio: float,
    seed: int,
    stratify_column: str | None,
) -> None:
    # Typical LogHub label column name (placeholder).
    column = stratify_column or "anomaly_type"
    sampler = StratifiedSampler(
        input_path=input_path,
        stratify_column=column,
        sample_ratio=sample_ratio,
        seed=seed,
    )
    sampled = sampler.sample()
    _write_sample(sampled, output_path)


def _write_sample(df: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.suffix.lower() in {".parquet", ".pq"}:
        df.to_parquet(output_path, index=False)
    else:
        df.to_csv(output_path, index=False)
    logging.info("Wrote sampled dataset to %s", output_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "QASecClaw stratified dataset sampler (default: 5%% of data). "
            "Preserves class distribution for research evaluation."
        )
    )

    parser.add_argument(
        "--dataset",
        choices=["owasp", "defects4j", "loghub", "custom"],
        required=True,
        help="Dataset kind (controls default stratify column).",
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input dataset file (CSV or Parquet).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output sampled dataset file (CSV or Parquet).",
    )
    parser.add_argument(
        "--stratify-column",
        type=str,
        default=None,
        help="Column to stratify on (overrides dataset default).",
    )
    parser.add_argument(
        "--sample-ratio",
        type=float,
        default=DEFAULT_SAMPLE_RATIO,
        help="Sampling ratio in (0,1); default 0.05 (5%%).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed for reproducibility (default: 1337).",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (default: INFO).",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    logging.info(
        "Starting stratified sampling: dataset=%s, input=%s, output=%s, ratio=%.4f, seed=%d",
        args.dataset,
        args.input,
        args.output,
        args.sample_ratio,
        args.seed,
    )

    if args.dataset == "owasp":
        _sample_owasp_benchmark(
            input_path=args.input,
            output_path=args.output,
            sample_ratio=args.sample_ratio,
            seed=args.seed,
            stratify_column=args.stratify_column,
        )
    elif args.dataset == "defects4j":
        _sample_defects4j(
            input_path=args.input,
            output_path=args.output,
            sample_ratio=args.sample_ratio,
            seed=args.seed,
            stratify_column=args.stratify_column,
        )
    elif args.dataset == "loghub":
        _sample_loghub(
            input_path=args.input,
            output_path=args.output,
            sample_ratio=args.sample_ratio,
            seed=args.seed,
            stratify_column=args.stratify_column,
        )
    else:
        # Fully custom dataset: user MUST provide stratify-column.
        if args.stratify_column is None:
            raise SystemExit(
                "For dataset=custom you must provide --stratify-column to define the class label."
            )
        sampler = StratifiedSampler(
            input_path=args.input,
            stratify_column=args.stratify_column,
            sample_ratio=args.sample_ratio,
            seed=args.seed,
        )
        sampled = sampler.sample()
        _write_sample(sampled, args.output)

    logging.info("Stratified sampling completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

