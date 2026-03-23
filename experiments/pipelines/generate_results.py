#!/usr/bin/env python3
"""
Results Generator for QASecClaw Benchmark Evaluation
=====================================================
Reads scored JSON results from multiple tools and generates:
  1. Markdown comparison tables
  2. LaTeX comparison tables
  3. Visualization plots (bar chart, radar chart)

Usage:
    python generate_results.py \
        --results results/qasecclaw.json results/semgrep.json \
        --output-dir research/figures/
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

CWE_NAMES: dict[int, str] = {
    78: "Command Injection",
    89: "SQL Injection",
    79: "XSS",
    22: "Path Traversal",
    327: "Weak Crypto",
    328: "Weak Hashing",
    330: "Weak Random",
    614: "Insecure Cookie",
    501: "Trust Boundary",
    90: "LDAP Injection",
    643: "XPath Injection",
}


def load_result(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def generate_markdown_table(results: list[dict], output_path: Path) -> None:
    """Generate a markdown comparison table."""
    lines = [
        "# OWASP Benchmark — Tool Comparison",
        "",
        "## Overall Metrics",
        "",
        "| Tool | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Youden's J |",
        "|------|----|----|----|----|-----------|--------|----|-----|------------|",
    ]

    for r in results:
        o = r["overall"]
        lines.append(
            f"| **{r['tool']}** "
            f"| {o['TP']} | {o['FP']} | {o['TN']} | {o['FN']} "
            f"| {o['Precision']:.4f} | {o['Recall']:.4f} | {o['F1']:.4f} "
            f"| {o['FPR']:.4f} | {o['Youdens_J']:.4f} |"
        )

    lines.append("")

    # Per-CWE F1 comparison
    all_cwes = sorted(set().union(*(r.get("per_cwe", {}).keys() for r in results)))
    if all_cwes:
        lines.append("## Per-CWE F1 Score Comparison")
        lines.append("")
        header_cols = " | ".join(f"{r['tool']} F1" for r in results)
        lines.append(f"| CWE | Category | {header_cols} |")
        sep_cols = " | ".join("--------" for _ in results)
        lines.append(f"|-----|----------|{sep_cols}|")

        for cwe_str in all_cwes:
            cwe_int = int(cwe_str)
            cat_name = CWE_NAMES.get(cwe_int, f"CWE-{cwe_int}")
            cells = []
            for r in results:
                cwe_data = r.get("per_cwe", {}).get(cwe_str)
                cells.append(f"{cwe_data['F1']:.4f}" if cwe_data else "N/A")
            lines.append(f"| CWE-{cwe_str} | {cat_name} | " + " | ".join(cells) + " |")
        lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info("Markdown table saved to %s", output_path)


def generate_latex_table(results: list[dict], output_path: Path) -> None:
    """Generate a LaTeX comparison table for paper inclusion."""
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{OWASP Benchmark Evaluation Results}",
        r"\label{tab:benchmark-results}",
        r"\begin{tabular}{lrrrrcccc}",
        r"\toprule",
        r"Tool & TP & FP & TN & FN & Precision & Recall & F1 & FPR \\",
        r"\midrule",
    ]

    for r in results:
        o = r["overall"]
        tool = r["tool"].replace("_", r"\_")
        lines.append(
            f"{tool} & {o['TP']} & {o['FP']} & {o['TN']} & {o['FN']} "
            f"& {o['Precision']:.3f} & {o['Recall']:.3f} & {o['F1']:.3f} & {o['FPR']:.3f} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info("LaTeX table saved to %s", output_path)


def generate_plots(results: list[dict], output_dir: Path) -> None:
    """Generate comparison plots (bar chart + radar chart)."""
    try:
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        log.warning("matplotlib/numpy not available — skipping plot generation.")
        log.warning("Install with: pip install matplotlib numpy")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Bar chart: Precision / Recall / F1 comparison ──
    tools = [r["tool"] for r in results]
    precision = [r["overall"]["Precision"] for r in results]
    recall = [r["overall"]["Recall"] for r in results]
    f1 = [r["overall"]["F1"] for r in results]

    x = np.arange(len(tools))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width, precision, width, label="Precision", color="#2196F3")
    bars2 = ax.bar(x, recall, width, label="Recall", color="#4CAF50")
    bars3 = ax.bar(x + width, f1, width, label="F1-Score", color="#FF9800")

    ax.set_xlabel("Tool", fontsize=12)
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("OWASP Benchmark — Tool Comparison", fontsize=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(tools, fontsize=11)
    ax.legend(fontsize=11)
    ax.set_ylim(0, 1.1)
    ax.grid(axis="y", alpha=0.3)

    # Add value labels on bars
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.2f}",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    bar_path = output_dir / "benchmark_comparison_bar.png"
    plt.savefig(bar_path, dpi=150, bbox_inches="tight")
    plt.close()
    log.info("Bar chart saved to %s", bar_path)

    # ── Radar chart: Per-CWE F1 scores ──
    all_cwes = sorted(set().union(*(r.get("per_cwe", {}).keys() for r in results)))
    if len(all_cwes) >= 3:
        categories = [CWE_NAMES.get(int(c), f"CWE-{c}") for c in all_cwes]
        num_cats = len(categories)
        angles = np.linspace(0, 2 * np.pi, num_cats, endpoint=False).tolist()
        angles += angles[:1]  # Close the polygon

        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
        colors = ["#2196F3", "#4CAF50", "#FF9800", "#E91E63", "#9C27B0"]

        for i, r in enumerate(results):
            values = []
            for cwe_str in all_cwes:
                cwe_data = r.get("per_cwe", {}).get(cwe_str)
                values.append(cwe_data["F1"] if cwe_data else 0.0)
            values += values[:1]  # Close
            color = colors[i % len(colors)]
            ax.plot(angles, values, "o-", linewidth=2, label=r["tool"], color=color)
            ax.fill(angles, values, alpha=0.1, color=color)

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, fontsize=9)
        ax.set_ylim(0, 1.0)
        ax.set_title("Per-CWE F1 Score Comparison", fontsize=14, fontweight="bold", pad=20)
        ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1))

        plt.tight_layout()
        radar_path = output_dir / "benchmark_cwe_radar.png"
        plt.savefig(radar_path, dpi=150, bbox_inches="tight")
        plt.close()
        log.info("Radar chart saved to %s", radar_path)

    # ── Confusion matrix heatmap per tool ──
    for r in results:
        fig, ax = plt.subplots(figsize=(5, 4))
        o = r["overall"]
        matrix = np.array([[o["TP"], o["FN"]], [o["FP"], o["TN"]]])
        im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto")

        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Predicted Pos", "Predicted Neg"])
        ax.set_yticklabels(["Actual Pos", "Actual Neg"])
        ax.set_title(f"Confusion Matrix — {r['tool']}", fontweight="bold")

        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(matrix[i, j]),
                        ha="center", va="center", fontsize=16, fontweight="bold",
                        color="white" if matrix[i, j] > matrix.max() * 0.6 else "black")

        plt.colorbar(im)
        plt.tight_layout()
        cm_path = output_dir / f"confusion_matrix_{r['tool']}.png"
        plt.savefig(cm_path, dpi=150, bbox_inches="tight")
        plt.close()
        log.info("Confusion matrix saved to %s", cm_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate comparison tables and plots from benchmark results."
    )
    parser.add_argument(
        "--results", type=Path, nargs="+", required=True,
        help="Paths to JSON result files from score_benchmark.py",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("research/figures"),
        help="Output directory for generated files",
    )

    args = parser.parse_args(argv)

    results = [load_result(p) for p in args.results]
    log.info("Loaded %d tool results", len(results))

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    generate_markdown_table(results, output_dir / "comparison_table.md")
    generate_latex_table(results, output_dir / "comparison_table.tex")
    generate_plots(results, output_dir)

    log.info("All results generated in %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
