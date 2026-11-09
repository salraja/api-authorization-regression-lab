import argparse
from pathlib import Path

from .reports import write_reports
from .runner import run
from .baseline import compare, load_baseline
import json


def main() -> int:
    parser = argparse.ArgumentParser(description="Check authorization policy against a synthetic local API fixture.")
    parser.add_argument("--fixture", choices=("secure", "vulnerable"), default="secure")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--policy", type=Path, help="Versioned JSON policy; requests remain inside local fixtures")
    parser.add_argument("--baseline", type=Path, help="A prior evidence.json report")
    args = parser.parse_args()
    try:
        previous = load_baseline(args.baseline) if args.baseline else None
        report = run(args.fixture, args.policy)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.error(str(error))
    paths = write_reports(report, args.output_dir)
    if previous:
        comparison = args.output_dir / "comparison.json"
        comparison.write_text(json.dumps(compare(previous, report), indent=2) + "\n", encoding="utf8")
        paths.append(comparison)
    summary = report["summary"]
    print(f"{args.fixture}: {summary['passed']}/{summary['total']} checks passed, {summary['findings']} policy violations")
    for path in paths:
        print(path)
    return 1 if summary["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
