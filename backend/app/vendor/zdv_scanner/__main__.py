import argparse
import sys
import threading

from .engine import ScanEngine
from .fuzzer import Fuzzer
from .report import write_report
from .scoring import prioritize
from .target import Target


def scan_main(argv=None):
    parser = argparse.ArgumentParser(prog="zscan scan")
    parser.add_argument("url", help="target URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--output", help="write report to this file")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    target = Target.from_url(args.url)
    result = ScanEngine().scan(target)
    ranked = prioritize([f.to_dict() for f in result.findings])
    for finding in ranked:
        print(f"[{finding['severity'].upper():8}] {finding['score']:>4} {finding['title']} ({finding['plugin']})")
    if result.errors:
        print("plugin errors:")
        for error in result.errors:
            print(f"  {error}")
    output = write_report({"target": result.target, "findings": ranked, "errors": result.errors, "elapsed": result.elapsed}, fmt=args.format, path=args.output)
    print(f"report written to {args.output}" if args.output else output)


def fuzz_main(argv=None):
    parser = argparse.ArgumentParser(prog="zscan fuzz")
    parser.add_argument("url", help="target URL (localhost only)")
    parser.add_argument("--iterations", type=int, default=50)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    target = Target.from_url(args.url)
    result = Fuzzer().fuzz(target, corpus=["/"], iterations=args.iterations)
    print(f"sent {result.requests} requests, {len(result.anomalies)} anomalies")
    for anomaly in result.anomalies:
        print(f"  [{anomaly.severity}] {anomaly.title}: {anomaly.evidence}")


def demo_main(argv=None):
    from .demo import main as demo

    demo()


def main():
    commands = {"scan": scan_main, "fuzz": fuzz_main, "demo": demo_main}
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print("usage: python -m scanner <command> [options]")
        print("commands: " + ", ".join(commands))
        sys.exit(2)
    commands[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()
