#!/usr/bin/env python3
import argparse
import os


def main():
    parser = argparse.ArgumentParser(description="Run the DefectAware observability dashboard.")
    parser.add_argument("--db", default="data/observability/traces.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    os.environ["DEFECTAWARE_TRACE_DB"] = os.path.abspath(args.db)
    import uvicorn

    uvicorn.run("observability.dashboard:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
