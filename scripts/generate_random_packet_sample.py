import argparse

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from src.data.sampling import generate_random_packet_dataset

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--output-path", default="data/samples/packet_sample.csv")
    parser.add_argument("--seed", type=int, default=None)

    args = parser.parse_args()

    generate_random_packet_dataset(
        data_dir=args.data_dir,
        output_path=args.output_path,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
    