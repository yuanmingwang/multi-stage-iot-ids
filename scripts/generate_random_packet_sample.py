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
    parser.add_argument("--benign-rows", type=int, default=200000)
    parser.add_argument("--attack-min", type=int, default=4000)
    parser.add_argument("--attack-max", type=int, default=6200)
    parser.add_argument("--min-attack-each", type=int, default=200)
    parser.add_argument("--seed", type=int, default=None)

    args = parser.parse_args()

    generate_random_packet_dataset(
        data_dir=args.data_dir,
        output_path=args.output_path,
        benign_rows=args.benign_rows,
        attack_min_rows=args.attack_min,
        attack_max_rows=args.attack_max,
        min_attack_each=args.min_attack_each,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
    