import argparse


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--benign-rows", type=int, default=200_000)
    parser.add_argument("--attack-min", type=int, default=4_000)
    parser.add_argument("--attack-max", type=int, default=6_200)
    parser.add_argument("--min-per-attack", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--chunksize", type=int, default=50_000)

    