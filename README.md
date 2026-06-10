# multi-stage-iot-ids
This project is about building a two-stage Intrusion Detection System for IoT network traffic using the CIC IoT-DIAD 2024 dataset.


Samples the packet-level dataset randomly:

```bash
python scripts/generate_random_packet_sample.py \
  --data-dir data/raw \
  --output-path data/samples/test_packet_sample.csv \
  --benign-rows 1000 \
  --attack-min 100 \
  --attack-max 200 \
  --min-attack-each 10 \
  --seed 42
```
