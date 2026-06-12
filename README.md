# multi-stage-iot-ids
This project is about building a two-stage Intrusion Detection System for IoT network traffic using the CIC IoT-DIAD 2024 dataset.

## 📂 Dataset
[![Kaggle Dataset](https://img.shields.io/badge/Kaggle-Dataset-blue?logo=kaggle)](https://www.kaggle.com/datasets/yuanmingwangumr/multi-stage-iot-ids)

### Folder Structure:
```
├── data
│   ├── raw
│   │   └── BenignTraffic.csv
│   │   └── ...
│   ├── samples
```


Samples the packet-level dataset randomly:

Test running
```bash
python scripts/generate_random_packet_sample.py \
  --data-dir data/raw \
  --output-path data/samples/test_packet_sample.csv \
  --benign-rows 1000 \
  --attack-min 100 \
  --attack-max 200 \
  --min-attack-each 10 \
  --seed 1
```

```bash
python scripts/generate_random_packet_sample.py \                                                                           
  --data-dir data/raw \
  --output-path data/samples/packet_sample_seed1.csv \
  --seed 1
```