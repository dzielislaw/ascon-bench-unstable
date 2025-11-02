# Ascon-Benchmark

**Lightweight Cryptography Evaluation Platform**

This project implements and compares the performance and efficiency of the **ASCON** lightweight cipher —  
the **NIST Lightweight Cryptography** competition winner — against traditional cryptographic standards:  
**AES-GCM**, **SHA-256**, and **HMAC-SHA-256**.

The environment is **modular, reproducible, and self-contained**, allowing controlled performance benchmarking  
in terms of **execution time**, **CPU usage**, and **memory footprint** for authenticated encryption, hashing,  
and message authentication.

---

## ⚙️ Environment Setup (Manual / Local Mode)


**Create a Python environment and install dependencies:**
```
    python -m venv venv
    source venv/bin/activate   # Linux / macOS
    # venv\Scripts\activate     # Windows
    pip install -r requirements.txt
```

## Running Benchmarks Manually
Run individual benchmarks using bench_cli.py

**Example: Run ASCON-128 (AEAD):**:

```
    python bench/bench_cli.py --mode aead --runs 100 --warmup 10 --out results/ascon_aead.csv
```

**Example: Compare ASCON-128 vs AES-GCM:**:
```
    python bench/bench_cli.py --mode aead --algorithm aes-gcm --runs 100 --warmup 10 --out results/aead_ascon_vs_aes.csv
```

**Example: Run ASCON-Hash vs SHA-256:**:
```
    python bench/bench_cli.py --mode hash --algorithm sha256 --runs 200 --warmup 10 --out results/hash_ascon_vs_sha.csv
```


**CLI Parameters**:

| Parameter     | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| `--mode`      | Benchmark mode: `aead`, `hash`, or `mac`                        |
| `--algorithm` | Algorithm to test (`ascon`, `aes-gcm`, `sha256`, `hmac-sha256`) |
| `--runs`      | Number of measured iterations                                   |
| `--warmup`    | Number of warm-up iterations (ignored in measurement)           |
| `--out`       | Output CSV file path for results                                |
| `--sizes`     | Input sizes to benchmark (default: `16 256 4096 65536`)         |



## Run Full Benchmark Suite (Local)
This script automatically:

- Executes ASCON and reference algorithms for all modes,

- Collects results in CSV files,

- Generates plots automatically.

Results will be available in the results/ directory

```
    python -m bench.auto_benchmark
```

## Running in Docker (Automated Environment)

**Build the container**
```
docker build -t ascon-bench .
```

**Run the benchmark**
```
docker run --name ascon_run ascon-bench
```

The container will:

- Launch auto_benchmark.py automatically,

- Perform all AEAD, Hash, and MAC benchmarks (ASCON vs reference algorithms),

- Save CSV + plots in /app/results (which can be copied from the container).

**Retrieve results from Docker**
```
docker cp ascon_run:/app/results ./results
```

## Analiza wyników
Each generated CSV file includes the following fields:

| Column           | Description                              |
| ---------------- | ---------------------------------------- |
| `algorithm`      | Tested algorithm                         |
| `mode`           | Function type (`aead`, `hash`, or `mac`) |
| `input_size`     | Input size in bytes                      |
| `wall_time_mean` | Average elapsed (real-world) time        |
| `cpu_time_mean`  | Average CPU processing time              |
| `mem_peak_mean`  | Average peak memory usage                |
| `runs`           | Number of measured iterations            |


## Recommended Workflow
- Run individual test (local): 	
```
python bench/bench_cli.py --mode hash --algorithm sha256
```

- Run all tests (local):	
```
python auto_benchmark.py
```

- Run all tests (Docker):
```
docker run --name ascon_run ascon-bench
```
