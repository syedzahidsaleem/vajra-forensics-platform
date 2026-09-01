"""
Feature Extractor for File-Type Classification (§33).

Extracts the 280-dimensional feature vector:
1. [0..255]   Byte frequency histogram (256 dimensions, normalized 0.0..1.0)
2. [256..271] Chunked Shannon entropy profile (16 uniform chunks across data, 0.0..8.0)
3. [272..277] 2-gram transition statistical summary (6 dimensions):
              - Sparsity (fraction of 65,536 pairs with 0 count)
              - Top-10 concentration (sum of top 10 bigrams / total bigrams)
              - Transition entropy (Shannon entropy over bigram distribution)
              - Mean probability over active transitions
              - Variance of bigram distribution
              - Distinct bigram ratio (distinct / 65,536)
4. [278]      Longest printable ASCII run (normalized log ratio)
5. [279]      Chi-square statistic against uniform distribution (normalized log10)
"""

import math
import numpy as np

NUM_FEATURES = 280
FEATURE_NAMES = [f"byte_freq_{i:02x}" for i in range(256)] + \
                [f"entropy_chunk_{i}" for i in range(16)] + \
                [
                    "bigram_sparsity",
                    "bigram_top10_concentration",
                    "bigram_transition_entropy",
                    "bigram_mean_prob",
                    "bigram_variance",
                    "bigram_distinct_ratio",
                    "longest_ascii_run_ratio",
                    "chi_square_uniformity",
                ]


def calculate_shannon_entropy(chunk: bytes) -> float:
    """Computes Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not chunk:
        return 0.0
    counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
    total = len(chunk)
    probs = counts[counts > 0] / total
    return float(-np.sum(probs * np.log2(probs)))


def extract_features(data: bytes) -> np.ndarray:
    """Extracts 280-dim feature vector from raw byte slice."""
    features = np.zeros(NUM_FEATURES, dtype=np.float32)
    n_bytes = len(data)
    if n_bytes == 0:
        return features

    byte_arr = np.frombuffer(data, dtype=np.uint8)

    # 1. Byte Histogram (256-dim)
    counts = np.bincount(byte_arr, minlength=256)
    features[0:256] = counts / float(n_bytes)

    # 2. Chunked Shannon Entropy Profile (16-dim)
    num_chunks = 16
    chunk_size = max(1, n_bytes // num_chunks)
    for i in range(num_chunks):
        start = i * chunk_size
        end = n_bytes if i == num_chunks - 1 else min(n_bytes, (i + 1) * chunk_size)
        if start < n_bytes:
            chunk = data[start:end]
            features[256 + i] = calculate_shannon_entropy(chunk)
        else:
            features[256 + i] = 0.0

    # 3. 2-gram transition features (6-dim)
    if n_bytes > 1:
        # Build bigram indices
        b1 = byte_arr[:-1].astype(np.int64)
        b2 = byte_arr[1:].astype(np.int64)
        bigram_indices = (b1 << 8) | b2
        bigram_counts = np.bincount(bigram_indices, minlength=65536)
        active_counts = bigram_counts[bigram_counts > 0]
        n_bigrams = n_bytes - 1
        num_distinct = len(active_counts)

        # Sparsity
        features[272] = float(65536 - num_distinct) / 65536.0

        # Top-10 concentration
        top10_sum = float(np.sum(np.sort(active_counts)[-10:]))
        features[273] = top10_sum / float(n_bigrams)

        # Transition entropy
        probs = active_counts / float(n_bigrams)
        features[274] = float(-np.sum(probs * np.log2(probs)))

        # Mean prob over active
        features[275] = float(1.0 / num_distinct) if num_distinct > 0 else 0.0

        # Variance of probabilities
        features[276] = float(np.var(probs))

        # Distinct ratio
        features[277] = float(num_distinct) / 65536.0
    else:
        features[272] = 1.0

    # 4. Longest Printable ASCII Run (1-dim)
    max_run = 0
    current_run = 0
    for b in data:
        if (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D):
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0

    log_run = math.log2(max_run + 1.0)
    log_total = math.log2(n_bytes + 1.0)
    features[278] = float(log_run / log_total) if log_total > 0 else 0.0

    # 5. Chi-square statistic against uniform distribution (1-dim)
    expected = float(n_bytes) / 256.0
    if expected > 0:
        chi2 = float(np.sum(((counts - expected) ** 2) / expected))
        # Log10 normalization
        norm_chi2 = math.log10(chi2 + 1.0) / 10.0
        features[279] = float(min(1.0, max(0.0, norm_chi2)))
    else:
        features[279] = 0.0

    return features
