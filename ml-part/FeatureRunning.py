import pandas as pd
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from FeatureExtraction import featureExtraction, feature_names

# ============================================================
# LOAD DATASET
# ============================================================
df = pd.read_csv("data/5.PhishLegi.csv")

if "url" not in df.columns:
    df.rename(columns={df.columns[0]: "url"}, inplace=True)
if "label" not in df.columns:
    raise ValueError("Dataset must contain a 'label' column!")

TOTAL = len(df)
print(f"TOTAL URLs TO PROCESS: {TOTAL}")
print("=" * 80)

# ============================================================
# PARALLEL FEATURE EXTRACTION WITH NICE PROGRESS
# ============================================================
features_data = []
failed = 0
start_time = time.time()

MAX_WORKERS = 100
PRINT_EVERY = 100  # Progress display frequency

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {
        executor.submit(featureExtraction, row["url"], row["label"]): idx
        for idx, row in df.iterrows()
    }

    for completed, future in enumerate(as_completed(futures), start=1):
        try:
            result = future.result()
            if result:
                features_data.append(result)
            else:
                failed += 1
        except:
            failed += 1

        if completed % PRINT_EVERY == 0 or completed == TOTAL:
            elapsed_min = (time.time() - start_time) / 60
            rate = completed / elapsed_min if elapsed_min > 0 else 0
            remaining_min = (TOTAL - completed) / rate if rate > 0 else 0
            percent = (completed / TOTAL) * 100

            print(
                f"✓ {completed}/{TOTAL} ({percent:.1f}%) | "
                f"Success: {len(features_data)} | Failed: {failed} | "
                f"Time: {elapsed_min:.1f}min | ETA: {remaining_min:.1f}min"
            )

# ============================================================
# SAVE RESULTS
# ============================================================
output_file = "data/6.FinalDataset.csv"
columns = feature_names + ["label"]
feature_df = pd.DataFrame(features_data, columns=columns)
feature_df.to_csv(output_file, index=False)

print("\n" + "=" * 80)
print("✔ Feature extraction completed!")
print(f"Saved: {output_file}")
print(f"Failed URLs: {failed}")
print("=" * 80)
