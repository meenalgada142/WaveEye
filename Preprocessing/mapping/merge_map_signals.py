#!/usr/bin/env python3
import csv
import sys
import glob
import os

print("=== MERGE SCRIPT DEBUG MODE ===")

def load_csv(path):
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    return rows[0], rows[1], rows[2:]

def pad(row, length):
    if len(row) < length:
        return row + [""] * (length - len(row))
    return row[:length]

def merge_two_tables(class1, head1, data1, class2, head2, data2):
    keep_idx2 = [j for j, n in enumerate(head2) if n not in head1]

    merged_class = class1 + [class2[j] for j in keep_idx2]
    merged_head  = head1  + [head2[j] for j in keep_idx2]

    len1, len2 = len(head1), len(head2)
    max_len = max(len(data1), len(data2))

    merged_data = []
    for i in range(max_len):
        r1 = pad(data1[i], len1) if i < len(data1) else [""] * len1
        r2 = pad(data2[i], len2) if i < len(data2) else [""] * len2
        merged_data.append(r1 + [r2[j] for j in keep_idx2])

    return merged_class, merged_head, merged_data

def merge_all(files, out_file):
    print("Merging", len(files), "files into:", out_file)
    print("FILES:")
    for f in files:
        print(" -", f)

    class_row, header_row, data_rows = load_csv(files[0])

    for f in files[1:]:
        print("Merging:", f)
        c2, h2, d2 = load_csv(f)
        class_row, header_row, data_rows = merge_two_tables(
            class_row, header_row, data_rows, c2, h2, d2
        )

    with open(out_file, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(class_row)
        w.writerow(header_row)
        for r in data_rows:
            w.writerow(r)

    print("WROTE MERGED CSV TO:", out_file)

if __name__ == "__main__":
    print("Arguments received:", sys.argv)

    if len(sys.argv) != 2:
        print("ERROR: Expected OUTPUT_DIR argument")
        sys.exit(1)

    output_dir = os.path.abspath(sys.argv[1])

    print("OUTPUT_DIR resolved to:", output_dir)

    # Try new naming pattern first (*_mapped.csv)
    mapped_files = sorted(glob.glob(os.path.join(output_dir, "*_mapped.csv")))
    
    # If no files with new naming, try old naming (*_mapped_values.csv)
    if not mapped_files:
        print("No *_mapped.csv files found, trying *_mapped.csv...")
        mapped_files = sorted(glob.glob(os.path.join(output_dir, "*_mapped.csv")))

    print("Mapped files found:", mapped_files)

    if len(mapped_files) < 2:
        print("ERROR: Less than 2 mapped files found.")
        print("\nDEBUG: Listing all CSV files in output directory:")
        all_csvs = sorted(glob.glob(os.path.join(output_dir, "*.csv")))
        for csv_file in all_csvs:
            print(f"  - {os.path.basename(csv_file)}")
        sys.exit(1)

    out_path = os.path.join(output_dir, "all_mapped_values.csv")
    merge_all(mapped_files, out_path)