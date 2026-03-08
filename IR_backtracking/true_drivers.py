import csv
import os
import sys

_PROD_VERBOSE: bool = os.environ.get("WAVEEYE_VERBOSE", "0") == "1"

def is_blank_row(row):
    return all(cell.strip() == "" for cell in row)

def is_separator_row(row):
    """Check if row is a '--- NEXT DRIVER ---' separator"""
    return row[0].strip() == "--- NEXT DRIVER ---"

def process_csv(input_path, output_path):
    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    header = rows[0]
    data_rows = rows[1:]

    # Split into signal blocks (separated by blank rows)
    blocks = []
    block = []

    for row in data_rows:
        if is_blank_row(row):
            if block:
                blocks.append(block)
                block = []
        else:
            block.append(row)

    if block:
        blocks.append(block)

    output = [header]

    # Process each signal block
    for block in blocks:
        if not block:
            continue
            
        # Get the main signal name from the first row
        main_signal = block[0][0].strip()
        
        # Filter rows to keep only:
        # 1. Rows where signal == main_signal AND depth == 1 (top-level drivers)
        # 2. Separator rows (--- NEXT DRIVER ---)
        filtered = []
        for row in block:
            if is_separator_row(row):
                # Keep separator rows
                filtered.append(row)
            elif row[0].strip() == main_signal:
                # Check depth column (index 2)
                try:
                    depth = row[2].strip()
                    if depth == "1" or depth == "":
                        # Keep depth 1 rows (true drivers for this signal)
                        filtered.append(row)
                except (IndexError, ValueError):
                    # If depth is missing or invalid, skip
                    pass
        
        # Add filtered rows to output
        output.extend(filtered)
        # Add blank separator row after each signal block
        output.append([""] * len(header))

    # Write output
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(output)

    if _PROD_VERBOSE:
        print(f"Filtered CSV saved to: {output_path}")
        print(f"Processed {len(blocks)} signal block(s)")

# -------- Import-friendly wrapper --------
def extract_true_drivers(input_csv, output_csv):
    process_csv(input_csv, output_csv)

# -------- CLI support --------
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python true_drivers.py input.csv output.csv")
        sys.exit(1)

    process_csv(sys.argv[1], sys.argv[2])