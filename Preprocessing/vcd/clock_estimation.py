import sys
import os
import numpy as np
from vcdvcd import VCDVCD


def determine_chunk_limits(file_path, avg_period):
    """Compute chunk size limits based on file size and clock period."""
    size_mb = os.path.getsize(file_path) / (1024 * 1024)
    if size_mb < 100:
        return None, None, size_mb
    elif size_mb < 1000:
        cycles_limit = 500_000
    elif size_mb < 5000:
        cycles_limit = 1_000_000
    else:
        cycles_limit = 2_000_000

    time_limit = cycles_limit * avg_period
    return cycles_limit, time_limit, size_mb


def find_matching_symbol(vcd, main_clock):
    """Find the internal symbol and reference name for the given clock."""
    normalized_target = main_clock.lower().replace('/', '.')
    for symbol, signal_obj in vcd.data.items():
        if not hasattr(signal_obj, "references"):
            continue
        for ref in signal_obj.references:
            normalized_ref = ref.lower().replace('/', '.')
            if normalized_ref.endswith(normalized_target):
                return symbol, ref
    return None, None


def estimate_first_chunk_cycles(vcd_path, main_clock):
    """Estimate clock cycles and decide chunk boundaries."""
    print(f"\nAnalyzing clock: {main_clock}")
    vcd = VCDVCD(vcd_path, store_tvs=True)

    symbol, ref_name = find_matching_symbol(vcd, main_clock)
    if not symbol:
        print(f"Clock '{main_clock}' not found in VCD.")
        print("Available signals (first 10):")
        for k in list(vcd.data.keys())[:10]:
            print(" ", k)
        return None

    print(f"Matched symbol: {symbol}  ->  {ref_name}")

    tv = getattr(vcd.data[symbol], "tv", [])
    tv_filtered = [(t, v) for t, v in tv if v in ("0", "1")]

    if not tv_filtered:
        print(f"No valid binary transitions found for {ref_name}.")
        return None

    times, vals = zip(*tv_filtered)
    times = np.array(times, dtype=float)
    vals = np.array(vals)

    rising_edges = times[1:][(np.array(vals[:-1]) == '0') & (np.array(vals[1:]) == '1')]
    if len(rising_edges) < 3:
        print("Not enough edges for clock estimation.")
        return None

    avg_period = np.mean(np.diff(rising_edges))
    cycles_limit, time_limit, size_mb = determine_chunk_limits(vcd_path, avg_period)

    if cycles_limit is None:
        total_cycles = len(rising_edges)
        last_time = rising_edges[-1]
        mode = "full"
    else:
        rising_edges_chunk = rising_edges[rising_edges <= time_limit]
        total_cycles = len(rising_edges_chunk)
        last_time = rising_edges_chunk[-1] if len(rising_edges_chunk) else 0
        mode = "limited"

    print(f"\nFile Size (MB): {size_mb:.2f}")
    print(f"Clock Period   : {avg_period:.3f}")
    print(f"Cycles Analyzed: {total_cycles}")
    print(f"Chunk Mode     : {mode}")
    print(f"Last Time Unit : {last_time:.2f}")

    return {
        "file_size_mb": size_mb,
        "avg_period": avg_period,
        "cycles_analyzed": total_cycles,
        "last_time_analyzed": last_time,
        "chunk_mode": mode
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python clock_estimation.py <vcd_file> <main_clock>")
        sys.exit(1)

    vcd_file = sys.argv[1]
    main_clock = sys.argv[2]

    if not os.path.exists(vcd_file):
        print(f"File not found: {vcd_file}")
        sys.exit(1)

    estimate_first_chunk_cycles(vcd_file, main_clock)


if __name__ == "__main__":
    main()
