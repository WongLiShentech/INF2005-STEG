"""Steganalysis: measuring a stego object rather than listening to it.

Audio hides a payload too well to hear. A six-second cover with a 700-byte
payload has under one per cent of its samples altered, each by a few parts in
65,536, and the result is indistinguishable by ear at any embedding depth.
Playing the two files side by side therefore proves nothing either way, which
is exactly the problem this module exists to solve: it turns the difference
into something that can be looked at.

Four measurements, in increasing order of how much they assume:

  waveform    the signal itself, cover and stego. They overlap exactly. That
              is the finding, not a failure of the chart.
  difference  cover minus stego. Flat zero everywhere except where the
              payload sits. Requires the original, so it is a teaching view
              rather than an attack.
  lsb_plane   the value of the low bits over time. Natural media carries
              structure there; an encrypted payload does not.
  chi_square  the Westfeld-Pfitzmann detector, run over a sliding window.
              Needs neither the original nor the passphrase, so this is the
              only one of the four an outside analyst could actually run.

Everything is reduced to a few hundred points before it leaves this module.
A chart cannot render half a million samples and a browser should not be
asked to hold them.
"""

import math

import numpy as np

POINTS = 560
WINDOWS = 48

# A chi-square bin needs enough observations for the statistic to mean
# anything; below this the sparse tail of the histogram dominates the result.
MIN_BIN_COUNT = 8
MIN_BINS = 5


def _signed_view(carrier, kind):
    """Audio amplitudes are signed on disk even though embedding treats them
    as unsigned bit patterns. A waveform has to be drawn from the real
    amplitudes or it is nonsense: silence would appear as a full-scale block
    and the signal would be cut in half at zero."""
    if kind == "audio" and carrier.dtype.itemsize > 1:
        return carrier.view(np.dtype(f"<i{carrier.dtype.itemsize}"))
    if kind == "audio":
        # 8-bit PCM is the one unsigned audio format: silence is 128, not 0.
        # Centring it is what puts the waveform on its axis.
        return carrier.astype(np.int16) - 128
    return carrier


def _buckets(length, points):
    """Split a carrier into contiguous, near-equal buckets."""
    points = max(1, min(points, length))
    edges = np.linspace(0, length, points + 1, dtype=np.int64)
    return edges


def _envelope(values, edges):
    """Per-bucket minimum and maximum: the shape a waveform display draws.

    Averaging would flatten the signal towards zero and hide exactly the
    peaks that make a waveform readable, so the extremes are kept instead.
    """
    lo, hi = [], []
    for start, end in zip(edges[:-1], edges[1:]):
        window = values[start:end]
        if window.size == 0:
            lo.append(0.0)
            hi.append(0.0)
            continue
        lo.append(float(window.min()))
        hi.append(float(window.max()))
    return lo, hi


def _bucket_mean(values, edges):
    return [
        float(values[start:end].mean()) if end > start else 0.0
        for start, end in zip(edges[:-1], edges[1:])
    ]


def _bucket_max(values, edges):
    return [
        float(values[start:end].max()) if end > start else 0.0
        for start, end in zip(edges[:-1], edges[1:])
    ]


def waveform(carrier, kind, points=POINTS):
    """The signal, reduced to a drawable envelope and scaled to -1..1."""
    values = _signed_view(carrier, kind).astype(np.float64)
    peak = float(2 ** (carrier.dtype.itemsize * 8 - 1)) if kind == "audio" else 255.0
    edges = _buckets(len(values), points)
    lo, hi = _envelope(values, edges)
    return {
        "low": [round(v / peak, 5) for v in lo],
        "high": [round(v / peak, 5) for v in hi],
        "peak": peak,
    }


def difference(cover, stego, points=POINTS):
    """Largest absolute change per bucket, and the worst change overall.

    Reported in raw carrier units rather than normalised, because the honest
    scale of the change is the point: fifteen levels out of 65,536 is what
    makes it inaudible, and a chart that normalised that away would be
    misleading in exactly the direction that flatters us.
    """
    delta = np.abs(cover.astype(np.int64) - stego.astype(np.int64))
    edges = _buckets(len(delta), points)
    values = _bucket_max(delta, edges)
    return {
        "values": values,
        "max": float(delta.max()) if delta.size else 0.0,
        "changed": int(np.count_nonzero(delta)),
    }


def lsb_plane(carrier, lsb_n, points=POINTS):
    """Mean value of the low bits, bucket by bucket, normalised to 0..1.

    In natural media the low bits are not random: they track the signal, so
    quiet passages and flat colour regions push this well away from the
    midpoint. Replacing them with encrypted payload drives every bucket to
    0.5, because ciphertext is uniform by construction. A line that goes
    flat is the tell.
    """
    mask = (1 << max(1, lsb_n)) - 1
    values = (carrier & mask).astype(np.float64) / mask
    edges = _buckets(len(values), points)
    return {"values": [round(v, 5) for v in _bucket_mean(values, edges)]}


def _chi_square_p(values, group, bins):
    """Westfeld-Pfitzmann, one window.

    LSB replacement makes values within each group of 2^n equally likely,
    because the low bits it overwrites are uniform. Natural media has no
    such property. The statistic measures how close the observed counts sit
    to that flattened distribution, and the returned probability is high
    when a window looks embedded.
    """
    histogram = np.bincount(values, minlength=bins).astype(np.float64)
    usable = bins - bins % group
    grouped = histogram[:usable].reshape(-1, group)
    grouped = grouped[grouped.sum(axis=1) >= MIN_BIN_COUNT]
    if len(grouped) < MIN_BINS:
        return 0.0

    expected = grouped.mean(axis=1, keepdims=True)
    statistic = float(((grouped - expected) ** 2 / np.maximum(expected, 1e-9)).sum())
    degrees = grouped.size - len(grouped)
    if degrees <= 0:
        return 0.0

    # Normal approximation to the upper tail. Exact for our degrees of
    # freedom to well within the precision a chart can show, and it avoids
    # depending on SciPy for one function.
    z = (statistic - degrees) / math.sqrt(2 * degrees)
    return round(0.5 * math.erfc(z / math.sqrt(2)), 5)


def chi_square_scan(carrier, lsb_n, windows=WINDOWS):
    """Run the detector across the file and report where it fires.

    This is the only view here that an outside analyst could produce: it
    needs no original and no passphrase, only the suspect file. Where it
    rises, a payload is present.
    """
    bins = 1 << (carrier.dtype.itemsize * 8)
    group = 1 << max(1, min(lsb_n, 8))
    values = carrier.astype(np.int64)
    edges = _buckets(len(values), windows)
    scores = [
        _chi_square_p(values[start:end], group, bins)
        for start, end in zip(edges[:-1], edges[1:])
    ]
    return {
        "values": scores,
        "peak": max(scores) if scores else 0.0,
        "windows": len(scores),
    }


def _comparison(stego_scan, cover_scan, region, occupancy, bins):
    """Compare the detector's output on the stego file against the same
    detector on the original, window for window.

    Deliberately not a yes-or-no verdict. Run across enough configurations,
    this test both misses real payloads and fires on untouched covers: it
    depends on the value histogram having local structure for LSB
    replacement to flatten, and depth, payload size and cover content all
    change how much structure there is. Reporting a confident verdict from a
    statistic that behaves that way would be dishonest, so the cover is run
    as a control and the two are shown side by side for the reader to judge.
    """
    stego, cover = stego_scan["values"], cover_scan["values"]
    if not stego:
        return {"separation": "none", "note": "nothing to scan."}

    fractions = [(index + 0.5) / len(stego) for index in range(len(stego))]
    inside = [i for i, f in enumerate(fractions) if region[0] <= f < region[1]]

    stego_peak = max((stego[i] for i in inside), default=0.0)
    control_peak = max((cover[i] for i in inside), default=0.0)
    elsewhere = max((stego[i] for i in range(len(stego)) if i not in inside), default=0.0)

    clear = stego_peak >= 0.6 and stego_peak > control_peak + 0.3 and stego_peak > elsewhere + 0.3
    partial = not clear and stego_peak > control_peak + 0.15

    if clear:
        separation = "clear"
        note = (
            f"Inside the embedded region the stego file peaks at {stego_peak:.2f} where the "
            f"untouched cover reaches only {control_peak:.2f}, and the rest of the stego file "
            f"stays at {elsewhere:.2f}. On this file an analyst holding neither the original "
            "nor the passphrase could locate the payload."
        )
    elif partial:
        separation = "partial"
        note = (
            f"The stego file peaks at {stego_peak:.2f} inside the region against {control_peak:.2f} "
            f"for the cover — a difference, but not one that stands clear of the {elsewhere:.2f} "
            "this test already produces on untouched parts of the same file. Suggestive, not conclusive."
        )
    else:
        separation = "none"
        why = (
            f"the payload occupies only {occupancy * 100:.2f}% of the carrier, so each window is "
            "dominated by untouched data"
            if occupancy < 0.05 else
            "this carrier has 65,536 possible values, so each window spreads its counts thinly "
            "across the histogram and the test loses power — the same test is far sharper on "
            "8-bit media, where there are only 256"
            if bins > 4096 else
            "the value histogram here lacks the local structure that LSB replacement flattens"
        )
        note = (
            f"The stego file peaks at {stego_peak:.2f} inside the region and the cover reaches "
            f"{control_peak:.2f} in the same windows: no usable separation, because {why}. "
            "The payload is present and verifiable — this test simply cannot see it."
        )

    return {
        "separation": separation,
        "stego_peak": round(stego_peak, 3),
        "control_peak": round(control_peak, 3),
        "elsewhere": round(elsewhere, 3),
        "note": note,
    }


def analyse(cover, stego, kind, lsb_n, offset, used_units, points=POINTS, windows=WINDOWS):
    """Everything the analysis panel draws for one protected file."""
    total = len(cover)
    result = {
        "kind": kind,
        "units": total,
        "depth": lsb_n,
        # Where the payload actually sits, as a fraction of the file, so the
        # charts can shade it. Known only because we protected the file
        # ourselves; the chi-square scan has to find it unaided.
        "region": [
            round(offset / total, 6),
            round(min(offset + used_units, total) / total, 6),
        ],
        "waveform": {
            "cover": waveform(cover, kind, points),
            "stego": waveform(stego, kind, points),
        },
        "difference": difference(cover, stego, points),
        "lsb": {
            "cover": lsb_plane(cover, lsb_n, points),
            "stego": lsb_plane(stego, lsb_n, points),
        },
        "chi": {
            "cover": chi_square_scan(cover, lsb_n, windows),
            "stego": chi_square_scan(stego, lsb_n, windows),
        },
    }
    result["detection"] = _comparison(
        result["chi"]["stego"],
        result["chi"]["cover"],
        result["region"],
        used_units / total if total else 0.0,
        1 << (cover.dtype.itemsize * 8),
    )
    return result
