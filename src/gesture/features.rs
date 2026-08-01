use rustfft::{FftPlanner, num_complex::Complex};

/// Fixed sample count every stream is resampled to before feature extraction.
/// This keeps FFT bins and per-sample deltas comparable across windows that
/// happened to capture different numbers of packets.
pub const FEAT_SAMPLES: usize = 128;

/// Linearly resample `values` to exactly `n` samples.
/// Single/empty inputs are handled so the caller always gets `n` points.
pub fn resample(values: &[f64], n: usize) -> Vec<f64> {
    if n == 0 {
        return Vec::new();
    }
    if values.is_empty() {
        return vec![0.0; n];
    }
    if values.len() == 1 {
        return vec![values[0]; n];
    }
    if values.len() == n {
        return values.to_vec();
    }

    let scale = (values.len() - 1) as f64 / (n - 1) as f64;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let pos = i as f64 * scale;
        let lo = pos.floor() as usize;
        let hi = (lo + 1).min(values.len() - 1);
        let frac = pos - lo as f64;
        out.push(values[lo] * (1.0 - frac) + values[hi] * frac);
    }
    out
}

/// Compute 9 time-domain features from a slice of RSSI samples.
/// Returns a Vec<f64> (length 9) with a fixed ordering.
pub fn time_features(values: &[f64]) -> Vec<f64> {
    if values.is_empty() {
        return vec![0.0; 9];
    }

    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;

    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    let std = variance.sqrt();

    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = max - min;

    let mut max_abs_delta = 0.0f64;
    let mut sum_abs_delta = 0.0f64;
    let mut mean_crossings = 0.0f64;
    let mut prev = values[0];
    for &v in values.iter().skip(1) {
        let d = (v - prev).abs();
        if d > max_abs_delta {
            max_abs_delta = d;
        }
        sum_abs_delta += d;
        // crossing of the mean level (RSSI is always negative, so a raw
        // zero-crossing is meaningless and would be constant zero)
        if (prev - mean).is_sign_negative() != (v - mean).is_sign_negative() {
            mean_crossings += 1.0;
        }
        prev = v;
    }

    // net drift: +1 net up, -1 net down, 0 flat
    let drift = (values[values.len() - 1] - values[0]).signum();

    // energy: sum of squares
    let energy = values.iter().map(|v| v * v).sum::<f64>() / n;

    vec![
        mean,
        variance,
        std,
        range,
        max_abs_delta,
        sum_abs_delta / n,
        drift,
        mean_crossings,
        energy,
    ]
}

/// Compute top-`bins` FFT magnitude features from a slice of RSSI samples.
/// Returns the DC-removed first `bins` magnitudes (excluding bin 0).
pub fn fft_features(values: &[f64], bins: usize) -> Vec<f64> {
    if values.is_empty() {
        return vec![0.0; bins];
    }

    let n = values.len();
    let mean = values.iter().sum::<f64>() / n as f64;
    let centered: Vec<Complex<f64>> = values
        .iter()
        .map(|v| Complex::new(v - mean, 0.0))
        .collect();

    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(n);
    let mut buffer = centered;
    fft.process(&mut buffer);

    let mut out = Vec::with_capacity(bins);
    out.extend(buffer.iter().skip(1).take(bins).map(|c| c.norm()));
    while out.len() < bins {
        out.push(0.0);
    }
    out
}

/// Combine time + fft features into one vector, per-AP.
/// The stream is resampled to a fixed length first so that FFT bins and
/// per-sample deltas are comparable across windows of different packet counts.
pub fn features_for_stream(values: &[f64], fft_bins: usize) -> Vec<f64> {
    let fixed = resample(values, FEAT_SAMPLES);
    let mut feats = time_features(&fixed);
    feats.extend(fft_features(&fixed, fft_bins));
    feats
}

/// Features for one AP stream, with an explicit presence bit appended last.
/// This distinguishes "AP seen but weak/flat" from "AP not in this window at
/// all" — a vanished AP no longer collapses to z-scored zeros.
pub fn features_for_stream_present(values: &[f64], present: bool) -> Vec<f64> {
    let mut feats = features_for_stream(values, 4);
    feats.push(if present { 1.0 } else { 0.0 });
    feats
}

/// Z-score normalize a feature matrix in place using the provided mean/std.
/// Each row is one sample; each column is one feature.
pub fn zscore_inplace(rows: &mut [Vec<f64>], means: &[f64], stds: &[f64]) {
    for row in rows.iter_mut() {
        for (v, (m, s)) in row.iter_mut().zip(means.iter().zip(stds.iter())) {
            if *s > 1e-9 {
                *v = (*v - *m) / *s;
            } else {
                *v = 0.0;
            }
        }
    }
}

/// Z-score normalize a single row using the provided mean/std.
pub fn zscore_inplace_single(raw: &[f64], means: &[f64], stds: &[f64]) -> Vec<f64> {
    let mut out = raw.to_vec();
    for (v, (m, s)) in out.iter_mut().zip(means.iter().zip(stds.iter())) {
        if *s > 1e-9 {
            *v = (*v - *m) / *s;
        } else {
            *v = 0.0;
        }
    }
    out
}

/// Compute per-column mean and std of a feature matrix.
pub fn fit_zscore(rows: &[Vec<f64>]) -> (Vec<f64>, Vec<f64>) {
    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let dim = rows[0].len();
    let mut means = vec![0.0; dim];
    let mut stds = vec![0.0; dim];

    for row in rows {
        for (i, v) in row.iter().enumerate() {
            means[i] += v;
        }
    }
    for m in means.iter_mut() {
        *m /= rows.len() as f64;
    }

    for row in rows {
        for (i, v) in row.iter().enumerate() {
            let d = v - means[i];
            stds[i] += d * d;
        }
    }
    for s in stds.iter_mut() {
        *s = (*s / rows.len() as f64).sqrt();
    }

    (means, stds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_signal_has_zero_variance() {
        let f = time_features(&[-50.0; 50]);
        assert!(f[1].abs() < 1e-6);
    }

    #[test]
    fn ramp_signal_detects_drift() {
        let v: Vec<f64> = (0..50).map(|i| -70.0 + i as f64).collect();
        let f = time_features(&v);
        assert!(f[6] > 0.0); // net up
    }

    #[test]
    fn mean_crossings_detect_oscillation() {
        // Oscillate around -50 -> should register mean crossings.
        let v: Vec<f64> = (0..128)
            .map(|i| -50.0 + ((i as f64 / 8.0) * std::f64::consts::TAU).sin())
            .collect();
        let f = time_features(&v);
        assert!(f[7] > 0.0);
    }

    #[test]
    fn fft_shape_is_stable() {
        // sin with period 64 -> energy in bin 1 (within first 4 bins)
        let v: Vec<f64> = (0..64)
            .map(|i| (2.0 * std::f64::consts::PI * i as f64 / 64.0).sin() * 5.0)
            .collect();
        let f = fft_features(&v, 4);
        assert_eq!(f.len(), 4);
        assert!(f.iter().any(|x| *x > 1e-6));
    }

    #[test]
    fn resample_preserves_length() {
        for len in [1usize, 2, 7, 64, 128, 256] {
            let v: Vec<f64> = (0..len).map(|i| i as f64).collect();
            let r = resample(&v, FEAT_SAMPLES);
            assert_eq!(r.len(), FEAT_SAMPLES);
        }
        assert_eq!(resample(&[], FEAT_SAMPLES), vec![0.0; FEAT_SAMPLES]);
        assert_eq!(resample(&[5.0], FEAT_SAMPLES), vec![5.0; FEAT_SAMPLES]);
    }

    #[test]
    fn features_for_stream_constant_dimension() {
        let a = features_for_stream(&(0..200).map(|i| -50.0 + (i % 7) as f64).collect::<Vec<_>>(), 4);
        let b = features_for_stream(&(0..40).map(|i| -55.0 + (i % 3) as f64).collect::<Vec<_>>(), 4);
        let c = features_for_stream(&[], 4);
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
        assert_eq!(a.len(), 13); // 9 time + 4 fft
    }

    #[test]
    fn presence_bit_distinguishes_missing_ap() {
        let present = features_for_stream_present(&[-50.0, -52.0, -48.0], true);
        let missing = features_for_stream_present(&[], false);
        assert_eq!(present.len(), missing.len());
        assert!((present[present.len() - 1] - 1.0).abs() < 1e-9);
        assert!(missing[missing.len() - 1].abs() < 1e-9);
    }

    #[test]
    fn zscore_normalizes() {
        let mut rows = vec![vec![10.0, 20.0], vec![30.0, 40.0]];
        let (m, s) = fit_zscore(&rows);
        zscore_inplace(&mut rows, &m, &s);
        // mean ~0, std ~1
        let mean: f64 = rows.iter().flat_map(|r| r.iter()).sum::<f64>() / 4.0;
        assert!(mean.abs() < 1e-9);
    }
}
