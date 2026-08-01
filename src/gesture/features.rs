use rustfft::{FftPlanner, num_complex::Complex};

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
    let mut zero_crossings = 0.0f64;
    let mut prev = values[0];
    for &v in values.iter().skip(1) {
        let d = (v - prev).abs();
        if d > max_abs_delta {
            max_abs_delta = d;
        }
        sum_abs_delta += d;
        if (prev > 0.0) != (v > 0.0) {
            zero_crossings += 1.0;
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
        zero_crossings,
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
pub fn features_for_stream(values: &[f64], fft_bins: usize) -> Vec<f64> {
    let mut feats = time_features(values);
    feats.extend(fft_features(values, fft_bins));
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
    fn zscore_normalizes() {
        let mut rows = vec![vec![10.0, 20.0], vec![30.0, 40.0]];
        let (m, s) = fit_zscore(&rows);
        zscore_inplace(&mut rows, &m, &s);
        // mean ~0, std ~1
        let mean: f64 = rows.iter().flat_map(|r| r.iter()).sum::<f64>() / 4.0;
        assert!(mean.abs() < 1e-9);
    }
}
