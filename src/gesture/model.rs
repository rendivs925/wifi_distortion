use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use smartcore::ensemble::random_forest_classifier::{
    RandomForestClassifier, RandomForestClassifierParameters,
};
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::metrics::accuracy;
use smartcore::metrics::distance::euclidian::Euclidian;
use smartcore::neighbors::knn_classifier::{KNNClassifier, KNNClassifierParameters};

use crate::gesture::features;

pub const MODEL_PATH: &str = "gesture_model.json";

type Mat = DenseMatrix<f64>;
type RfModel = RandomForestClassifier<f64, u32, Mat, Vec<u32>>;
type KnnModel = KNNClassifier<f64, u32, Mat, Vec<u32>, Euclidian<f64>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct TrainedModel {
    /// Feature normalization (per-column z-score).
    pub means: Vec<f64>,
    pub stds: Vec<f64>,
    /// Ordered class labels.
    pub labels: Vec<String>,
    /// Number of features per sample.
    pub feature_dim: usize,
    /// Global AP order (strongest first) used to lay out feature blocks.
    /// Inference must use this exact ordering.
    pub ap_order: Vec<String>,
    /// RandomForest for the winning label.
    pub rf: RfModel,
    /// KNN for per-class probabilities (margin estimation).
    pub knn: KnnModel,
}

impl TrainedModel {
    pub fn save(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string(self).context("failed to serialize model")?;
        std::fs::write(path, json).context("failed to write model file")?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path).context("failed to read model file")?;
        serde_json::from_str(&json).context("failed to deserialize model")
    }

    /// Predict the label for a raw (un-normalized) feature vector.
    /// Returns (label, margin) where margin = (prob[label] - max_other)/prob[label].
    /// Margin is computed for the exact label returned, so RF and KNN stay consistent.
    pub fn predict(&self, raw_feature: &[f64]) -> Result<Option<(String, f64)>> {
        if raw_feature.len() != self.feature_dim {
            return Err(anyhow::anyhow!(
                "feature dim mismatch: expected {}, got {}",
                self.feature_dim,
                raw_feature.len()
            ));
        }

        let normalized = self.normalize(raw_feature);
        let x = DenseMatrix::from_2d_array(&[normalized.as_slice()])
            .map_err(|e| anyhow::anyhow!("matrix error: {:?}", e))?;

        let label_pred = self.rf.predict(&x).context("model predict failed")?;
        let label_idx = label_pred[0] as usize;
        if label_idx >= self.labels.len() {
            return Ok(None);
        }
        let label = self.labels[label_idx].clone();

        let probs = self.knn.predict_proba(&x).context("KNN predict_proba failed")?;
        let prob_vec = &probs[0];

        // Margin is relative to the RF-chosen label. If KNN gives it zero
        // probability (the models disagree), the margin collapses to ~0/negative
        // and the confidence gate will reject — which is the safe behavior.
        let p_label = prob_vec.get(label_idx).copied().unwrap_or(0.0);
        let max_other = prob_vec
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != label_idx)
            .map(|(_, p)| *p)
            .fold(0.0f64, f64::max);

        let margin = if p_label > 1e-9 {
            (p_label - max_other) / p_label
        } else {
            0.0
        };

        Ok(Some((label, margin)))
    }

    pub fn normalize(&self, raw: &[f64]) -> Vec<f64> {
        features::zscore_inplace_single(raw, &self.means, &self.stds)
    }
}

/// Train RandomForest + KNN from feature rows + labels with a stratified
/// 80/20 split. Returns the model and logs held-out accuracy for both.
pub fn train(
    feature_rows: &[Vec<f64>],
    label_indices: &[u32],
    label_names: &[String],
    ap_order: &[String],
) -> Result<TrainedModel> {
    if feature_rows.is_empty() {
        return Err(anyhow::anyhow!("no training data"));
    }
    let n = feature_rows.len();
    let dim = feature_rows[0].len();
    if n < 5 {
        return Err(anyhow::anyhow!(
            "not enough training samples (have {}); record more",
            n
        ));
    }

    // Stratified split: for each class, hold out the last 20% as test.
    let mut train_idx: Vec<usize> = Vec::new();
    let mut test_idx: Vec<usize> = Vec::new();
    for c in 0..label_names.len() {
        let mut idxs: Vec<usize> = (0..n).filter(|&i| label_indices[i] as usize == c).collect();
        let test_count = (idxs.len() as f64 * 0.2).round() as usize;
        let split = idxs.len() - test_count.min(idxs.len());
        let rest = idxs.split_off(split);
        train_idx.extend(idxs);
        test_idx.extend(rest);
    }
    if train_idx.is_empty() || test_idx.is_empty() {
        return Err(anyhow::anyhow!(
            "train/test split ended up empty (n={})",
            n
        ));
    }

    let x_train: Vec<Vec<f64>> = train_idx.iter().map(|&i| feature_rows[i].clone()).collect();
    let y_train: Vec<u32> = train_idx.iter().map(|&i| label_indices[i]).collect();
    let x_test: Vec<Vec<f64>> = test_idx.iter().map(|&i| feature_rows[i].clone()).collect();
    let y_test: Vec<u32> = test_idx.iter().map(|&i| label_indices[i]).collect();

    let (means, stds) = features::fit_zscore(&x_train);

    let mut xt = x_train.clone();
    features::zscore_inplace(&mut xt, &means, &stds);
    let rows_train: Vec<&[f64]> = xt.iter().map(|r| r.as_slice()).collect();
    let xt_train =
        DenseMatrix::from_2d_array(&rows_train).map_err(|e| anyhow::anyhow!("matrix: {:?}", e))?;

    let mut xte = x_test.clone();
    features::zscore_inplace(&mut xte, &means, &stds);
    let rows_test: Vec<&[f64]> = xte.iter().map(|r| r.as_slice()).collect();
    let xt_test =
        DenseMatrix::from_2d_array(&rows_test).map_err(|e| anyhow::anyhow!("matrix: {:?}", e))?;

    let rf_params = RandomForestClassifierParameters::default()
        .with_n_trees(100)
        .with_max_depth(20)
        .with_min_samples_leaf(1)
        .with_min_samples_split(2)
        .with_seed(42);
    let rf = RandomForestClassifier::fit(&xt_train, &y_train, rf_params)
        .context("RandomForest fit failed")?;

    let knn_params = KNNClassifierParameters::default().with_k(3);
    let knn = KNNClassifier::fit(&xt_train, &y_train, knn_params).context("KNN fit failed")?;

    let rf_pred = rf.predict(&xt_test).context("RF predict failed")?;
    let knn_pred = knn.predict(&xt_test).context("KNN predict failed")?;

    let rf_acc = accuracy(&y_test, &rf_pred);
    let knn_acc = accuracy(&y_test, &knn_pred);

    tracing::info!(
        "train={} test={} dim={} rf_acc={:.2} knn_acc={:.2}",
        y_train.len(),
        y_test.len(),
        dim,
        rf_acc,
        knn_acc
    );

    Ok(TrainedModel {
        means,
        stds,
        labels: label_names.to_vec(),
        feature_dim: dim,
        ap_order: ap_order.to_vec(),
        rf,
        knn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn train_and_predict_roundtrip() {
        let rows: Vec<Vec<f64>> = (0..40)
            .map(|i| vec![if i < 20 { 0.0 } else { 10.0 }, 1.0])
            .collect();
        let labels: Vec<u32> = (0..40).map(|i| if i < 20 { 0 } else { 1 }).collect();
        let names = vec!["a".to_string(), "b".to_string()];
        let aps = vec!["AP1".to_string(), "AP2".to_string()];

        let m = train(&rows, &labels, &names, &aps).unwrap();
        let out = m.predict(&vec![10.5, 1.0]).unwrap().unwrap();
        assert_eq!(out.0, "b");
    }

    #[test]
    fn model_serializes_and_roundtrips() {
        let rows: Vec<Vec<f64>> = (0..40)
            .map(|i| vec![if i < 20 { 0.0 } else { 10.0 }, 1.0])
            .collect();
        let labels: Vec<u32> = (0..40).map(|i| if i < 20 { 0 } else { 1 }).collect();
        let names = vec!["a".to_string(), "b".to_string()];
        let aps = vec!["AP1".to_string(), "AP2".to_string()];

        let m = train(&rows, &labels, &names, &aps).unwrap();
        let json = serde_json::to_string(&m).expect("serialize failed");
        let m2: TrainedModel = serde_json::from_str(&json).expect("deserialize failed");
        let out = m2.predict(&vec![10.5, 1.0]).unwrap().unwrap();
        assert_eq!(out.0, "b");
    }
}
