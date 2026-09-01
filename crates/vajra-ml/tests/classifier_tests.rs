//! ML Classifier and Analyzer Integration Tests (§33, §29).

use vajra_carve::entropy::EntropyAnalyzer;
use vajra_ml::{FileTypeClassifier, MlEntropyAnalyzer};

#[test]
fn test_classifier_intact_and_header_stripped_detection() {
    let classifier = FileTypeClassifier::default();

    // 1. Synthetic PDF with intact signature
    let intact_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    let feats_pdf = vajra_ml::extract_features(intact_pdf);
    let res_pdf = classifier.classify(&feats_pdf);
    assert_eq!(res_pdf.predicted_class, "pdf");
    assert!(res_pdf.probability > 0.60);

    // 2. Synthetic PDF with stripped header (first 8 bytes zeroed)
    let mut stripped_pdf = intact_pdf.to_vec();
    stripped_pdf[0..8].copy_from_slice(b"        ");
    let feats_stripped = vajra_ml::extract_features(&stripped_pdf);
    let res_stripped = classifier.classify(&feats_stripped);
    assert_eq!(
        res_stripped.predicted_class, "pdf",
        "Stripped PDF should still be classified as PDF via structural entropy and ASCII ratio"
    );

    // 3. Explainability basis: Top 5 features present and non-empty
    assert_eq!(res_pdf.top_features.len(), 5);
    for feat in &res_pdf.top_features {
        assert!(!feat.feature_name.is_empty());
        assert!(feat.global_importance > 0.0);
    }
}

#[test]
fn test_ml_entropy_analyzer_trait_implementation() {
    let analyzer = MlEntropyAnalyzer::new();

    let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 45 >>\nstream\nBT /F1 12 Tf 72 712 Td (Confidential Evidence) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000210 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n";

    // Matching format: PDF against "pdf"
    let score_match = analyzer.evaluate_consistency(pdf_data, "pdf");
    assert!(
        score_match >= 0.70,
        "Matching PDF should have high entropy consistency score, got {}",
        score_match
    );

    // Mismatched format: PDF against "jpeg"
    let score_mismatch = analyzer.evaluate_consistency(pdf_data, "jpeg");
    assert!(
        score_mismatch <= 0.40,
        "PDF evaluated against JPEG should receive lower consistency, got {}",
        score_mismatch
    );
}

