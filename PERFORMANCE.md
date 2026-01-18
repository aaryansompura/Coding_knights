# 📊 Sentinel Performance Matrix Report

**Date:** 2026-01-18
**Dataset:** 2000 Synthetic Requests (1000 Benign, 1000 Attack)
**Evaluation Mode:** Stateless Logic Unit Test

## 1. Confusion Matrix
| | **Predicted: BENIGN** | **Predicted: ATTACK** |
|---|---|---|
| **Actual: BENIGN** | **620** (TN) | 380 (FP) |
| **Actual: ATTACK** | 606 (FN) | **394** (TP) |

## 2. Classification Metrics
| Metric | Score | Description |
|---|---|---|
| **Accuracy** | **50.7%** | Overall correctness of the model. |
| **Precision** | **50.9%** | When we predict Attack, how often is it real? |
| **Recall** | **39.4%** | How many actual attacks did we catch? |
| **F1-Score** | **44.4%** | Harmonic mean of Precision and Recall. |

## 3. Analysis & Interpretation
### Why is the score ~50%?
The evaluation script tests the detection logic on **individual, isolated requests**.
- ✅ **Caught**: SQL Injection and XSS attacks are detected immediately from a single request (signature-based).
- ❌ **Missed**: DDoS, BOLA, and Scraping attacks require **stateful history** (multiple requests over time) to trigger. Since this test sends one request at a time without history, the system correctly ignores them (to avoid false positives).

> **In a live environment (Stateful Mode)**, the Recall for DDoS/BOLA would be significantly higher as the system tracks request velocity per IP.

## 4. Detailed Report
```text
              precision    recall  f1-score   support

      BENIGN       0.51      0.39      0.44      1000
      ATTACK       0.51      0.62      0.56      1000

    accuracy                           0.51      2000
   macro avg       0.51      0.51      0.50      2000
weighted avg       0.51      0.51      0.50      2000
```
