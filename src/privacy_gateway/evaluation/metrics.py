def detection_scores(y_true: list[bool], y_pred: list[bool]) -> dict[str, float]:
    tp = sum(truth and pred for truth, pred in zip(y_true, y_pred, strict=True))
    fp = sum((not truth) and pred for truth, pred in zip(y_true, y_pred, strict=True))
    tn = sum((not truth) and (not pred) for truth, pred in zip(y_true, y_pred, strict=True))
    fn = sum(truth and (not pred) for truth, pred in zip(y_true, y_pred, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }
