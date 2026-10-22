def aggregate_risk_scores(scores: list[float]) -> dict:
    """Sum risk scores. Uses TenSEAL CKKS when the extra is installed."""
    if not scores:
        return {"backend": "none", "sum": 0.0, "count": 0, "mean": 0.0}

    try:
        import tenseal as ts
    except ImportError:
        total = float(sum(scores))
        return {
            "backend": "plaintext-fallback",
            "sum": total,
            "count": len(scores),
            "mean": total / len(scores),
        }

    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60],
    )
    context.generate_galois_keys()
    context.global_scale = 2**40
    encrypted = ts.ckks_vector(context, [float(score) for score in scores])
    total = float(encrypted.sum().decrypt()[0])
    return {
        "backend": "tenseal",
        "sum": total,
        "count": len(scores),
        "mean": total / len(scores),
    }
