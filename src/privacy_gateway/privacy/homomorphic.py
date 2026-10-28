import json
import time
from dataclasses import dataclass, field

from privacy_gateway.privacy.risk import split_batches

POLY_MODULUS_DEGREE = 8192
COEFF_MOD_BIT_SIZES = (60, 40, 40, 60)
SCALE_BITS = 40


class KeyHolder:
    """The auditor. Creates the CKKS keys and is the only party that can decrypt.

    8192 slots with a 200-bit modulus gives about 128-bit security. Only the
    public key leaves this object, and only addition is needed, so no Galois or
    relinearization keys are shared.
    """

    backend = "tenseal-ckks"

    def __init__(
        self,
        poly_modulus_degree: int = POLY_MODULUS_DEGREE,
        coeff_mod_bit_sizes: tuple[int, ...] = COEFF_MOD_BIT_SIZES,
        scale_bits: int = SCALE_BITS,
    ):
        import tenseal as ts

        self._ts = ts
        self._context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_modulus_degree,
            coeff_mod_bit_sizes=list(coeff_mod_bit_sizes),
        )
        self._context.global_scale = 2**scale_bits
        self.slot_count = poly_modulus_degree // 2

    def public_context(self) -> bytes:
        return self._context.serialize(
            save_public_key=True,
            save_secret_key=False,
            save_galois_keys=False,
            save_relin_keys=False,
        )

    def decrypt(self, payload: bytes) -> list[float]:
        return [float(value) for value in self._ts.ckks_vector_from(self._context, payload).decrypt()]


class GatewayEncryptor:
    """One gateway or department. It can encrypt its own totals but cannot decrypt anything."""

    def __init__(self, public_context: bytes):
        import tenseal as ts

        self._ts = ts
        self._context = _public(ts.context_from(public_context))

    def encrypt(self, vector: list[float]) -> bytes:
        return self._ts.ckks_vector(self._context, [float(value) for value in vector]).serialize()


class Aggregator:
    """Untrusted collector. Adds ciphertexts slot by slot and never sees a plaintext."""

    def __init__(self, public_context: bytes):
        import tenseal as ts

        self._ts = ts
        self._context = _public(ts.context_from(public_context))

    def add(self, payloads: list[bytes]) -> bytes:
        if not payloads:
            raise ValueError("nothing to aggregate")
        total = self._ts.ckks_vector_from(self._context, payloads[0])
        for payload in payloads[1:]:
            total = total + self._ts.ckks_vector_from(self._context, payload)
        return total.serialize()


class PlainKeyHolder:
    """Same interface without encryption, used when TenSEAL is not installed."""

    backend = "plaintext-fallback"
    slot_count = POLY_MODULUS_DEGREE // 2

    def public_context(self) -> bytes:
        return b"plaintext"

    def decrypt(self, payload: bytes) -> list[float]:
        return json.loads(payload)


class PlainEncryptor:
    def __init__(self, public_context: bytes):
        pass

    def encrypt(self, vector: list[float]) -> bytes:
        return json.dumps([float(value) for value in vector]).encode("utf-8")


class PlainAggregator:
    def __init__(self, public_context: bytes):
        pass

    def add(self, payloads: list[bytes]) -> bytes:
        if not payloads:
            raise ValueError("nothing to aggregate")
        vectors = [json.loads(payload) for payload in payloads]
        return json.dumps([sum(values) for values in zip(*vectors)]).encode("utf-8")


@dataclass
class SecureSum:
    totals: list[float]
    backend: str
    parties: int
    public_context_bytes: int
    ciphertext_bytes: int
    timings_ms: dict[str, float] = field(default_factory=dict)

    def info(self) -> dict:
        return {
            "backend": self.backend,
            "parties": self.parties,
            "public_context_bytes": self.public_context_bytes,
            "ciphertext_bytes": self.ciphertext_bytes,
            "timings_ms": self.timings_ms,
        }


def he_backend() -> str:
    try:
        import tenseal  # noqa: F401
    except ImportError:
        return PlainKeyHolder.backend
    return KeyHolder.backend


def secure_sum(vectors: list[list[float]], encrypted: bool = True) -> SecureSum:
    """Add one vector per gateway so only the key holder learns the total.

    Each gateway encrypts under the auditor's public key, the aggregator adds the
    ciphertexts, and the auditor decrypts the sum. CKKS is approximate, so values
    come back within about 1e-6. Cost grows with the number of gateways, not the
    number of events, because each gateway sends one ciphertext.
    """
    if not vectors:
        raise ValueError("no gateway vectors")
    width = len(vectors[0])
    if any(len(vector) != width for vector in vectors):
        raise ValueError("gateway vectors must have the same length")

    timings: dict[str, float] = {}
    started = time.perf_counter()
    use_he = encrypted and he_backend() == KeyHolder.backend
    holder = KeyHolder() if use_he else PlainKeyHolder()
    encryptor_type, aggregator_type = (GatewayEncryptor, Aggregator) if use_he else (PlainEncryptor, PlainAggregator)
    if width > holder.slot_count:
        raise ValueError(f"vector has {width} slots, the context holds {holder.slot_count}")
    public = holder.public_context()
    timings["keygen"] = _ms(started)

    started = time.perf_counter()
    ciphertexts = [encryptor_type(public).encrypt(vector) for vector in vectors]
    timings["encrypt"] = _ms(started)

    started = time.perf_counter()
    total = aggregator_type(public).add(ciphertexts)
    timings["aggregate"] = _ms(started)

    started = time.perf_counter()
    totals = holder.decrypt(total)[:width]
    timings["decrypt"] = _ms(started)

    return SecureSum(
        totals=totals,
        backend=holder.backend,
        parties=len(vectors),
        public_context_bytes=len(public),
        ciphertext_bytes=len(ciphertexts[0]),
        timings_ms=timings,
    )


def aggregate_risk_scores(scores: list[float], parties: int = 3) -> dict:
    """Sum risk scores held by several gateways. Uses TenSEAL CKKS when the extra is installed."""
    if not scores:
        return {"backend": "none", "sum": 0.0, "count": 0, "mean": 0.0}

    batches = split_batches([float(score) for score in scores], parties)
    result = secure_sum([[sum(batch), float(len(batch))] for batch in batches])
    total = result.totals[0]
    count = round(result.totals[1])
    return {"sum": total, "count": count, "mean": total / count if count else 0.0, **result.info()}


def _public(context):
    if context.is_private():
        raise ValueError("only the key holder may hold the secret key")
    return context


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)
