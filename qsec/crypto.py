from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class AlgorithmRecord:
    name: str
    family: str
    status: str
    standard: str
    quantum_risk: str


ALGORITHMS: Dict[str, AlgorithmRecord] = {
    "RSA": AlgorithmRecord("RSA", "integer factorization", "legacy", "", "quantum-vulnerable"),
    "DSA": AlgorithmRecord("DSA", "finite-field discrete logarithm", "legacy", "", "quantum-vulnerable"),
    "DH": AlgorithmRecord("Diffie-Hellman", "finite-field discrete logarithm", "legacy", "", "quantum-vulnerable"),
    "ECDSA": AlgorithmRecord("ECDSA", "elliptic-curve discrete logarithm", "legacy", "", "quantum-vulnerable"),
    "ECDH": AlgorithmRecord("ECDH", "elliptic-curve discrete logarithm", "legacy", "", "quantum-vulnerable"),
    "ED25519": AlgorithmRecord("Ed25519", "elliptic-curve signature", "legacy", "", "quantum-vulnerable"),
    "X25519": AlgorithmRecord("X25519", "elliptic-curve key agreement", "legacy", "", "quantum-vulnerable"),
    "ML-KEM": AlgorithmRecord("ML-KEM", "module lattice KEM", "standardized", "FIPS 203", "post-quantum"),
    "ML-DSA": AlgorithmRecord("ML-DSA", "module lattice signature", "standardized", "FIPS 204", "post-quantum"),
    "SLH-DSA": AlgorithmRecord("SLH-DSA", "stateless hash signature", "standardized", "FIPS 205", "post-quantum"),
    "KYBER": AlgorithmRecord("CRYSTALS-Kyber", "module lattice KEM", "pre-standard", "not automatically FIPS 203", "post-quantum transition"),
    "DILITHIUM": AlgorithmRecord("CRYSTALS-Dilithium", "module lattice signature", "pre-standard", "not automatically FIPS 204", "post-quantum transition"),
    "SPHINCS+": AlgorithmRecord("SPHINCS+", "stateless hash signature", "pre-standard", "not automatically FIPS 205", "post-quantum transition"),
    "FALCON": AlgorithmRecord("Falcon", "lattice signature", "pre-standard", "not automatically FN-DSA", "post-quantum transition"),
    "HQC": AlgorithmRecord("HQC", "code-based KEM", "selected", "future NIST standard", "post-quantum candidate"),
    "FN-DSA": AlgorithmRecord("FN-DSA", "lattice signature", "in-development", "planned FIPS 206", "post-quantum candidate"),
}


@dataclass(frozen=True)
class CryptoFinding:
    path: str
    line: int
    column: int
    algorithm: str
    status: str
    quantum_risk: str
    standard: str
    match: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "algorithm": self.algorithm,
            "status": self.status,
            "quantum_risk": self.quantum_risk,
            "standard": self.standard,
            "match": self.match,
        }


_PATTERN_DEFINITIONS: Tuple[Tuple[str, str], ...] = (
    ("ML-KEM", r"\bML[-_ ]?KEM(?:[-_ ]?(?:512|768|1024))?\b"),
    ("ML-DSA", r"\bML[-_ ]?DSA(?:[-_ ]?(?:44|65|87))?\b"),
    ("SLH-DSA", r"\bSLH[-_ ]?DSA(?:[-_ ]?[A-Z0-9]+)*\b"),
    ("KYBER", r"\b(?:CRYSTALS[-_ ]?)?KYBER(?:[-_ ]?(?:512|768|1024))?\b"),
    ("DILITHIUM", r"\b(?:CRYSTALS[-_ ]?)?DILITHIUM(?:[-_ ]?(?:2|3|5))?\b"),
    ("SPHINCS+", r"\b(?:SPHINCS\+|SPHINCSPLUS)(?:[-_ ]?[A-Z0-9]+)*\b"),
    ("FALCON", r"\bFALCON(?:[-_ ]?(?:512|1024))?\b"),
    ("HQC", r"\bHQC(?:[-_ ]?(?:128|192|256))?\b"),
    ("FN-DSA", r"\bFN[-_ ]?DSA(?:[-_ ]?[A-Z0-9]+)*\b"),
    ("RSA", r"\b(?:RSA(?:[-_ ]?(?:2048|3072|4096))?|ssh-rsa|BEGIN RSA (?:PRIVATE|PUBLIC) KEY)\b"),
    ("ECDSA", r"\b(?:ECDSA|ecdsa-sha2-[A-Za-z0-9-]+|secp(?:256|384|521)[rk]1|P-(?:256|384|521))\b"),
    ("ECDH", r"\b(?:ECDH|ECDHE|ecdh-sha2-[A-Za-z0-9-]+)\b"),
    ("ED25519", r"\b(?:ED25519|ssh-ed25519)\b"),
    ("X25519", r"\bX25519\b"),
    ("DSA", r"\b(?:DSA|ssh-dss|BEGIN DSA PRIVATE KEY)\b"),
    ("DH", r"\b(?:DIFFIE[-_ ]?HELLMAN|DHE|MODP(?:2048|3072|4096)|DH_GROUP\d+)\b"),
)

_PATTERNS = tuple((name, re.compile(pattern, re.IGNORECASE)) for name, pattern in _PATTERN_DEFINITIONS)
_DEFAULT_IGNORES = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}
_TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".ini", ".java", ".js", ".json",
    ".md", ".pem", ".properties", ".ps1", ".py", ".rb", ".rs", ".sh", ".toml", ".ts",
    ".txt", ".xml", ".yaml", ".yml", ".conf", ".cfg", ".env",
}


def scan_text(text: str, path: str = "<memory>") -> List[CryptoFinding]:
    findings: List[CryptoFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        candidates = []
        for key, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                candidates.append((match.start(), match.end(), key, match.group(0)))
        candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))
        accepted = []
        for candidate in candidates:
            start, end, _, _ = candidate
            if any(start < accepted_end and end > accepted_start for accepted_start, accepted_end, _, _ in accepted):
                continue
            accepted.append(candidate)
        for start, _, key, matched_text in sorted(accepted, key=lambda item: item[0]):
            record = ALGORITHMS[key]
            findings.append(
                CryptoFinding(
                    path=path,
                    line=line_number,
                    column=start + 1,
                    algorithm=record.name,
                    status=record.status,
                    quantum_risk=record.quantum_risk,
                    standard=record.standard,
                    match=matched_text,
                )
            )
    return findings


def _iter_files(root: Path, maximum_file_bytes: int) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _DEFAULT_IGNORES for part in path.parts):
            continue
        try:
            if path.stat().st_size > maximum_file_bytes:
                continue
        except OSError:
            continue
        if path.suffix.lower() in _TEXT_SUFFIXES or path.name.lower().startswith("dockerfile"):
            yield path


def scan_path(path: str | Path, maximum_file_bytes: int = 4 * 1024 * 1024) -> List[CryptoFinding]:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(str(root))
    findings: List[CryptoFinding] = []
    for file_path in _iter_files(root, maximum_file_bytes):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, path=str(file_path)))
    return findings


def summarize_findings(findings: Sequence[CryptoFinding]) -> Dict[str, object]:
    vulnerable = [item for item in findings if item.quantum_risk == "quantum-vulnerable"]
    standardized = [item for item in findings if item.status == "standardized"]
    candidates = [item for item in findings if item.status in {"selected", "in-development"}]
    prestandard = [item for item in findings if item.status == "pre-standard"]
    by_algorithm: Dict[str, int] = {}
    for item in findings:
        by_algorithm[item.algorithm] = by_algorithm.get(item.algorithm, 0) + 1
    return {
        "total_matches": len(findings),
        "quantum_vulnerable_matches": len(vulnerable),
        "standardized_pqc_matches": len(standardized),
        "pqc_candidate_matches": len(candidates),
        "prestandard_pqc_matches": len(prestandard),
        "harvest_vault_exposure": bool(vulnerable),
        "algorithms": dict(sorted(by_algorithm.items())),
    }
