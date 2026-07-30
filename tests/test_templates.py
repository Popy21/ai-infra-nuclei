"""
Porte de qualité du pack.

Un template qui passe ces tests est publiable ; un template qui les échoue ne doit
jamais être commité. C'est cette contrainte qui rend un commit automatique
significatif : sans elle, un commit ne prouve rien.
"""

import os
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(ROOT, "templates")

VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
REQUIRED_INFO = ("name", "author", "severity", "description", "impact",
                 "remediation", "reference", "tags")


def template_files():
    out = []
    for root, _, files in os.walk(TEMPLATES_DIR):
        for f in sorted(files):
            if f.endswith((".yaml", ".yml")):
                out.append(os.path.join(root, f))
    return out


ALL = template_files()


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def rel(path):
    return os.path.relpath(path, ROOT)


# --------------------------------------------------------------------------
def test_pack_is_not_empty():
    assert ALL, "aucun template trouvé sous templates/"


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_yaml_parses(path):
    assert load(path) is not None


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_id_matches_filename(path):
    doc = load(path)
    expected = os.path.splitext(os.path.basename(path))[0]
    assert doc.get("id") == expected, f"id={doc.get('id')!r} != nom de fichier {expected!r}"


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_required_info_fields(path):
    info = load(path).get("info") or {}
    missing = [k for k in REQUIRED_INFO if not info.get(k)]
    assert not missing, f"champs info manquants : {missing}"


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_severity_is_valid(path):
    sev = (load(path).get("info") or {}).get("severity")
    assert sev in VALID_SEVERITY, f"sévérité invalide : {sev!r}"


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_has_real_references(path):
    refs = (load(path).get("info") or {}).get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    assert refs, "aucune référence"
    for r in refs:
        assert str(r).startswith("http"), f"référence non-URL : {r!r}"


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_tagged_ai(path):
    tags = (load(path).get("info") or {}).get("tags") or ""
    tags = [t.strip() for t in str(tags).split(",")]
    assert "ai" in tags or "ml" in tags, f"le pack est thématique : tags={tags}"


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_no_placeholder_left(path):
    with open(path) as f:
        body = f.read()
    for marker in ("TODO", "FIXME", "XXX", "changeme", "example.com"):
        assert marker not in body, f"marqueur de brouillon restant : {marker}"


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_matcher_is_not_status_only(path):
    """
    Un matcher qui ne teste que le code HTTP déclenche sur n'importe quel serveur
    vivant. C'est le défaut le plus courant des templates rejetés en amont.
    """
    doc = load(path)
    protocols = [k for k in ("http", "network", "dns", "file", "javascript") if k in doc]
    assert protocols, "aucun bloc de protocole"
    for proto in protocols:
        for block in doc[proto]:
            matchers = block.get("matchers") or []
            assert matchers, "bloc sans matcher"
            kinds = {m.get("type") for m in matchers}
            assert kinds - {"status"}, (
                "le bloc ne contient qu'un matcher de statut — il déclencherait "
                "sur tout serveur répondant 200"
            )


@pytest.mark.parametrize("path", ALL, ids=rel)
def test_description_impact_remediation_are_substantive(path):
    info = load(path).get("info") or {}
    for field, mini in (("description", 80), ("impact", 40), ("remediation", 40)):
        val = re.sub(r"\s+", " ", str(info.get(field, ""))).strip()
        assert len(val) >= mini, (
            f"{field} fait {len(val)} caractères, minimum {mini} — "
            "une phrase creuse ne renseigne personne"
        )


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_nuclei_validates_the_whole_pack():
    r = subprocess.run(
        ["nuclei", "-validate", "-t", TEMPLATES_DIR, "-duc"],
        capture_output=True, text=True, timeout=300,
    )
    combined = r.stdout + r.stderr
    assert "All templates validated successfully" in combined, combined[-2000:]
