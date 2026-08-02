"""
Porte de qualité de `scripts/coverage.py`.

L'outil n'a d'intérêt que s'il tient deux promesses. Qu'il lise l'identifiant
comme le fait le moteur — il ne parse pas le YAML, il lit une ligne, et c'est un
raccourci qui doit être payé par une vérification sur le pack réel, fichier par
fichier. Et qu'il ne signale un doublon que là où il y en a un : un rapport qui
crie sur des identifiants distincts se fait ignorer au deuxième passage, et ne
sert alors plus à rien du tout.
"""

import importlib.util
import json
import os
import subprocess
import sys

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "coverage.py")
TEMPLATES_DIR = os.path.join(ROOT, "templates")


def load_script():
    """
    Chargé par chemin plutôt qu'importé : `scripts/` n'est pas un paquet, et
    `import coverage` désignerait coverage.py, l'outil de couverture de code.
    """
    spec = importlib.util.spec_from_file_location("pack_coverage", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pack_coverage = load_script()


def pack_files():
    out = []
    for directory, _, files in os.walk(TEMPLATES_DIR):
        for name in sorted(files):
            if name.endswith((".yaml", ".yml")):
                out.append(os.path.join(directory, name))
    return out


PACK = pack_files()


def rel(path):
    return os.path.relpath(path, ROOT)


def write(root, relative, body):
    path = os.path.join(root, *relative.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(body)
    return path


def template(template_id):
    """Le squelette minimal qui porte un identifiant — le reste ne concerne pas l'outil."""
    return "id: %s\n\ninfo:\n  name: Peu importe\n  severity: info\n" % template_id


# --------------------------------------------------------------------------
# Lecture de l'identifiant.

@pytest.mark.parametrize("path", PACK, ids=rel)
def test_l_identifiant_lu_est_celui_que_yaml_rend(path):
    """
    La justification du raccourci, et elle se vérifie plutôt qu'elle ne se
    plaide : sur chaque template du pack, la ligne lue doit donner exactement ce
    que le parseur donne.
    """
    with open(path, encoding="utf-8") as handle:
        expected = (yaml.safe_load(handle) or {}).get("id")
    assert pack_coverage.read_id(path) == expected


@pytest.mark.parametrize("body", [
    # Nu, guillemeté, apostrophé : les trois écritures qu'un template peut porter.
    "id: foo-exposed\n\ninfo:\n  name: x\n",
    'id: "foo-exposed"\n\ninfo:\n  name: x\n',
    "id: 'foo-exposed'\n\ninfo:\n  name: x\n",
    # Suivi d'un commentaire, que la grammaire d'un identifiant ne peut pas contenir.
    "id: foo-exposed  # à proposer en amont\n\ninfo:\n  name: x\n",
    # Fins de ligne Windows : un template relayé par un éditeur distrait.
    "id: foo-exposed\r\n\r\ninfo:\r\n  name: x\r\n",
    # L'identifiant n'est pas tenu d'ouvrir le document.
    "info:\n  name: x\nid: foo-exposed\n",
    # Et surtout : un `id:` indenté appartient à un bloc, ce n'est pas
    # l'identifiant du template. Ici il est dans un scalaire de description.
    "id: foo-exposed\n\ninfo:\n  description: |\n    id: pas-celui-la\n",
])
def test_l_identifiant_est_lu_sous_les_ecritures_que_yaml_accepte(tmp_path, body):
    path = write(str(tmp_path), "t.yaml", body)
    with open(path, encoding="utf-8") as handle:
        expected = (yaml.safe_load(handle) or {}).get("id")

    assert expected == "foo-exposed", "le cas de test ne dit pas ce qu'il croit dire"
    assert pack_coverage.read_id(path) == "foo-exposed"


@pytest.mark.parametrize("body", [
    # Un profil de nuclei : un `.yml` de l'arbre amont, sans identifiant.
    "info:\n  name: ai\ntags:\n  - ai\n",
    # Une clé vide n'est pas un identifiant.
    "id:\n\ninfo:\n  name: x\n",
    # Le seul `id:` du document est indenté, donc il appartient à un bloc.
    "info:\n  description: |\n    id: pas-un-identifiant\n",
])
def test_le_fichier_sans_identifiant_ne_rend_rien(tmp_path, body):
    path = write(str(tmp_path), "t.yml", body)
    assert pack_coverage.read_id(path) is None


# --------------------------------------------------------------------------
# Collecte.

def test_seuls_les_templates_sont_collectes(tmp_path):
    """
    L'arbre amont ne contient pas que des templates : des profils, des listes de
    charges utiles, de la documentation. Ce qui ne porte pas d'identifiant n'a
    pas à peupler la comparaison, et un `.txt` encore moins.
    """
    root = str(tmp_path)
    write(root, "http/exposure/foo-exposed.yaml", template("foo-exposed"))
    write(root, "http/exposure/bar-exposed.yml", template("bar-exposed"))
    write(root, "profiles/ai.yml", "info:\n  name: ai\n")
    write(root, "helpers/payloads/liste.txt", "foo-exposed\n")
    write(root, "README.md", "id: pas-un-template\n")

    assert set(pack_coverage.collect_ids(root)) == {"foo-exposed", "bar-exposed"}


def test_la_collecte_nomme_tous_les_fichiers_qui_portent_l_identifiant(tmp_path):
    root = str(tmp_path)
    write(root, "http/cves/2026/CVE-2026-0770.yaml", template("CVE-2026-0770"))
    write(root, "http/misconfiguration/langflow.yaml", template("CVE-2026-0770"))

    assert pack_coverage.collect_ids(root) == {
        "CVE-2026-0770": [
            os.path.join("http", "cves", "2026", "CVE-2026-0770.yaml"),
            os.path.join("http", "misconfiguration", "langflow.yaml"),
        ],
    }


def test_les_identifiants_du_pack_sont_ceux_des_noms_de_fichier():
    """
    Amarre l'outil au pack réel : ce qu'il lit sous `templates/` doit être la
    trentaine d'identifiants que le dépôt porte, chacun sous son propre nom.
    """
    found = pack_coverage.collect_ids(TEMPLATES_DIR)
    assert len(found) == len(PACK), "un template du pack n'a pas été vu"
    for template_id, paths in found.items():
        for path in paths:
            assert os.path.splitext(os.path.basename(path))[0] == template_id


def test_les_identifiants_du_pack_tiennent_dans_la_grammaire_de_nuclei():
    """
    C'est cette grammaire — segments alphanumériques joints par `-` ou `_` — qui
    autorise normalise() à ne rabattre que la casse et le séparateur. Si un
    identifiant du pack en sortait, la normalisation ne voudrait plus rien dire.
    """
    for template_id in pack_coverage.collect_ids(TEMPLATES_DIR):
        assert pack_coverage.NUCLEI_ID.match(template_id), template_id


# --------------------------------------------------------------------------
# Comparaison.

def two_trees(tmp_path, ours, theirs):
    pack, upstream = os.path.join(str(tmp_path), "pack"), os.path.join(str(tmp_path), "amont")
    for template_id, relative in ours:
        write(pack, relative, template(template_id))
    for template_id, relative in theirs:
        write(upstream, relative, template(template_id))
    return pack, upstream


def compare(pack, upstream):
    return pack_coverage.collisions(pack_coverage.collect_ids(pack),
                                    pack_coverage.collect_ids(upstream))


def test_l_identifiant_deja_porte_en_amont_est_signale(tmp_path):
    pack, upstream = two_trees(
        tmp_path,
        ours=[("CVE-2026-0770", "cves/CVE-2026-0770.yaml"),
              ("vllm-unauthenticated-api", "exposure/vllm-unauthenticated-api.yaml")],
        theirs=[("CVE-2026-0770", "http/cves/2026/CVE-2026-0770.yaml"),
                ("CVE-2021-44228", "http/cves/2021/CVE-2021-44228.yaml")],
    )

    found = compare(pack, upstream)

    assert [collision.pack_id for collision in found] == ["CVE-2026-0770"], (
        "vllm-unauthenticated-api n'existe pas en amont : le signaler ferait "
        "renoncer à un template que le pack est seul à porter"
    )
    assert found[0].ours == [os.path.join("cves", "CVE-2026-0770.yaml")]
    assert found[0].theirs == [os.path.join("http", "cves", "2026", "CVE-2026-0770.yaml")]


def test_rien_n_est_signale_quand_les_identifiants_different(tmp_path):
    pack, upstream = two_trees(
        tmp_path,
        ours=[("langserve-exposed-playground", "exposure/langserve-exposed-playground.yaml")],
        theirs=[("langserve-detect", "http/technologies/langserve-detect.yaml"),
                ("langflow-panel", "http/exposed-panels/langflow-panel.yaml")],
    )

    assert compare(pack, upstream) == []


def test_le_doublon_est_signale_a_la_casse_et_au_separateur_pres(tmp_path):
    """
    Le moteur compare les chaînes telles quelles et chargerait les deux sans
    broncher. Ce sont pourtant deux écritures du même nom — la grammaire ne
    distingue rien d'autre que les segments et ce qui les joint — et le pack n'a
    aucune raison de porter la seconde.
    """
    pack, upstream = two_trees(
        tmp_path,
        ours=[("ollama_unauthenticated_api", "exposure/ollama_unauthenticated_api.yaml")],
        theirs=[("Ollama-Unauthenticated-API", "http/misconfiguration/ollama.yaml")],
    )

    found = compare(pack, upstream)

    assert len(found) == 1
    assert found[0].pack_id == "ollama_unauthenticated_api"
    assert found[0].upstream_id == "Ollama-Unauthenticated-API"


def test_le_rapport_nomme_les_deux_fichiers_et_compte_les_deux_arbres(tmp_path):
    """
    Un rapport qui dirait « doublon » sans dire lequel, ni où, obligerait à
    refaire à la main le travail qu'on vient de lui demander.
    """
    pack, upstream = two_trees(
        tmp_path,
        ours=[("CVE-2026-0770", "cves/CVE-2026-0770.yaml"),
              ("qdrant-no-api-key", "exposure/qdrant-no-api-key.yaml")],
        theirs=[("CVE-2026-0770", "http/cves/2026/CVE-2026-0770.yaml")],
    )
    pack_ids, upstream_ids = pack_coverage.collect_ids(pack), pack_coverage.collect_ids(upstream)

    report = pack_coverage.format_report(pack_ids, upstream_ids, pack, upstream,
                                         pack_coverage.collisions(pack_ids, upstream_ids))

    assert "2 identifiants" in report and "1 identifiants" in report
    assert "1 doublon" in report and "2 doublons" not in report
    assert os.path.join("cves", "CVE-2026-0770.yaml") in report
    assert os.path.join("http", "cves", "2026", "CVE-2026-0770.yaml") in report
    assert "qdrant-no-api-key" not in report, "le rapport ne parle que des doublons"


def test_le_rapport_le_dit_quand_il_n_y_a_rien(tmp_path):
    pack, upstream = two_trees(
        tmp_path,
        ours=[("qdrant-no-api-key", "exposure/qdrant-no-api-key.yaml")],
        theirs=[("CVE-2021-44228", "http/cves/2021/CVE-2021-44228.yaml")],
    )
    pack_ids, upstream_ids = pack_coverage.collect_ids(pack), pack_coverage.collect_ids(upstream)

    report = pack_coverage.format_report(pack_ids, upstream_ids, pack, upstream, [])

    assert "aucun doublon." in report


# --------------------------------------------------------------------------
# Résolution de l'arbre amont : elle suit celle de nuclei, sinon l'outil compare
# le pack à un arbre que personne n'utilise.

@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    home = os.path.join(str(tmp_path), "home")
    os.makedirs(home)
    monkeypatch.setenv("HOME", home)
    monkeypatch.delenv(pack_coverage.NUCLEI_TEMPLATES_DIR_ENV, raising=False)
    monkeypatch.delenv(pack_coverage.NUCLEI_CONFIG_DIR_ENV, raising=False)
    return home


def test_l_amont_par_defaut_est_celui_de_nuclei(isolated_home):
    assert pack_coverage.resolve_upstream() == os.path.join(isolated_home, "nuclei-templates")


def test_l_amont_suit_le_chemin_retenu_par_nuclei_dans_sa_configuration(isolated_home):
    config = os.path.join(isolated_home, ".config", "nuclei")
    os.makedirs(config)
    with open(os.path.join(config, ".templates-config.json"), "w", encoding="utf-8") as handle:
        json.dump({"nuclei-templates-directory": "/srv/nuclei-templates"}, handle)

    assert pack_coverage.resolve_upstream() == "/srv/nuclei-templates"


def test_la_variable_d_environnement_passe_avant_la_configuration(isolated_home, monkeypatch):
    config = os.path.join(isolated_home, ".config", "nuclei")
    os.makedirs(config)
    with open(os.path.join(config, ".templates-config.json"), "w", encoding="utf-8") as handle:
        json.dump({"nuclei-templates-directory": "/srv/nuclei-templates"}, handle)
    monkeypatch.setenv(pack_coverage.NUCLEI_TEMPLATES_DIR_ENV, "/env/nuclei-templates")

    assert pack_coverage.resolve_upstream() == "/env/nuclei-templates"
    assert pack_coverage.resolve_upstream("/cli/nuclei-templates") == "/cli/nuclei-templates", (
        "l'argument de ligne de commande passe avant tout le reste"
    )


def test_une_configuration_illisible_ne_fait_pas_echouer_la_resolution(isolated_home):
    config = os.path.join(isolated_home, ".config", "nuclei")
    os.makedirs(config)
    with open(os.path.join(config, ".templates-config.json"), "w", encoding="utf-8") as handle:
        handle.write("{ ceci n'est pas du JSON")

    assert pack_coverage.resolve_upstream() == os.path.join(isolated_home, "nuclei-templates")


# --------------------------------------------------------------------------
# Ligne de commande.

def test_le_code_de_sortie_dit_le_verdict(tmp_path, capsys):
    pack, upstream = two_trees(
        tmp_path,
        ours=[("CVE-2026-0770", "cves/CVE-2026-0770.yaml")],
        theirs=[("CVE-2026-0770", "http/cves/2026/CVE-2026-0770.yaml")],
    )
    assert pack_coverage.main(["--pack", pack, "--upstream", upstream]) == 1

    propre, _ = two_trees(
        tmp_path,
        ours=[("qdrant-no-api-key", "propre/exposure/qdrant-no-api-key.yaml")],
        theirs=[],
    )
    propre = os.path.join(propre, "propre")
    assert pack_coverage.main(["--pack", propre, "--upstream", upstream]) == 0

    absent = os.path.join(str(tmp_path), "nulle-part")
    assert pack_coverage.main(["--pack", propre, "--upstream", absent]) == 2, (
        "un amont introuvable n'est pas un pack sans doublon : le confondre avec "
        "un succès ferait passer la porte à un template qui existe déjà"
    )
    assert "introuvable" in capsys.readouterr().err


def test_quiet_ne_parle_que_pour_signaler(tmp_path, capsys):
    pack, upstream = two_trees(
        tmp_path,
        ours=[("qdrant-no-api-key", "exposure/qdrant-no-api-key.yaml")],
        theirs=[("CVE-2021-44228", "http/cves/2021/CVE-2021-44228.yaml")],
    )

    assert pack_coverage.main(["--pack", pack, "--upstream", upstream, "--quiet"]) == 0
    assert capsys.readouterr().out == ""

    assert pack_coverage.main(["--pack", pack, "--upstream", upstream]) == 0
    assert "aucun doublon." in capsys.readouterr().out


def test_le_script_s_execute_en_ligne_de_commande(tmp_path):
    pack, upstream = two_trees(
        tmp_path,
        ours=[("CVE-2026-0770", "cves/CVE-2026-0770.yaml")],
        theirs=[("CVE-2026-0770", "http/cves/2026/CVE-2026-0770.yaml")],
    )

    run = subprocess.run(
        [sys.executable, SCRIPT, "--pack", pack, "--upstream", upstream],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )

    assert run.returncode == 1, run.stderr
    assert "CVE-2026-0770" in run.stdout
    assert "1 doublon" in run.stdout


# --------------------------------------------------------------------------
UPSTREAM = pack_coverage.resolve_upstream()


@pytest.mark.skipif(not os.path.isdir(UPSTREAM), reason="nuclei-templates absent")
def test_l_arbre_reel_de_nuclei_templates_se_lit_entierement():
    """
    Le seul test qui touche les treize mille fichiers de l'amont, et il ne juge
    pas le pack : il vérifie que la lecture les traverse sans s'étrangler sur un
    encodage ou sur un `.yml` qui n'est pas un template, et que ce qu'elle en
    tire tient dans la grammaire du moteur. Le verdict, lui, appartient à
    l'exploitant — 0 ou 1, selon ce que le pack porte au moment où on l'exécute.
    """
    upstream = pack_coverage.collect_ids(UPSTREAM)

    assert len(upstream) > 1000, "un arbre amont à jour porte des milliers de templates"
    for template_id in upstream:
        assert pack_coverage.NUCLEI_ID.match(template_id), template_id

    assert pack_coverage.main(["--quiet"]) in (0, 1)
