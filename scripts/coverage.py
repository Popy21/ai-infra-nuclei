#!/usr/bin/env python3
"""
Compare les identifiants du pack à ceux de `nuclei-templates`, signale les
doublons, et écrit le tableau de couverture du README.

Le pack est une antichambre : ce qu'il contient a vocation à être proposé en
amont. Un template dont l'identifiant existe déjà chez projectdiscovery n'a donc
rien à y apporter — et tant qu'il vit ici, il fait doublon au chargement, où deux
templates portant le même `id` se disputent la même ligne de résultat.

Le tableau du README répond à l'autre moitié de la question : non plus ce que
l'amont porte déjà, mais ce que le pack couvre — un produit, un template, une
sévérité. Il est écrit par cet outil plutôt que tenu à la main, parce qu'une
liste manuelle diverge au premier template ajouté et qu'un README qui ment sur
son propre contenu ne se relit plus. La suite de tests refuse le décalage.

Usage :

    python3 scripts/coverage.py                      # amont résolu comme nuclei le résout
    python3 scripts/coverage.py --upstream CHEMIN
    python3 scripts/coverage.py --quiet              # ne parle que s'il y a un doublon
    python3 scripts/coverage.py --markdown           # le tableau, sur la sortie standard
    python3 scripts/coverage.py --readme             # le tableau, dans README.md

Codes de sortie : 0 aucun doublon, 1 au moins un doublon, 2 arbre introuvable.
"""

import argparse
import collections
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(ROOT, "templates")
README_FILE = os.path.join(ROOT, "README.md")

TEMPLATE_SUFFIXES = (".yaml", ".yml")

# Les deux marqueurs bornent ce que --readme réécrit, et rien d'autre du fichier
# n'est touché : le README reste un texte qu'on rédige, avec un tableau qu'on
# régénère. Ce sont des commentaires HTML, donc invisibles au rendu Markdown.
TABLE_BEGIN = "<!-- couverture -->"
TABLE_END = "<!-- /couverture -->"
TABLE_HEADER = ("| Produit | Template | Sévérité |", "| --- | --- | --- |")

# `id` est une clé de premier niveau, donc une ligne qui commence en colonne 0 :
# ce qui est indenté appartient à un bloc — `info`, un matcher, le scalaire d'une
# description — et n'est pas l'identifiant du template. La valeur peut être nue,
# guillemetée, ou suivie d'un commentaire ; la grammaire que nuclei impose à un
# identifiant (voir NUCLEI_ID) n'y admet ni espace ni `#`, donc la lire ainsi ne
# perd rien de ce que le moteur, lui, accepterait.
#
# Lire la ligne plutôt que parser le document est un choix de coût : l'arbre
# amont pèse treize mille fichiers, que yaml.safe_load traverse en une minute
# quand la lecture directe met trois secondes. La correspondance des deux
# lectures est vérifiée sur le pack réel par la suite de tests, fichier par
# fichier — c'est elle qui autorise le raccourci, pas une supposition.
ID_LINE = re.compile(
    r"^id:[ \t]*(?:\"([^\"]*)\"|'([^']*)'|([^\s#]+))[ \t]*(?:#.*)?$",
    re.MULTILINE,
)

# `pkg/templates/parser_config.go` : un identifiant est une suite de segments
# alphanumériques, séparés par `-` ou `_`, et nuclei refuse le template qui n'y
# tient pas. C'est cette grammaire qui donne son sens à normalise().
NUCLEI_ID = re.compile(r"^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$")

# Résolution de l'arbre amont, dans l'ordre où nuclei la fait lui-même :
# l'argument de ligne de commande, puis NUCLEI_TEMPLATES_DIR (cmd/nuclei/main.go),
# puis le chemin retenu dans .templates-config.json, et pour finir le défaut
# $HOME/nuclei-templates (applyDefaultConfig, pkg/catalog/config/nucleiconfig.go).
NUCLEI_TEMPLATES_DIR_ENV = "NUCLEI_TEMPLATES_DIR"
NUCLEI_CONFIG_DIR_ENV = "NUCLEI_CONFIG_DIR"
TEMPLATES_CONFIG_FILE = ".templates-config.json"
TEMPLATES_CONFIG_KEY = "nuclei-templates-directory"
UPSTREAM_DIR_NAME = "nuclei-templates"

Collision = collections.namedtuple("Collision", "pack_id upstream_id ours theirs")
Covered = collections.namedtuple("Covered", "product template_id severity path")


def read_id(path):
    """
    Rend l'identifiant du template, ou None si le fichier n'en porte pas — c'est
    le cas des profils de `nuclei-templates` et de ses listes d'aide, qui sont
    des `.yml` sans en être.
    """
    with open(path, encoding="utf-8", errors="replace") as handle:
        match = ID_LINE.search(handle.read())
    if match is None:
        return None
    value = next(group for group in match.groups() if group is not None)
    return value or None


def collect_ids(root):
    """
    Associe à chaque identifiant rencontré sous `root` les chemins qui le
    portent, relatifs à `root`.

    Une liste plutôt qu'un chemin : rien n'interdit à deux fichiers de déclarer
    le même identifiant, et c'est précisément ce qu'un rapport de doublons doit
    pouvoir nommer.
    """
    found = {}
    for directory, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            if not name.endswith(TEMPLATE_SUFFIXES):
                continue
            path = os.path.join(directory, name)
            template_id = read_id(path)
            if template_id is None:
                continue
            found.setdefault(template_id, []).append(os.path.relpath(path, root))
    for paths in found.values():
        paths.sort()
    return found


def normalise(template_id):
    """
    Deux identifiants qui ne diffèrent que par la casse ou par le séparateur sont
    le même nom écrit deux fois : la grammaire de nuclei ne connaît que des
    segments alphanumériques et, pour les joindre, `-` ou `_`. Le moteur, lui,
    compare les chaînes telles quelles et ne les confondrait pas — raison de plus
    pour que le rapport le fasse, puisque personne ne veut de ces deux-là.
    """
    return template_id.lower().replace("_", "-")


def collisions(pack, upstream):
    """
    Les identifiants du pack que `nuclei-templates` porte déjà, triés par
    identifiant du pack.
    """
    index = {}
    for template_id, paths in upstream.items():
        index.setdefault(normalise(template_id), []).append((template_id, paths))

    found = []
    for template_id in sorted(pack):
        for upstream_id, theirs in sorted(index.get(normalise(template_id), [])):
            found.append(Collision(template_id, upstream_id, pack[template_id], theirs))
    return found


def nuclei_config_dirs():
    """
    nuclei écrit sa configuration dans le répertoire applicatif de la plate-forme
    — `~/Library/Application Support/nuclei` sur macOS, `~/.config/nuclei`
    ailleurs — sauf si NUCLEI_CONFIG_DIR la déplace. Les deux sont interrogés
    sans regarder la plate-forme : celui qui n'existe pas ne répond rien.
    """
    from_env = os.environ.get(NUCLEI_CONFIG_DIR_ENV)
    if from_env:
        return [from_env]
    home = os.path.expanduser("~")
    return [
        os.path.join(home, "Library", "Application Support", "nuclei"),
        os.path.join(home, ".config", "nuclei"),
    ]


def configured_upstream():
    """Le chemin que nuclei a retenu dans .templates-config.json, s'il y en a un."""
    for directory in nuclei_config_dirs():
        path = os.path.join(directory, TEMPLATES_CONFIG_FILE)
        try:
            with open(path, encoding="utf-8") as handle:
                configured = json.load(handle).get(TEMPLATES_CONFIG_KEY)
        except (OSError, ValueError):
            continue
        if configured:
            return configured
    return None


def resolve_upstream(explicit=None):
    if explicit:
        return os.path.expanduser(explicit)
    from_env = os.environ.get(NUCLEI_TEMPLATES_DIR_ENV)
    if from_env:
        return os.path.expanduser(from_env)
    configured = configured_upstream()
    if configured:
        return os.path.expanduser(configured)
    return os.path.join(os.path.expanduser("~"), UPSTREAM_DIR_NAME)


def format_report(pack, upstream, pack_dir, upstream_dir, found):
    lines = [
        "pack             : %d identifiants sous %s" % (len(pack), pack_dir),
        "nuclei-templates : %d identifiants sous %s" % (len(upstream), upstream_dir),
        "",
    ]
    if not found:
        lines.append("aucun doublon.")
        return "\n".join(lines)

    lines.append("%d doublon%s :" % (len(found), "s" if len(found) > 1 else ""))
    for collision in found:
        lines.append("")
        if collision.pack_id == collision.upstream_id:
            lines.append("  %s" % collision.pack_id)
        else:
            lines.append("  %s / %s (le même nom, à la casse et au séparateur près)"
                         % (collision.pack_id, collision.upstream_id))
        for path in collision.ours:
            lines.append("    ici    %s" % path)
        for path in collision.theirs:
            lines.append("    amont  %s" % path)
    return "\n".join(lines)


def read_templates(pack_dir):
    """
    Ce que le pack couvre, un template par entrée, trié par produit puis par
    identifiant — deux templates du même produit se lisent alors côte à côte.

    Ici on parse le document, là où read_id() se contente d'une ligne : le
    raccourci ne se justifiait que par les treize mille fichiers de l'amont, et
    le pack en compte trente. Surtout, le tableau a besoin de ce qui vit dans
    `info` — la sévérité, le produit — que seule une lecture du document rend
    sans le deviner à l'indentation.

    yaml n'est importé qu'ici : le rapport de doublons, lui, ne dépend que de la
    bibliothèque standard et doit pouvoir tourner ainsi.
    """
    import yaml

    covered = []
    for directory, dirs, files in os.walk(pack_dir):
        dirs.sort()
        for name in sorted(files):
            if not name.endswith(TEMPLATE_SUFFIXES):
                continue
            path = os.path.join(directory, name)
            with open(path, encoding="utf-8") as handle:
                document = yaml.safe_load(handle) or {}
            template_id = document.get("id")
            if not template_id:
                continue
            info = document.get("info") or {}
            metadata = info.get("metadata") or {}
            covered.append(Covered(
                # `metadata.product` n'est pas exigé par la porte de qualité du
                # pack : à défaut, l'identifiant nomme le produit aussi bien que
                # possible, plutôt que de laisser une case vide.
                metadata.get("product") or template_id,
                template_id,
                info.get("severity") or "",
                # Relatif à la racine, parce que c'est de là que le README lit
                # ses liens ; et en séparateurs POSIX, parce qu'un lien Markdown
                # écrit sous Windows doit rester cliquable ailleurs.
                os.path.relpath(path, ROOT).replace(os.sep, "/"),
            ))
    covered.sort(key=lambda entry: (entry.product, entry.template_id))
    return covered


def format_table(covered):
    """Le tableau de couverture, en Markdown, tel qu'il vit dans le README."""
    products = len({entry.product for entry in covered})
    lines = [
        "%d template%s, %d produit%s." % (len(covered), "s" if len(covered) > 1 else "",
                                          products, "s" if products > 1 else ""),
        "",
    ]
    lines.extend(TABLE_HEADER)
    for entry in covered:
        lines.append("| %s | [`%s`](%s) | %s |"
                     % (entry.product, entry.template_id, entry.path, entry.severity))
    return "\n".join(lines)


def replace_block(text, table):
    """
    Rend `text` où le bloc borné par les marqueurs porte `table`.

    L'absence de marqueur est une erreur et non une invitation à écrire le
    tableau à un endroit deviné : un README dont on ne sait pas où finit la
    prose n'est pas un fichier qu'un outil a le droit de réécrire.
    """
    begin = text.find(TABLE_BEGIN)
    end = text.find(TABLE_END, begin + len(TABLE_BEGIN)) if begin != -1 else -1
    if begin == -1 or end == -1:
        raise ValueError("marqueurs %s / %s introuvables" % (TABLE_BEGIN, TABLE_END))
    return text[:begin + len(TABLE_BEGIN)] + "\n" + table + "\n" + text[end:]


def write_readme(path, covered):
    """Écrit le tableau dans le README, et dit s'il a changé quelque chose."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    updated = replace_block(text, format_table(covered))
    if updated == text:
        return False
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(updated)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Signale les identifiants du pack que nuclei-templates porte "
                    "déjà, et écrit le tableau de couverture du README.",
    )
    parser.add_argument("--pack", default=TEMPLATES_DIR,
                        help="arbre du pack (défaut : %(default)s)")
    parser.add_argument("--upstream", default=None,
                        help="arbre de nuclei-templates (défaut : celui de nuclei)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="ne rien écrire tant qu'aucun doublon n'est trouvé")
    parser.add_argument("--markdown", action="store_true",
                        help="écrire le tableau de couverture sur la sortie standard")
    parser.add_argument("--readme", action="store_true",
                        help="écrire le tableau de couverture dans README.md")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.pack):
        print("pack introuvable : %s" % args.pack, file=sys.stderr)
        return 2

    # Le tableau ne dit que ce que le pack porte : il n'a pas besoin de l'amont,
    # et l'exiger empêcherait de régénérer le README sans avoir cloné treize
    # mille fichiers.
    if args.markdown or args.readme:
        covered = read_templates(args.pack)
        if args.markdown:
            print(format_table(covered))
        if args.readme:
            print("%s : %s" % (README_FILE, "tableau mis à jour"
                              if write_readme(README_FILE, covered) else "déjà à jour"))
        return 0

    upstream_dir = resolve_upstream(args.upstream)
    if not os.path.isdir(upstream_dir):
        print("nuclei-templates introuvable : %s\n"
              "cloner le dépôt, lancer `nuclei -update-templates`, ou passer "
              "--upstream / %s." % (upstream_dir, NUCLEI_TEMPLATES_DIR_ENV),
              file=sys.stderr)
        return 2

    pack = collect_ids(args.pack)
    upstream = collect_ids(upstream_dir)
    found = collisions(pack, upstream)

    if found or not args.quiet:
        print(format_report(pack, upstream, args.pack, upstream_dir, found))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
