#!/usr/bin/env python3
"""
Compare les identifiants du pack à ceux de `nuclei-templates`, et signale les
doublons.

Le pack est une antichambre : ce qu'il contient a vocation à être proposé en
amont. Un template dont l'identifiant existe déjà chez projectdiscovery n'a donc
rien à y apporter — et tant qu'il vit ici, il fait doublon au chargement, où deux
templates portant le même `id` se disputent la même ligne de résultat.

Usage :

    python3 scripts/coverage.py                      # amont résolu comme nuclei le résout
    python3 scripts/coverage.py --upstream CHEMIN
    python3 scripts/coverage.py --quiet              # ne parle que s'il y a un doublon

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

TEMPLATE_SUFFIXES = (".yaml", ".yml")

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


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Signale les identifiants du pack que nuclei-templates porte déjà.",
    )
    parser.add_argument("--pack", default=TEMPLATES_DIR,
                        help="arbre du pack (défaut : %(default)s)")
    parser.add_argument("--upstream", default=None,
                        help="arbre de nuclei-templates (défaut : celui de nuclei)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="ne rien écrire tant qu'aucun doublon n'est trouvé")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.pack):
        print("pack introuvable : %s" % args.pack, file=sys.stderr)
        return 2

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
