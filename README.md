# ai-infra-nuclei

Templates [nuclei](https://github.com/projectdiscovery/nuclei) pour les
**expositions d'infrastructure IA** — pas les CVE, les défauts de configuration.

## Pourquoi ce pack

Le dépôt officiel `nuclei-templates` est centré CVE. Or le risque dominant sur
l'infrastructure IA n'est pas une faille logicielle : c'est que **ces services
n'ont aucune authentification par défaut** et se retrouvent exposés en l'état.

Ollama, vLLM, ComfyUI, LangServe, Ray, MLflow, ChromaDB, Qdrant : aucun n'a
d'écran de connexion. Ils sont conçus pour tourner en local, sur un réseau de
confiance. Il suffit d'un `--host 0.0.0.0` pour que l'API de gestion complète
devienne publique — et c'est un réglage que tout le monde applique pour servir
une autre machine du réseau.

Couverture actuelle dans `nuclei-templates` au 2026-07-30 : LangServe 0 template,
ComfyUI 2, vLLM 3, Ollama 4. Face à des dizaines de milliers d'instances
exposées, c'est mince.

## Ce que couvre le pack

**Exposition** (`templates/exposure/`) — service atteignable sans
authentification, avec une preuve que l'API *répond*, pas seulement qu'un port
est ouvert.

**CVE** (`templates/cves/`) — vulnérabilités de l'écosystème IA sans template
amont.

## Usage

```bash
nuclei -t templates/ -u https://cible
nuclei -t templates/exposure/ -l cibles.txt -tags ai
```

## Règle de qualité

Un matcher doit **prouver l'exposition**, pas deviner. Un template qui ne teste
que le code HTTP 200 déclenche sur n'importe quel serveur vivant et n'a aucune
valeur — c'est le motif de rejet le plus fréquent en amont, et la suite de tests
le refuse (`test_matcher_is_not_status_only`).

Chaque template doit passer :

```bash
python3 -m pytest -q      # structure, sévérité, références, matchers
nuclei -validate -t templates/
```

## Contribuer

Les templates jugés bons sont ensuite proposés à
[`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates)
— ce pack sert d'antichambre, pas de silo.

## Portée

Détection en lecture seule. Aucun template n'exécute de charge utile, ne modifie
d'état, ni ne consomme de ressource au-delà d'une requête. À n'utiliser que sur
une infrastructure que vous possédez ou pour laquelle vous avez une autorisation
écrite.

## Licence

MIT
