"""
Porte de qualité du pack.

Un template qui passe ces tests est publiable ; un template qui les échoue ne doit
jamais être commité. C'est cette contrainte qui rend un commit automatique
significatif : sans elle, un commit ne prouve rien.
"""

import ast
import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import threading
import uuid

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


# --------------------------------------------------------------------------
# Un produit, un constat. Deux templates qui interrogent les mêmes routes du
# même produit déclenchent sur la même réponse : le rapport porte alors deux
# lignes pour un seul fait, et la seconde ne renseigne personne. Le pack tient
# déjà deux paires — les deux templates Ollama, les deux CVE Langflow — et
# elles valent parce que chacun garde une route que l'autre n'interroge pas :
# POST /api/pull contre GET /api/tags, POST /api/v1/validate/code contre POST
# /api/v1/responses. Une route peut donc être commune — les deux CVE Langflow
# lisent toutes deux /api/v1/version pour dater l'instance — mais elle ne peut
# pas être tout ce que les deux ont. C'est cette règle que la suite vérifie ici
# sur toutes les paires du pack, plutôt qu'à la main sur celle qu'on a en tête.

URL_PLACEHOLDER = re.compile(r"^\{\{[^}]*\}\}")


def normalise_route(method, target):
    """
    Rend le couple (méthode, chemin) d'une requête, hôte retiré.

    `{{BaseURL}}` et `{{RootURL}}` nomment la cible, pas l'endpoint. La barre
    finale, elle, appartient au produit — Django sert `/version/` là où FastAPI
    sert `/version` — mais elle ne sépare pas deux routes d'un même produit :
    deux templates qui écriraient la même à la barre près resteraient deux fois
    la même.
    """
    target = URL_PLACEHOLDER.sub("", str(target).strip())
    if not target.startswith("/"):
        target = "/" + target
    return str(method or "GET").upper(), target.rstrip("/") or "/"


def request_routes(doc):
    """
    Les routes qu'un template interroge.

    Les deux écritures du pack désignent les mêmes endpoints et doivent donc se
    lire pareil : sous `path` la méthode est portée par le bloc et vaut GET par
    défaut, sous `raw` chaque requête porte la sienne sur sa ligne de commande.
    """
    found = set()
    for block in doc.get("http") or []:
        for target in block.get("path") or []:
            found.add(normalise_route(block.get("method"), target))
        for raw in block.get("raw") or []:
            start_line = raw.strip().splitlines()[0].split()
            assert len(start_line) >= 2, f"requête brute illisible : {raw!r}"
            found.add(normalise_route(start_line[0], start_line[1]))
    return found


def distinguishable(ours, theirs):
    """Chacun des deux interroge-t-il une route que l'autre ignore ?"""
    return bool(ours - theirs) and bool(theirs - ours)


def test_no_two_templates_of_a_product_rest_on_the_same_endpoints():
    """
    Le couple (endpoint, produit) est ce qui identifie un constat : deux
    templates ne peuvent pas le partager, sans quoi le second ne fait que
    redire le premier sur la même réponse.
    """
    by_product = {}
    for path in ALL:
        doc = load(path)
        product = ((doc.get("info") or {}).get("metadata") or {}).get("product")
        assert product, (
            "info.metadata.product manquant : rien ne dit alors de quel produit "
            "le template parle, et le couple (endpoint, produit) ne peut pas "
            f"être vérifié — {rel(path)}"
        )
        routes = request_routes(doc)
        assert routes, (
            "aucune requête HTTP lisible : le lecteur ne connaît que `path` et "
            "`raw`, et un template dont il ne tire rien traverserait la "
            f"vérification sans être vérifié — {rel(path)}"
        )
        by_product.setdefault(product, []).append((rel(path), routes))

    for product, templates in sorted(by_product.items()):
        for index, (ours, our_routes) in enumerate(templates):
            for theirs, their_routes in templates[index + 1:]:
                assert distinguishable(our_routes, their_routes), (
                    f"{ours} et {theirs} couvrent {product} et aucun des deux "
                    "n'interroge de route que l'autre ignore : "
                    f"{sorted(our_routes)} contre {sorted(their_routes)}. Les "
                    "deux déclenchent sur la même réponse, et deux lignes pour "
                    "un seul fait n'en disent pas plus qu'une"
                )


# Les deux écritures d'une même requête, telles qu'elles cohabitent dans le
# pack : `path` quand le bloc n'a qu'une méthode, `raw` quand elles diffèrent.
# Un doublon peut très bien s'écrire de l'autre façon que celui qu'il double.
DUPLICATE_UNDER_PATH = {"http": [{"path": ["{{BaseURL}}/api/v1/version",
                                           "{{BaseURL}}/api/v1/flows"]}]}
DUPLICATE_UNDER_RAW = {"http": [{"raw": [
    "GET /api/v1/version HTTP/1.1\nHost: {{Hostname}}\n\n",
    "GET /api/v1/flows/ HTTP/1.1\nHost: {{Hostname}}\n\n",
]}]}


def test_the_endpoint_reader_reads_both_writings_alike():
    expected = {("GET", "/api/v1/version"), ("GET", "/api/v1/flows")}
    assert request_routes(DUPLICATE_UNDER_PATH) == expected, (
        "un bloc `path` sans méthode ne se lit pas comme le GET que nuclei "
        f"émet — {sorted(request_routes(DUPLICATE_UNDER_PATH))}"
    )
    assert request_routes(DUPLICATE_UNDER_RAW) == expected, (
        "un doublon écrit en `raw` passerait devant celui qu'il double, écrit "
        f"en `path` — {sorted(request_routes(DUPLICATE_UNDER_RAW))}"
    )


def test_the_endpoint_check_refuses_a_duplicate_and_admits_a_route_in_common():
    """
    La vérification ne dit quelque chose que si elle sait refuser. Le doublon :
    les mêmes routes des deux côtés, à l'écriture près. L'inclusion : tout ce
    que l'un interroge, l'autre l'interroge déjà. Et la forme que le pack
    admet, celle des deux CVE Langflow — une route en commun, mais chacun la
    sienne par ailleurs.
    """
    ours = request_routes(DUPLICATE_UNDER_PATH)
    theirs = request_routes(DUPLICATE_UNDER_RAW)
    assert not distinguishable(ours, theirs), (
        "deux templates qui interrogent les mêmes routes ne sont pas vus"
    )

    assert not distinguishable(ours, ours | {("POST", "/api/v1/run")}), (
        "un template dont l'autre interroge déjà toutes les routes n'est pas vu"
    )

    assert distinguishable(
        {("GET", "/api/v1/version"), ("POST", "/api/v1/validate/code")},
        {("GET", "/api/v1/version"), ("POST", "/api/v1/responses")},
    ), (
        "la vérification refuse la paire Langflow : elle interdirait la route "
        "de corroboration partagée, qui n'est pas le constat"
    )


# --------------------------------------------------------------------------
# Endpoint partagé : plusieurs runtimes parlent le protocole OpenAI et servent
# tous GET /v1/models. Un matcher qui se contente de la forme générique
# {"object":"list","data":[...]} déclenche sur tous à la fois. Ces deux corps
# gardent le discriminant produit du template vLLM.

VLLM_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "vllm-unauthenticated-api.yaml")

# Réponse de vLLM, telle que FastAPI sérialise ModelList/ModelCard.
VLLM_MODELS_BODY = (
    '{"object":"list","data":[{"id":"meta-llama/Llama-3.1-8B-Instruct",'
    '"object":"model","created":1753900000,"owned_by":"vllm",'
    '"root":"meta-llama/Llama-3.1-8B-Instruct","parent":null,'
    '"max_model_len":131072,"permission":[{"id":"modelperm-4f1c",'
    '"object":"model_permission","created":1753900000,'
    '"allow_sampling":true}]}]}'
)

# Même endpoint, même forme, autre produit : le template ne doit pas déclencher.
OTHER_OPENAI_API_BODY = (
    '{"object":"list","data":[{"id":"gpt-4o","object":"model",'
    '"created":1753900000,"owned_by":"openai"}]}'
)


def word_matcher_hits(matcher, body):
    """Sémantique nuclei d'un matcher `word` : condition `or` par défaut."""
    words = matcher.get("words") or []
    if matcher.get("condition") == "and":
        return all(w in body for w in words)
    return any(w in body for w in words)


def test_vllm_matcher_distinguishes_vllm_from_other_openai_apis():
    doc = load(VLLM_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v1/models" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /v1/models"

    block = blocks[0]
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, VLLM_MODELS_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /v1/models de vLLM"
    )
    assert not all(word_matcher_hits(m, OTHER_OPENAI_API_BODY) for m in body_matchers), (
        "le template déclenche sur une API compatible OpenAI qui n'est pas vLLM"
    )


# --------------------------------------------------------------------------
# Endpoint générique : /info est un nom banal et "model_id" une clé banale. La
# signature du template TGI doit tenir aux paramètres du routeur, pas au seul
# nom du modèle — sinon toute passerelle d'inférence servant /info déclenche.

TGI_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                            "text-generation-inference-exposed.yaml")

# Réponse du routeur TGI, telle qu'axum sérialise la struct Info.
TGI_INFO_BODY = (
    '{"model_id":"meta-llama/Llama-3.1-8B-Instruct",'
    '"model_sha":"0e9e39f249a16976918f6564b8830bc894c89659",'
    '"model_pipeline_tag":"text-generation","max_concurrent_requests":128,'
    '"max_best_of":2,"max_stop_sequences":4,"max_input_tokens":4095,'
    '"max_total_tokens":4096,"max_batch_total_tokens":16000,'
    '"max_waiting_tokens":20,"max_batch_size":null,"validation_workers":2,'
    '"max_client_batch_size":4,"version":"3.3.4","sha":null,'
    '"docker_label":null}'
)

# Une autre passerelle d'inférence sert /info et nomme aussi son modèle
# model_id : même endpoint, même clé, autre produit.
OTHER_INFO_BODY = (
    '{"model_id":"meta-llama/Llama-3.1-8B-Instruct","backend":"triton",'
    '"version":"1.2.0","max_batch_size":8}'
)

# /info d'un service qui n'a rien à voir avec l'inférence.
ACTUATOR_INFO_BODY = (
    '{"app":{"name":"billing-api","version":"4.1.0"},'
    '"git":{"branch":"main","commit":{"id":"9f3c1ab"}}}'
)


def test_tgi_matcher_needs_router_parameters_not_just_model_id():
    doc = load(TGI_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/info" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /info"

    block = blocks[0]
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, TGI_INFO_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /info du routeur TGI"
    )
    assert not all(word_matcher_hits(m, OTHER_INFO_BODY) for m in body_matchers), (
        "le template déclenche sur une passerelle d'inférence qui n'est pas TGI"
    )
    assert not all(word_matcher_hits(m, ACTUATOR_INFO_BODY) for m in body_matchers), (
        "le template déclenche sur un /info sans rapport avec l'inférence"
    )


# --------------------------------------------------------------------------
# LM Studio parle aussi le protocole OpenAI, donc /v1/models ne le distingue de
# rien. Le template doit se poser sur /api/v0/models, l'API propre au produit, et
# sa signature doit tenir aux clés de la bibliothèque locale — sinon il déclenche
# sur les autres runtimes déjà couverts par le pack.

LMSTUDIO_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "lmstudio-server-exposed.yaml")

# Réponse de l'API REST de LM Studio : un modèle chargé, un modèle présent mais
# non chargé.
LMSTUDIO_MODELS_BODY = (
    '{"data":[{"id":"qwen2.5-7b-instruct","object":"model","type":"llm",'
    '"publisher":"lmstudio-community","arch":"qwen2",'
    '"compatibility_type":"gguf","quantization":"Q4_K_M","state":"loaded",'
    '"max_context_length":32768,"loaded_context_length":4096},'
    '{"id":"text-embedding-nomic-embed-text-v1.5","object":"model",'
    '"type":"embeddings","publisher":"nomic-ai","arch":"nomic-bert",'
    '"compatibility_type":"gguf","quantization":"Q4_0","state":"not-loaded",'
    '"max_context_length":2048}],"object":"list"}'
)


def test_lmstudio_matcher_targets_the_product_api_not_openai_compat():
    doc = load(LMSTUDIO_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/v0/models" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /api/v0/models — /v1/models est partagé "
        "par tous les serveurs compatibles OpenAI et ne désigne pas LM Studio"
    )

    block = blocks[0]
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, LMSTUDIO_MODELS_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /api/v0/models de LM Studio"
    )
    assert not all(word_matcher_hits(m, OTHER_OPENAI_API_BODY) for m in body_matchers), (
        "le template déclenche sur une API compatible OpenAI qui n'est pas LM Studio"
    )
    # Collision interne au pack : deux templates ne doivent pas revendiquer la
    # même instance.
    assert not all(word_matcher_hits(m, VLLM_MODELS_BODY) for m in body_matchers), (
        "le template déclenche sur vLLM, déjà couvert par son propre template"
    )


# --------------------------------------------------------------------------
# SGLang décrit son modèle sous /get_model_info. Le corps a gagné des clés au fil
# des versions : s'appuyer sur les plus récentes raterait les instances
# anciennes, or ce sont elles qui traînent exposées. La signature doit donc tenir
# aux seules clés que toutes les versions sérialisent, sans pour autant se
# réduire à "model_path", qui ne désigne aucun produit.

SGLANG_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "sglang-server-exposed.yaml")

# Réponse d'une version récente : le dict complet.
SGLANG_MODEL_INFO_BODY = (
    '{"model_path":"meta-llama/Llama-3.1-8B-Instruct",'
    '"tokenizer_path":"meta-llama/Llama-3.1-8B-Instruct",'
    '"is_generation":true,"preferred_sampling_params":null,'
    '"weight_version":"default"}'
)

# Même endpoint sur une version plus ancienne : seules model_path et
# is_generation sont sérialisées. Le template doit toujours reconnaître celle-ci.
SGLANG_OLD_MODEL_INFO_BODY = (
    '{"model_path":"meta-llama/Llama-3.1-8B-Instruct","is_generation":true}'
)

# Une autre pile de service nomme aussi ses poids model_path et son tokenizer
# tokenizer_path : ces deux clés seules ne prouvent donc rien.
OTHER_MODEL_INFO_BODY = (
    '{"model_path":"/models/llama-3.1-8b","tokenizer_path":"/models/llama-3.1-8b",'
    '"backend":"triton","version":"1.2.0","max_batch_size":8}'
)


def test_sglang_matcher_holds_across_versions_without_becoming_generic():
    doc = load(SGLANG_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/get_model_info" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /get_model_info"

    block = blocks[0]
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, SGLANG_MODEL_INFO_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /get_model_info de SGLang"
    )
    assert all(word_matcher_hits(m, SGLANG_OLD_MODEL_INFO_BODY)
               for m in body_matchers), (
        "le template exige des clés absentes des versions plus anciennes de "
        "SGLang — il raterait les instances qui traînent exposées"
    )
    assert not all(word_matcher_hits(m, OTHER_MODEL_INFO_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une pile de service qui n'est pas SGLang : "
        "model_path et tokenizer_path sont des clés banales"
    )
    # Collision interne au pack : /info du routeur TGI décrit lui aussi le modèle
    # servi, et les deux templates ne doivent pas revendiquer la même instance.
    assert not all(word_matcher_hits(m, TGI_INFO_BODY) for m in body_matchers), (
        "le template déclenche sur TGI, déjà couvert par son propre template"
    )


# --------------------------------------------------------------------------
# Au-delà de la lecture. /api/tags prouve qu'Ollama répond, pas que les routes
# mutantes sont ouvertes : un proxy placé devant peut ne laisser passer que la
# lecture. Le template doit donc interroger /api/pull lui-même — et le faire sans
# provoquer le téléchargement qu'il signale, sinon il devient l'abus qu'il
# détecte.

OLLAMA_PULL_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                    "ollama-model-pull-abuse.yaml")

# Refus de validation d'une version récente : le nom passe par model.ParseName.
OLLAMA_PULL_INVALID_NAME_BODY = '{"error":"invalid model name"}'

# Même refus sur une version antérieure à ce passage, avec l'ancien message.
OLLAMA_PULL_OLD_REQUIRED_BODY = '{"error":"model is required"}'

# Premier événement du flux de progression quand un pull démarre réellement.
# Reconnaître ce corps voudrait dire rapporter un téléchargement déclenché par le
# template lui-même.
OLLAMA_PULL_PROGRESS_BODY = '{"status":"pulling manifest"}'

# 400 générique — proxy, passerelle ou service quelconque servant le même chemin.
GENERIC_BAD_REQUEST_BODY = '{"error":"Bad Request"}'


def ollama_pull_block():
    doc = load(OLLAMA_PULL_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/pull" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas /api/pull — /api/tags est déjà couvert par "
        "ollama-unauthenticated-api.yaml et ne prouve rien des routes mutantes"
    )
    return blocks[0]


def test_ollama_pull_probe_cannot_trigger_a_download():
    block = ollama_pull_block()

    assert block.get("method") == "POST", (
        "/api/pull n'est servi qu'en POST : autre chose ne prouve pas que la "
        "route est atteignable"
    )

    sent = json.loads(block.get("body") or "null")
    assert isinstance(sent, dict), "le corps envoyé n'est pas un objet JSON"
    name = str(sent.get("model") or sent.get("name") or "")
    assert not name.strip(), (
        f"le corps envoie un nom de modèle exploitable ({name!r}) : Ollama "
        "sortirait vers le registre et commencerait à télécharger des poids"
    )

    statuses = [s for m in (block.get("matchers") or [])
                if m.get("type") == "status"
                for s in (m.get("status") or [])]
    assert 400 in statuses, (
        "le refus de validation est un 400 : sans lui le template ne prouve "
        "pas que le handler a désérialisé la requête"
    )
    assert 200 not in statuses, (
        "un 200 sur /api/pull signifie que le téléchargement a commencé — "
        "l'accepter serait rapporter une consommation causée par le template"
    )


def test_ollama_pull_matcher_holds_across_versions_without_becoming_generic():
    block = ollama_pull_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la preuve du refus "
        "peut être court-circuitée par le seul code de statut"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, OLLAMA_PULL_INVALID_NAME_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas le refus de validation d'/api/pull"
    )
    assert all(word_matcher_hits(m, OLLAMA_PULL_OLD_REQUIRED_BODY)
               for m in body_matchers), (
        "le template n'accepte que la formulation récente du refus — il "
        "raterait les instances anciennes, précisément celles qui traînent "
        "exposées"
    )
    assert not all(word_matcher_hits(m, OLLAMA_PULL_PROGRESS_BODY)
                   for m in body_matchers), (
        "le template reconnaît le flux de progression d'un pull en cours : il "
        "rapporterait un téléchargement qu'il a lui-même déclenché"
    )
    assert not all(word_matcher_hits(m, GENERIC_BAD_REQUEST_BODY)
                   for m in body_matchers), (
        "le template déclenche sur un 400 générique : n'importe quel proxy "
        "servant ce chemin suffirait à le faire remonter"
    )


# --------------------------------------------------------------------------
# /system_stats décrit une machine à GPU, et ce vocabulaire n'appartient à
# personne : "system", "devices", "os", "vram_total", "python_version" sont ce
# qu'écrirait n'importe quelle sonde de supervision maison. La signature du
# template ComfyUI doit donc tenir à des clés que le produit seul sérialise, tout
# en restant sur celles que toutes les versions émettent — exiger
# "comfyui_version" raterait les instances anciennes.

COMFYUI_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "comfyui-unauthenticated.yaml")

# Réponse d'une version récente : le dict complet, argv compris.
COMFYUI_SYSTEM_STATS_BODY = (
    '{"system":{"os":"posix","ram_total":67260375040,"ram_free":31234567890,'
    '"comfyui_version":"0.3.44","required_frontend_version":"1.23.4",'
    '"python_version":"3.12.4 (main, Jun  7 2024, 06:33:07) [GCC 12.2.0]",'
    '"pytorch_version":"2.7.1+cu126","embedded_python":false,'
    '"argv":["main.py","--listen","0.0.0.0","--output-directory","/srv/out"]},'
    '"devices":[{"name":"cuda:0 NVIDIA GeForce RTX 4090 : cudaMallocAsync",'
    '"type":"cuda","index":0,"vram_total":25757220864,"vram_free":24696061952,'
    '"torch_vram_total":1073741824,"torch_vram_free":58720256}]}'
)

# Même endpoint sur une version antérieure : ni comfyui_version, ni les versions
# de PyTorch et du frontend, ni la mémoire de l'hôte, ni argv. Le template doit
# toujours reconnaître celle-ci.
COMFYUI_OLD_SYSTEM_STATS_BODY = (
    '{"system":{"os":"posix",'
    '"python_version":"3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]",'
    '"embedded_python":false},'
    '"devices":[{"name":"cuda:0 NVIDIA GeForce RTX 3090 : cudaMallocAsync",'
    '"type":"cuda","index":0,"vram_total":25438126080,"vram_free":24216764416,'
    '"torch_vram_total":1073741824,"torch_vram_free":50331648}]}'
)

# Une sonde de supervision GPU quelconque : elle emploie tout le vocabulaire
# générique de /system_stats — system, devices, os, python_version, vram_total,
# vram_free, jusqu'à une version — sans être ComfyUI. Ces clés seules ne prouvent
# donc rien.
OTHER_GPU_STATS_BODY = (
    '{"system":{"os":"posix","python_version":"3.11.9","hostname":"gpu-node-04"},'
    '"devices":[{"name":"NVIDIA A100-SXM4-40GB","type":"cuda","index":0,'
    '"vram_total":42949672960,"vram_free":41003286528}],"version":"2.4.1"}'
)


def test_comfyui_matcher_rests_on_product_keys_not_generic_gpu_stats():
    doc = load(COMFYUI_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/system_stats" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /system_stats"

    block = blocks[0]
    assert block.get("method") == "GET", (
        "/system_stats se lit en GET : le template ne doit rien envoyer à une "
        "instance qu'il découvre"
    )
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, COMFYUI_SYSTEM_STATS_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /system_stats de ComfyUI"
    )
    assert all(word_matcher_hits(m, COMFYUI_OLD_SYSTEM_STATS_BODY)
               for m in body_matchers), (
        "le template exige des clés absentes des versions plus anciennes de "
        "ComfyUI — comfyui_version notamment — il raterait les instances qui "
        "traînent exposées"
    )
    assert not all(word_matcher_hits(m, OTHER_GPU_STATS_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une sonde de supervision GPU qui n'est pas "
        "ComfyUI : system, devices et vram_total sont des clés banales"
    )
    # Collisions internes au pack : ces corps décrivent eux aussi la machine ou le
    # modèle servi, et deux templates ne doivent pas revendiquer la même instance.
    for other_body in (TGI_INFO_BODY, SGLANG_MODEL_INFO_BODY):
        assert not all(word_matcher_hits(m, other_body) for m in body_matchers), (
            "le template déclenche sur un runtime déjà couvert par son propre "
            "template"
        )


# --------------------------------------------------------------------------
# LangServe n'est qu'une greffe de routes sur FastAPI : sa documentation est
# celle de FastAPI, donc /docs ne renvoie que la coquille Swagger UI commune à
# toutes les applications du framework. La preuve doit se lire dans le document
# que cette page charge, et tenir aux routes que add_routes greffe — sans jamais
# appeler /invoke, qui ferait tourner la chaîne aux frais de l'exploitant.

LANGSERVE_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                  "langserve-exposed-playground.yaml")

# Document d'une application langchain-cli : la chaîne est montée sous un
# préfixe, cas de loin le plus courant.
LANGSERVE_OPENAPI_BODY = (
    '{"openapi":"3.1.0","info":{"title":"LangChain Server","version":"1.0",'
    '"description":"Spin up a simple api server using LangChain Runnable '
    'interfaces"},"paths":{'
    '"/ma-chaine/invoke":{"post":{"summary":"Invoke",'
    '"operationId":"invoke_ma_chaine_invoke_post"}},'
    '"/ma-chaine/batch":{"post":{"summary":"Batch"}},'
    '"/ma-chaine/stream":{"post":{"summary":"Stream"}},'
    '"/ma-chaine/stream_log":{"post":{"summary":"Stream Log"}},'
    '"/ma-chaine/input_schema":{"get":{"summary":"Input Schema"}},'
    '"/ma-chaine/output_schema":{"get":{"summary":"Output Schema"}},'
    '"/ma-chaine/config_schema":{"get":{"summary":"Config Schema"}}},'
    '"components":{"schemas":{"MaChaineInvokeRequest":{"type":"object"}}}}'
)

# Même produit, montage à la racine : les routes n'ont plus de préfixe. Une
# instance plus ancienne, sans /astream_events ni /feedback.
LANGSERVE_ROOT_OPENAPI_BODY = (
    '{"openapi":"3.0.2","info":{"title":"FastAPI","version":"0.1.0"},"paths":{'
    '"/invoke":{"post":{"summary":"Invoke"}},'
    '"/batch":{"post":{"summary":"Batch"}},'
    '"/stream":{"post":{"summary":"Stream"}},'
    '"/stream_log":{"post":{"summary":"Stream Log"}},'
    '"/input_schema":{"get":{"summary":"Input Schema"}},'
    '"/output_schema":{"get":{"summary":"Output Schema"}},'
    '"/config_schema":{"get":{"summary":"Config Schema"}}}}'
)

# Une passerelle de fonctions quelconque : elle sert /docs, elle sert
# /openapi.json, et elle a bien une route /invoke. "invoke" est un mot banal, il
# ne désigne aucun produit à lui seul.
OTHER_FASTAPI_OPENAPI_BODY = (
    '{"openapi":"3.1.0","info":{"title":"functions-runner","version":"2.3.0"},'
    '"paths":{"/invoke":{"post":{"summary":"Invoke Function",'
    '"operationId":"invoke_invoke_post"}},'
    '"/healthz":{"get":{"summary":"Healthz"}},'
    '"/config":{"get":{"summary":"Config"}}}}'
)

# Collision interne au pack : les runtimes déjà couverts sont eux aussi des
# applications FastAPI et servent donc le même /openapi.json.
VLLM_OPENAPI_BODY = (
    '{"openapi":"3.1.0","info":{"title":"FastAPI","version":"0.1.0"},"paths":{'
    '"/health":{"get":{"summary":"Health"}},'
    '"/v1/models":{"get":{"summary":"Show Available Models"}},'
    '"/v1/completions":{"post":{"summary":"Create Completion"}},'
    '"/v1/chat/completions":{"post":{"summary":"Create Chat Completion"}},'
    '"/tokenize":{"post":{"summary":"Tokenize"}}}}'
)


def langserve_openapi_block():
    doc = load(LANGSERVE_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/openapi.json" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /openapi.json — /docs ne renvoie que la "
        "coquille Swagger UI, identique pour toute application FastAPI, et ne "
        "désigne donc pas LangServe"
    )
    return blocks[0]


def test_langserve_probe_never_runs_the_chain():
    doc = load(LANGSERVE_TEMPLATE)

    assert langserve_openapi_block().get("method") == "GET", (
        "le document de documentation se lit en GET : le template ne doit rien "
        "envoyer à une instance qu'il découvre"
    )

    for block in (doc.get("http") or []):
        paths = block.get("path") or []
        assert not (block.get("method") == "POST"
                    and any("/invoke" in p for p in paths)), (
            "le template appelle /invoke : la chaîne tournerait vraiment, donc "
            "le template consommerait le quota du fournisseur de modèle sur le "
            "compte de l'exploitant — c'est l'abus qu'il est censé signaler"
        )


def test_langserve_matcher_rests_on_runnable_routes_not_on_fastapi_shape():
    block = langserve_openapi_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, LANGSERVE_OPENAPI_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas le document d'une application LangServe"
    )
    assert all(word_matcher_hits(m, LANGSERVE_ROOT_OPENAPI_BODY)
               for m in body_matchers), (
        "le template n'accepte que les chaînes montées sous un préfixe, ou "
        "exige des routes absentes des versions plus anciennes — il raterait "
        "les instances qui traînent exposées"
    )
    assert not all(word_matcher_hits(m, OTHER_FASTAPI_OPENAPI_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une passerelle de fonctions qui n'est pas "
        "LangServe : /invoke est un nom de route banal"
    )
    assert not all(word_matcher_hits(m, VLLM_OPENAPI_BODY)
                   for m in body_matchers), (
        "le template déclenche sur vLLM, déjà couvert par son propre template : "
        "tous ces runtimes sont des applications FastAPI et servent le même "
        "/openapi.json"
    )


# --------------------------------------------------------------------------
# L'index des flux de Flowise est un tableau d'objets nommés, datés et marqués
# déployés : la forme même que sert n'importe quel constructeur de flux. La
# signature doit donc tenir aux colonnes de l'entité ChatFlow, et aux plus
# anciennes d'entre elles — exiger "chatbotConfig", "analytic" ou "category",
# ajoutées au fil des versions, raterait les instances anciennes. Et parce que
# le voisinage de cet endpoint est dangereux, le template ne doit toucher ni la
# route de prédiction ni celle des identifiants.

FLOWISE_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "flowise-unauthenticated-api.yaml")

# Réponse d'une version récente : le graphe est réencodé en chaîne JSON dans
# flowData, et l'enregistrement porte les colonnes ajoutées après coup.
FLOWISE_CHATFLOWS_BODY = (
    '[{"id":"6f1a9c40-3b7e-4d21-9a0c-1f8e5b2d7c33","name":"Support RAG",'
    '"flowData":"{\\"nodes\\":[{\\"id\\":\\"chatOpenAI_0\\",\\"data\\":'
    '{\\"inputs\\":{\\"credential\\":\\"b2c4e1a8-77d9-4f13-8e60-9a3c5d0b6e21\\",'
    '\\"modelName\\":\\"gpt-4o-mini\\"}}}],\\"edges\\":[]}",'
    '"deployed":true,"isPublic":true,"apikeyid":null,'
    '"chatbotConfig":"{\\"welcomeMessage\\":\\"Bonjour\\"}","apiConfig":null,'
    '"analytic":null,"speechToText":null,"followUpPrompts":null,'
    '"category":"support","type":"CHATFLOW",'
    '"createdDate":"2026-05-12T09:14:22.000Z",'
    '"updatedDate":"2026-07-02T16:41:08.000Z"}]'
)

# Même endpoint sur une version antérieure : ni chatbotConfig, ni analytic, ni
# speechToText, ni category, ni type. Le template doit toujours la reconnaître.
FLOWISE_OLD_CHATFLOWS_BODY = (
    '[{"id":"9b1c7e52-0a44-4c8b-b3d6-2e7f1a904d15","name":"demo",'
    '"flowData":"{\\"nodes\\":[],\\"edges\\":[]}",'
    '"deployed":false,"isPublic":false,"apikeyid":null,'
    '"createdDate":"2024-02-03T11:02:44.000Z",'
    '"updatedDate":"2024-02-03T11:09:12.000Z"}]'
)

# Une plateforme d'automatisation quelconque énumère elle aussi des flux nommés,
# datés, déployés et publics ou non : ce vocabulaire n'appartient à personne.
OTHER_FLOW_PLATFORM_BODY = (
    '[{"id":42,"name":"Nightly sync","description":"ETL nocturne",'
    '"deployed":true,"isPublic":false,'
    '"nodes":[{"id":"http_1","type":"http"}],"edges":[],'
    '"createdDate":"2026-01-08T10:00:00.000Z",'
    '"updatedDate":"2026-03-19T08:30:00.000Z"}]'
)

# Un éditeur de graphes bâti sur la même bibliothèque de rendu enregistre sa
# scène sous flowData : cette clé seule ne prouve donc rien.
OTHER_GRAPH_EDITOR_BODY = (
    '[{"id":7,"name":"parcours-client",'
    '"flowData":"{\\"nodes\\":[],\\"edges\\":[],'
    '\\"viewport\\":{\\"x\\":0,\\"y\\":0,\\"zoom\\":1}}",'
    '"owner":"marketing","createdAt":"2026-04-01T12:00:00.000Z"}]'
)


def flowise_chatflows_block():
    doc = load(FLOWISE_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/v1/chatflows" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /api/v1/chatflows"
    return blocks[0]


def test_flowise_probe_only_reads_the_chatflow_index():
    doc = load(FLOWISE_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method") == "GET", (
            "l'index des flux se lit en GET : le template ne doit rien envoyer "
            "à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            assert "/prediction" not in path, (
                "le template appelle la route de prédiction : le flux "
                "tournerait vraiment, donc le template consommerait le quota du "
                "fournisseur de modèle sur le compte de l'exploitant — c'est "
                "l'abus qu'il est censé signaler"
            )
            assert "/credentials" not in path, (
                "le template lit la route des identifiants, qui les renvoie "
                "déchiffrés : il exfiltrerait le secret qu'il est censé "
                "signaler"
            )


def test_flowise_matcher_rests_on_chatflow_columns_not_on_flow_list_shape():
    block = flowise_chatflows_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, FLOWISE_CHATFLOWS_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /api/v1/chatflows de Flowise"
    )
    assert all(word_matcher_hits(m, FLOWISE_OLD_CHATFLOWS_BODY)
               for m in body_matchers), (
        "le template exige des colonnes absentes des versions plus anciennes de "
        "Flowise — chatbotConfig, analytic ou category — il raterait les "
        "instances qui traînent exposées"
    )
    assert not all(word_matcher_hits(m, OTHER_FLOW_PLATFORM_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une plateforme d'automatisation qui n'est "
        "pas Flowise : nom, date et drapeau de déploiement sont la forme "
        "commune de toute liste de flux"
    )
    assert not all(word_matcher_hits(m, OTHER_GRAPH_EDITOR_BODY)
                   for m in body_matchers), (
        "le template déclenche sur un éditeur de graphes qui n'est pas "
        "Flowise : flowData seul ne désigne aucun produit"
    )


# --------------------------------------------------------------------------
# Xinference expose deux façons de parler de ses modèles, et une seule tient :
# /v1/models ne liste que les modèles chargés — vide sur une instance au repos,
# et de la forme OpenAI que trois autres templates du pack revendiquent déjà —
# tandis que le registre énumère les familles livrées avec le paquet, donc
# répond peuplé même à vide. Sa réponse non détaillée ne porte que deux clés :
# la signature doit tenir à celles-là, sans exiger le détail qui coûterait un
# parcours de disque à l'exploitant, et sans jamais toucher les verbes qui
# lancent un modèle.

XINFERENCE_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "xinference-exposed.yaml")

# Réponse du registre : catalogue intégré, plus un modèle enregistré par
# l'exploitant. Forme inchangée depuis la version 0.11.
XINFERENCE_REGISTRATIONS_BODY = (
    '[{"model_name":"deepseek-v3","is_builtin":true},'
    '{"model_name":"llama-3.1-instruct","is_builtin":true},'
    '{"model_name":"support-rag-ft","is_builtin":false},'
    '{"model_name":"qwen2.5-instruct","is_builtin":true}]'
)

# Même endpoint avec ?detailed=true : les familles sont rendues entières. Le
# template ne demande pas ce détail, mais reconnaître cette forme-là ne coûte
# rien et couvre une instance derrière un proxy qui ajoute le paramètre.
XINFERENCE_DETAILED_REGISTRATIONS_BODY = (
    '[{"version":2,"model_name":"qwen2.5-instruct",'
    '"model_lang":["en","zh"],"model_ability":["generate","chat"],'
    '"model_description":"Qwen2.5 is the latest series of Qwen large language models.",'
    '"model_family":"qwen2.5-instruct","is_builtin":true,'
    '"model_specs":[{"model_format":"pytorch","model_size_in_billions":7,'
    '"quantizations":["none"],"model_hub":"huggingface",'
    '"cache_status":false}],"model_version_count":6,'
    '"model_instance_count":0}]'
)

# Une autre passerelle d'inférence énumère elle aussi son catalogue et nomme son
# modèle model_name : cette clé seule ne désigne aucun produit.
OTHER_MODEL_CATALOG_BODY = (
    '[{"model_name":"llama-3.1-8b-instruct","backend":"triton",'
    '"state":"READY","version":"1"},'
    '{"model_name":"bge-m3","backend":"onnxruntime","state":"READY",'
    '"version":"2"}]'
)

# Un registre d'extensions quelconque distingue lui aussi ce qu'il livre de ce
# que l'exploitant a ajouté : is_builtin seul ne prouve rien non plus.
OTHER_BUILTIN_REGISTRY_BODY = (
    '[{"name":"http-request","is_builtin":true,"enabled":true},'
    '{"name":"crm-connector","is_builtin":false,"enabled":true}]'
)


def xinference_registrations_block():
    doc = load(XINFERENCE_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any("/v1/model_registrations" in p for p in (b.get("path") or []))]
    assert blocks, (
        "le template ne vise pas le registre de modèles — /v1/models ne liste "
        "que les modèles chargés, donc renvoie une liste vide sur une instance "
        "au repos, et sa forme OpenAI est déjà revendiquée par les templates "
        "vLLM, SGLang et LM Studio"
    )
    return blocks[0]


def test_xinference_probe_never_launches_nor_registers_a_model():
    doc = load(XINFERENCE_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method") == "GET", (
            "le registre se lit en GET : le même chemin en POST enregistre un "
            "modèle, et POST /v1/models en lance un — le template déclencherait "
            "le téléchargement de poids et occuperait le GPU qu'il est censé "
            "signaler"
        )
        for path in (block.get("path") or []):
            assert "detailed=true" not in path, (
                "le template demande le catalogue détaillé : Xinference "
                "contrôlerait l'état du cache de chaque famille intégrée, donc "
                "parcourrait le disque de l'hôte aux frais de l'exploitant"
            )


def test_xinference_matcher_rests_on_the_registry_flag_not_on_model_name():
    block = xinference_registrations_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, XINFERENCE_REGISTRATIONS_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /v1/model_registrations de "
        "Xinference"
    )
    assert all(word_matcher_hits(m, XINFERENCE_DETAILED_REGISTRATIONS_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas le registre rendu en détail — il raterait "
        "une instance dont le paramètre detailed est ajouté en amont"
    )
    assert not all(word_matcher_hits(m, OTHER_MODEL_CATALOG_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une passerelle d'inférence qui n'est pas "
        "Xinference : model_name est le nom que tout le monde donne à son modèle"
    )
    assert not all(word_matcher_hits(m, OTHER_BUILTIN_REGISTRY_BODY)
                   for m in body_matchers), (
        "le template déclenche sur un registre d'extensions : is_builtin seul "
        "ne désigne aucun produit"
    )
    # Collisions internes au pack : ces runtimes décrivent eux aussi le modèle
    # servi, et deux templates ne doivent pas revendiquer la même instance.
    for other_body in (VLLM_MODELS_BODY, LMSTUDIO_MODELS_BODY,
                       SGLANG_MODEL_INFO_BODY, TGI_INFO_BODY):
        assert not all(word_matcher_hits(m, other_body) for m in body_matchers), (
            "le template déclenche sur un runtime déjà couvert par son propre "
            "template"
        )


# --------------------------------------------------------------------------
# Langflow a un endpoint qui prouverait l'exposition bien plus largement,
# /api/v1/auto_login : il délivre une session de superutilisateur à qui la
# demande. Le template ne doit pas l'appeler — il repartirait avec le jeton
# qu'il signale — ni toucher /api/v1/validate/code, qui exec() ce qu'on lui
# poste. Reste /api/v1/users/whoami, dont la réponse est le dossier
# utilisateur : forme banale, un compte a un nom, un drapeau d'activité et une
# date. La signature doit donc tenir aux colonnes propres au modèle de Langflow,
# et aux plus anciennes d'entre elles.

LANGFLOW_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "langflow-unauthenticated.yaml")

# Réponse d'une version récente : le superutilisateur créé au premier démarrage,
# avec les champs ajoutés après coup (store_api_key, optins).
LANGFLOW_WHOAMI_BODY = (
    '{"id":"4c9d1e77-2a05-4b8f-9c31-7e6a0d4b2f18","username":"langflow",'
    '"profile_image":null,"store_api_key":null,"is_active":true,'
    '"is_superuser":true,"create_at":"2026-04-11T08:22:41.113402",'
    '"updated_at":"2026-07-19T14:05:02.887130",'
    '"last_login_at":"2026-07-19T14:05:02.886901",'
    '"optins":{"github_starred":false,"dialog_dismissed":true,'
    '"discord_clicked":false}}'
)

# Même route sur une instance 1.0 : ni store_api_key, ni optins, et le compte
# n'a jamais servi. Le template doit toujours la reconnaître.
LANGFLOW_OLD_WHOAMI_BODY = (
    '{"id":"b8f0c2d4-6e11-4a73-95bc-0d3f8e7a1c42","username":"langflow",'
    '"profile_image":null,"is_active":true,"is_superuser":true,'
    '"create_at":"2024-06-03T09:12:55.401238",'
    '"updated_at":"2024-06-03T09:12:55.401244","last_login_at":null}'
)

# Le modèle utilisateur de Django, servi tel quel par quantité d'API : mêmes
# username, is_active et is_superuser. Ces clés seules ne désignent donc rien.
DJANGO_CURRENT_USER_BODY = (
    '{"id":1,"username":"admin","email":"admin@corp.internal",'
    '"first_name":"","last_name":"","is_staff":true,"is_active":true,'
    '"is_superuser":true,"last_login":"2026-07-19T14:05:02.886901Z",'
    '"date_joined":"2024-06-03T09:12:55.401238Z"}'
)

# Un profil applicatif quelconque : il a lui aussi un nom, une image et des
# dates de création et de connexion.
OTHER_PROFILE_BODY = (
    '{"id":"9c2a","username":"adele","profile_image":"/avatars/9c2a.png",'
    '"is_active":true,"role":"owner","created_at":"2026-01-08T10:00:00Z",'
    '"last_login_at":"2026-07-28T18:41:09Z"}'
)


def langflow_whoami_block():
    doc = load(LANGFLOW_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/v1/users/whoami" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /api/v1/users/whoami — /api/v1/version "
        "répond sans authentification même sur une instance fermée et ne prouve "
        "donc rien, et /api/v1/flows/ rend une liste sans clé sur une instance "
        "encore vide"
    )
    return blocks[0]


def test_langflow_probe_never_opens_a_session_nor_runs_code():
    doc = load(LANGFLOW_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method") == "GET", (
            "le dossier utilisateur se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            assert "auto_login" not in path, (
                "le template appelle /api/v1/auto_login : la route délivre une "
                "session de superutilisateur à qui la demande, donc le template "
                "repartirait avec le jeton qu'il est censé signaler — et elle "
                "écrit en base au passage"
            )
            assert "/validate/code" not in path, (
                "le template appelle /api/v1/validate/code, qui compile et "
                "exec() le code posté : c'est l'exécution qu'il est censé "
                "signaler, pas provoquer"
            )


def test_langflow_matcher_rests_on_the_user_model_not_on_a_generic_profile():
    block = langflow_whoami_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, LANGFLOW_WHOAMI_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /api/v1/users/whoami de Langflow"
    )
    assert all(word_matcher_hits(m, LANGFLOW_OLD_WHOAMI_BODY)
               for m in body_matchers), (
        "le template exige des colonnes absentes des versions plus anciennes de "
        "Langflow — store_api_key ou optins — il raterait les instances qui "
        "traînent exposées"
    )
    assert not all(word_matcher_hits(m, DJANGO_CURRENT_USER_BODY)
                   for m in body_matchers), (
        "le template déclenche sur le modèle utilisateur de Django : "
        "is_superuser et is_active sont les champs que sert n'importe quelle "
        "API bâtie dessus"
    )
    assert not all(word_matcher_hits(m, OTHER_PROFILE_BODY)
                   for m in body_matchers), (
        "le template déclenche sur un profil applicatif quelconque : un compte "
        "a partout un nom, une image et des dates"
    )

    # Le privilège est la conséquence, pas la preuve : une instance qui rend un
    # compte non privilégié à un anonyme a tout autant son API de gestion
    # ouverte.
    assert all(word_matcher_hits(m, LANGFLOW_WHOAMI_BODY.replace(
        '"is_superuser":true', '"is_superuser":false')) for m in body_matchers), (
        "le template exige is_superuser à true : il raterait une instance dont "
        "le compte auto-connecté n'est pas superutilisateur, alors que son API "
        "de gestion répond tout autant sans authentification"
    )


# --------------------------------------------------------------------------
# LocalAI parle le protocole OpenAI, mais son /v1/models est le plus pauvre du
# lot : OpenAIModel n'a que "id" et "object". Un matcher posé là ne pourrait que
# décrire la forme OpenAI générique — donc déclencher sur vLLM et LM Studio, déjà
# couverts. Le template doit viser /system, l'endpoint propre au produit, et sa
# signature doit tenir sur une instance au repos : c'est celle qu'on trouve
# oubliée sur un port ouvert.

LOCALAI_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "localai-unauthenticated-api.yaml")

# Réponse de /system, telle que LocalAI sérialise SystemInformationResponse.
LOCALAI_SYSTEM_BODY = (
    '{"backends":["llama-cpp","whisper","stablediffusion-ggml"],'
    '"loaded_models":[{"id":"qwen3-4b"},{"id":"granite-embedding-107m-multilingual"}]}'
)

# Même endpoint sur une instance au repos : aucun modèle chargé, aucun backend
# externe déclaré. Les deux tranches étant initialisées à [] dans le handler, les
# deux clés restent sérialisées — le template doit toujours déclencher.
LOCALAI_IDLE_SYSTEM_BODY = '{"backends":[],"loaded_models":[]}'

# /v1/models de LocalAI : OpenAIModel ne porte que "id" et "object". Ce corps est
# un sous-ensemble strict de celui de vLLM — la preuve qu'aucune signature ne
# peut y séparer les deux produits.
LOCALAI_OPENAI_MODELS_BODY = (
    '{"object":"list","data":[{"id":"qwen3-4b","object":"model"},'
    '{"id":"stablediffusion","object":"model"}]}'
)

# Une sonde d'inventaire maison sous /system : elle énumère elle aussi des
# moteurs et des modèles, sans être LocalAI.
OTHER_SYSTEM_BODY = (
    '{"hostname":"gpu-01","backends":["triton","onnxruntime"],'
    '"models":["resnet50"],"uptime_seconds":83122}'
)


def test_localai_matcher_targets_system_and_holds_on_an_idle_instance():
    doc = load(LOCALAI_TEMPLATE)

    paths = [p for b in (doc.get("http") or []) for p in (b.get("path") or [])]
    assert "{{BaseURL}}/v1/models" not in paths, (
        "le template vise /v1/models — LocalAI n'y sérialise que \"id\" et "
        "\"object\", donc rien qui le distingue de vLLM ou LM Studio"
    )

    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/system" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /system"

    block = blocks[0]
    assert block.get("method", "GET") == "GET", (
        "/system se lit : la même surface non authentifiée sert POST "
        "/models/apply, qui téléchargerait des poids"
    )
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, LOCALAI_SYSTEM_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /system de LocalAI"
    )
    assert all(word_matcher_hits(m, LOCALAI_IDLE_SYSTEM_BODY)
               for m in body_matchers), (
        "le template exige un modèle chargé ou un backend déclaré : il raterait "
        "une instance au repos, précisément celle qui traîne exposée"
    )
    assert not all(word_matcher_hits(m, OTHER_SYSTEM_BODY) for m in body_matchers), (
        "le template déclenche sur une sonde d'inventaire quelconque servant "
        "/system : énumérer des moteurs ne désigne aucun produit"
    )
    assert not all(word_matcher_hits(m, LOCALAI_OPENAI_MODELS_BODY)
                   for m in body_matchers), (
        "le template déclenche sur la forme OpenAI générique, que LocalAI "
        "partage avec tous les runtimes du pack"
    )
    # Collisions internes au pack : deux templates ne doivent pas revendiquer la
    # même instance.
    assert not all(word_matcher_hits(m, VLLM_MODELS_BODY) for m in body_matchers), (
        "le template déclenche sur vLLM, déjà couvert par son propre template"
    )
    assert not all(word_matcher_hits(m, LMSTUDIO_MODELS_BODY)
                   for m in body_matchers), (
        "le template déclenche sur LM Studio, déjà couvert par son propre template"
    )


# --------------------------------------------------------------------------
# Cas particulier du pack : /api/config est public par dessein — la page de
# connexion doit savoir, avant toute authentification, s'il faut afficher le
# bouton d'inscription. Le template ne peut donc pas se contenter de reconnaître
# Open WebUI : reconnaître le produit, c'est reconnaître une instance
# correctement fermée aussi bien qu'une instance ouverte. Le constat tient à la
# valeur d'un seul drapeau, et la signature produit doit par ailleurs traverser
# les versions — le bloc public de "features" a gagné et perdu des clés depuis
# la 0.3.

OPENWEBUI_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                  "open-webui-signup-enabled.yaml")

# Instance récente, des comptes existent déjà, inscription laissée ouverte : le
# défaut d'ENABLE_SIGNUP n'a pas été touché.
OPENWEBUI_CONFIG_SIGNUP_OPEN_BODY = (
    '{"status":true,"name":"Open WebUI","version":"0.6.18","default_locale":"",'
    '"oauth":{"providers":{}},"features":{"auth":true,'
    '"auth_trusted_header":false,"enable_ldap":false,"enable_api_key":true,'
    '"enable_signup":true,"enable_login_form":true,"enable_websocket":true,'
    '"enable_version_update_check":true}}'
)

# Même route sur une instance 0.3 : ni enable_ldap, ni enable_api_key, ni
# enable_websocket. Le template doit toujours la reconnaître.
OPENWEBUI_OLD_CONFIG_SIGNUP_OPEN_BODY = (
    '{"status":true,"name":"Open WebUI","version":"0.3.35","default_locale":"",'
    '"oauth":{"providers":{}},"features":{"auth":true,'
    '"auth_trusted_header":false,"enable_signup":true,'
    '"enable_login_form":true}}'
)

# La base ne contient aucun utilisateur : le gestionnaire d'inscription accorde
# le rôle admin au premier compte créé. C'est le pire cas, et il doit remonter.
OPENWEBUI_ONBOARDING_BODY = (
    '{"onboarding":true,"status":true,"name":"Open WebUI","version":"0.6.18",'
    '"default_locale":"","oauth":{"providers":{}},"features":{"auth":true,'
    '"auth_trusted_header":false,"enable_ldap":false,"enable_api_key":true,'
    '"enable_signup":true,"enable_login_form":true,"enable_websocket":true}}'
)

# Même produit, même route, inscription fermée comme il se doit. Le template ne
# doit pas déclencher : sinon il remonte toute instance Open WebUI vivante.
OPENWEBUI_CONFIG_SIGNUP_CLOSED_BODY = (
    '{"status":true,"name":"Open WebUI","version":"0.6.18","default_locale":"",'
    '"oauth":{"providers":{"google":"Google"}},"features":{"auth":true,'
    '"auth_trusted_header":false,"enable_ldap":false,"enable_api_key":true,'
    '"enable_signup":false,"enable_login_form":true,"enable_websocket":true,'
    '"enable_version_update_check":true}}'
)

# Le serveur sérialise compact, mais un intermédiaire peut reformater le corps
# qu'il relaie. La même instance ouverte, réindentée : le template doit encore
# la reconnaître.
OPENWEBUI_REFORMATTED_SIGNUP_OPEN_BODY = (
    '{\n  "status": true,\n  "name": "Open WebUI",\n  "version": "0.6.18",\n'
    '  "default_locale": "",\n  "oauth": {"providers": {}},\n'
    '  "features": {\n    "auth": true,\n    "auth_trusted_header": false,\n'
    '    "enable_signup": true,\n    "enable_login_form": true\n  }\n}'
)

# Une application quelconque publie elle aussi son état d'inscription sous
# /api/config : "enable_signup" et "enable_login_form" ne désignent aucun
# produit.
OTHER_APP_CONFIG_BODY = (
    '{"status":true,"name":"wiki interne","version":"3.4.1",'
    '"features":{"enable_signup":true,"enable_login_form":true,'
    '"enable_oauth":false}}'
)


def body_matcher_hits(matcher, body):
    """
    Sémantique nuclei d'un matcher de corps, `word` comme `regex` : condition
    `or` par défaut, `and` quand elle est demandée.
    """
    kind = matcher.get("type")
    if kind == "word":
        needles = matcher.get("words") or []
        def hit(n):
            return n in body
    elif kind == "regex":
        needles = matcher.get("regex") or []
        def hit(n):
            return re.search(n, body) is not None
    else:
        raise AssertionError(f"type de matcher de corps non géré : {kind!r}")

    if matcher.get("condition") == "and":
        return all(hit(n) for n in needles)
    return any(hit(n) for n in needles)


def openwebui_config_block():
    doc = load(OPENWEBUI_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/config" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /api/config"
    return blocks[0]


def test_openwebui_probe_never_creates_an_account():
    doc = load(OPENWEBUI_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'état de l'inscription se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            assert "/signup" not in path, (
                "le template appelle la route d'inscription : il créerait le "
                "compte qu'il est censé signaler, et sur une instance dont la "
                "base est vide ce compte serait administrateur — le scanner "
                "prendrait la main sur ce qu'il audite"
            )


def test_openwebui_matcher_proves_signup_is_open_not_merely_that_it_is_openwebui():
    block = openwebui_config_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "suffirait à faire remonter une instance correctement fermée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(body_matcher_hits(m, OPENWEBUI_CONFIG_SIGNUP_OPEN_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /api/config d'Open WebUI dont "
        "l'inscription est ouverte"
    )
    assert all(body_matcher_hits(m, OPENWEBUI_OLD_CONFIG_SIGNUP_OPEN_BODY)
               for m in body_matchers), (
        "le template exige des clés absentes du bloc public des versions plus "
        "anciennes — enable_ldap, enable_websocket ou enable_api_key — il "
        "raterait les instances qui traînent exposées"
    )
    assert all(body_matcher_hits(m, OPENWEBUI_ONBOARDING_BODY)
               for m in body_matchers), (
        "le template rate l'instance sans aucun utilisateur, celle dont la "
        "prochaine inscription sera administratrice"
    )
    assert all(body_matcher_hits(m, OPENWEBUI_REFORMATTED_SIGNUP_OPEN_BODY)
               for m in body_matchers), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not all(body_matcher_hits(m, OPENWEBUI_CONFIG_SIGNUP_CLOSED_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une instance dont l'inscription est fermée : "
        "/api/config est public par dessein, reconnaître Open WebUI ne prouve "
        "rien"
    )
    assert not all(body_matcher_hits(m, OTHER_APP_CONFIG_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une application quelconque servant "
        "/api/config : enable_signup et enable_login_form sont des clés banales"
    )


# --------------------------------------------------------------------------
# AnythingLLM n'a pas un drapeau d'exposition mais deux, et c'est le middleware
# validatedRequest qui les combine : il n'exige un jeton qu'en mode
# multi-utilisateur, ou — en mono-utilisateur — si AUTH_TOKEN *et* JWT_SECRET
# sont tous deux posés. Il suffit donc qu'un seul des deux manque pour que toute
# l'API de gestion passe sans authentification. GET /api/setup-complete publie
# ces trois drapeaux sans middleware, et le template doit transcrire la condition
# telle quelle : ni la réduire à RequiresAuth, ce qui raterait l'instance
# démarrée sans JWT_SECRET, ni l'oublier, ce qui ferait remonter toute instance
# vivante. Sa signature produit doit par ailleurs ne tenir qu'aux clés que
# JSON.stringify ne peut pas omettre : celles qui valent directement une variable
# d'environnement disparaissent du corps quand elle n'est pas posée.

ANYTHINGLLM_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                    "anythingllm-exposed.yaml")

# Instance récente, mono-utilisateur, aucun mot de passe : le défaut de
# l'installation Docker documentée. Tout est configuré côté modèles, donc les
# clés qui valent une variable d'environnement sont bien présentes.
ANYTHINGLLM_SETUP_COMPLETE_OPEN_BODY = (
    '{"results":{"RequiresAuth":false,"AuthToken":false,"JWTSecret":false,'
    '"StorageDir":"/app/server/storage","MultiUserMode":false,'
    '"MemoryEnabled":true,"DisableTelemetry":"false",'
    '"EmbeddingEngine":"native","HasExistingEmbeddings":true,'
    '"HasCachedEmbeddings":true,"EmbeddingModelPref":"Xenova/all-MiniLM-L6-v2",'
    '"VectorDB":"lancedb","LLMProvider":"openai","LLMModel":"gpt-4o-mini",'
    '"OpenAiKey":true,"WhisperProvider":"local",'
    '"TextToSpeechProvider":"native","AgentSerpApiKey":false}}'
)

# Même route sur une instance qui n'a rien configuré — celle qu'on trouve
# oubliée sur un port ouvert. STORAGE_DIR, EMBEDDING_ENGINE, VECTOR_DB et
# LLM_PROVIDER ne sont pas posés : leur valeur vaut undefined, donc
# JSON.stringify omet purement et simplement les clés. Le template doit toujours
# reconnaître ce corps-là.
ANYTHINGLLM_BARE_SETUP_COMPLETE_BODY = (
    '{"results":{"RequiresAuth":false,"AuthToken":false,"JWTSecret":false,'
    '"MultiUserMode":false,"DisableTelemetry":"false",'
    '"HasExistingEmbeddings":false,"HasCachedEmbeddings":false}}'
)

# Le piège du produit : l'exploitant a bien posé un mot de passe, mais pas
# JWT_SECRET. validatedRequest tombe dans sa branche de passe-droit et laisse
# passer chaque requête sans jeton — l'instance est ouverte alors qu'elle affiche
# un écran de connexion. Le template doit la faire remonter.
ANYTHINGLLM_PASSWORD_WITHOUT_JWT_SECRET_BODY = (
    '{"results":{"RequiresAuth":true,"AuthToken":true,"JWTSecret":false,'
    '"StorageDir":"/app/server/storage","MultiUserMode":false,'
    '"DisableTelemetry":"false","EmbeddingEngine":"native",'
    '"HasExistingEmbeddings":true,"HasCachedEmbeddings":true,'
    '"VectorDB":"lancedb","LLMProvider":"ollama"}}'
)

# Le serveur sérialise compact, mais un intermédiaire peut reformater le corps
# qu'il relaie. La même instance ouverte, réindentée.
ANYTHINGLLM_REFORMATTED_OPEN_BODY = (
    '{\n  "results": {\n    "RequiresAuth": false,\n    "AuthToken": false,\n'
    '    "JWTSecret": false,\n    "MultiUserMode": false,\n'
    '    "HasExistingEmbeddings": true,\n    "VectorDB": "lancedb"\n  }\n}'
)

# Mono-utilisateur, mot de passe posé et JWT_SECRET présent : validatedRequest
# exige le jeton. L'instance est fermée, le template ne doit pas déclencher.
ANYTHINGLLM_PASSWORD_PROTECTED_BODY = (
    '{"results":{"RequiresAuth":true,"AuthToken":true,"JWTSecret":true,'
    '"StorageDir":"/app/server/storage","MultiUserMode":false,'
    '"DisableTelemetry":"false","EmbeddingEngine":"native",'
    '"HasExistingEmbeddings":true,"HasCachedEmbeddings":true,'
    '"VectorDB":"lancedb","LLMProvider":"openai","OpenAiKey":true}}'
)

# Mode multi-utilisateur : chaque requête exige un compte nommé, quel que soit
# l'état d'AUTH_TOKEN — et AUTH_TOKEN n'a justement rien à y faire, donc
# RequiresAuth y vaut false sur une instance parfaitement fermée. C'est le
# faux positif le plus coûteux du produit, et le seul RequiresAuth n'en protège
# pas.
ANYTHINGLLM_MULTI_USER_BODY = (
    '{"results":{"RequiresAuth":false,"AuthToken":false,"JWTSecret":true,'
    '"StorageDir":"/app/server/storage","MultiUserMode":true,'
    '"DisableTelemetry":"false","EmbeddingEngine":"native",'
    '"HasExistingEmbeddings":true,"HasCachedEmbeddings":true,'
    '"VectorDB":"lancedb","LLMProvider":"openai","OpenAiKey":true}}'
)

# Une application quelconque publie elle aussi son état d'authentification :
# "RequiresAuth" et "MultiUserMode" à false ne désignent aucun produit.
OTHER_APP_AUTH_SETTINGS_BODY = (
    '{"results":{"RequiresAuth":false,"MultiUserMode":false,'
    '"AuthToken":false,"Version":"2.7.1","StorageDir":"/var/lib/app"}}'
)


def anythingllm_setup_complete_block():
    doc = load(ANYTHINGLLM_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/setup-complete" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /api/setup-complete — /api/ping ne porte "
        "aucune signature produit, /api/system/multi-user-mode ne dit pas si un "
        "mot de passe est posé, et GET /api/workspaces rend {\"workspaces\":[]} "
        "sur une instance neuve"
    )
    return blocks[0]


def test_anythingllm_probe_neither_writes_nor_attempts_to_authenticate():
    doc = load(ANYTHINGLLM_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "les réglages se lisent en GET : le template ne doit rien envoyer à "
            "une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            assert "env-dump" not in path, (
                "le template appelle /api/env-dump, qui n'est pas une lecture : "
                "dumpENV() réécrit le fichier .env de l'instance sur le disque "
                "de l'hôte"
            )
            assert "request-token" not in path, (
                "le template appelle la route de connexion : il tenterait de "
                "s'authentifier sur ce qu'il audite"
            )


def test_anythingllm_matcher_transcribes_the_middleware_not_a_single_flag():
    block = anythingllm_setup_complete_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "suffirait à faire remonter une instance correctement fermée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(body_matcher_hits(m, ANYTHINGLLM_SETUP_COMPLETE_OPEN_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /api/setup-complete "
        "d'AnythingLLM démarré sans authentification"
    )
    assert all(body_matcher_hits(m, ANYTHINGLLM_BARE_SETUP_COMPLETE_BODY)
               for m in body_matchers), (
        "le template s'appuie sur des clés que JSON.stringify omet quand la "
        "variable d'environnement correspondante n'est pas posée — StorageDir, "
        "EmbeddingEngine, VectorDB ou LLMProvider — il raterait l'instance qui "
        "n'a rien configuré, précisément celle qui traîne exposée"
    )
    assert all(body_matcher_hits(m, ANYTHINGLLM_PASSWORD_WITHOUT_JWT_SECRET_BODY)
               for m in body_matchers), (
        "le template exige RequiresAuth à false : il raterait l'instance dont "
        "le mot de passe est posé mais JWT_SECRET absent, alors que "
        "validatedRequest y laisse passer chaque requête sans jeton"
    )
    assert all(body_matcher_hits(m, ANYTHINGLLM_REFORMATTED_OPEN_BODY)
               for m in body_matchers), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not all(body_matcher_hits(m, ANYTHINGLLM_PASSWORD_PROTECTED_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une instance protégée par mot de passe, dont "
        "AUTH_TOKEN et JWT_SECRET sont tous deux posés : validatedRequest y "
        "exige le jeton"
    )
    assert not all(body_matcher_hits(m, ANYTHINGLLM_MULTI_USER_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une instance en mode multi-utilisateur : "
        "AUTH_TOKEN n'y sert à rien, donc RequiresAuth y vaut false alors que "
        "chaque requête exige un compte nommé — reconnaître ce corps ferait "
        "remonter toute instance correctement fermée"
    )
    assert not all(body_matcher_hits(m, OTHER_APP_AUTH_SETTINGS_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une application quelconque publiant son état "
        "d'authentification : RequiresAuth et MultiUserMode ne désignent aucun "
        "produit"
    )


# --------------------------------------------------------------------------
# Dify traverse une phase d'appropriation : sur une installation auto-hébergée,
# le premier venu qui poste /console/api/setup devient owner de la plateforme.
# GET sur cette même route est non authentifié par dessein — la page
# d'installation doit pouvoir demander l'état avant qu'un compte existe — donc
# reconnaître Dify n'y prouve rien : "finished" est ce que rend toute console
# déjà appropriée, et l'édition cloud avec. Le constat tient à la seule valeur
# "not_started", et à la paire entière : "step" et "not_started" pris séparément
# sont le vocabulaire de n'importe quel assistant d'installation. Le template ne
# doit par ailleurs jamais poster sur cette route, sous peine de créer le compte
# administrateur qu'il signale.

DIFY_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "dify-exposed-console.yaml")

# Console atteignable et sans propriétaire : aucune ligne DifySetup en base.
# Corps sérialisé à l'identique depuis les versions 0.x.
DIFY_SETUP_NOT_STARTED_BODY = '{"step":"not_started"}'

# Même état sur une version récente : le modèle de réponse porte désormais
# setup_at, laissé à null tant que l'installation n'a pas eu lieu.
DIFY_SETUP_NOT_STARTED_MODERN_BODY = '{"step":"not_started","setup_at":null}'

# Le serveur sérialise compact, mais un intermédiaire peut reformater le corps
# qu'il relaie. La même console libre, réindentée.
DIFY_SETUP_REFORMATTED_NOT_STARTED_BODY = '{\n  "step": "not_started"\n}'

# Installation auto-hébergée déjà appropriée : le compte owner existe, et
# l'écran de connexion garde tout le reste. Le template ne doit pas déclencher,
# sinon il remonte toute instance Dify vivante.
DIFY_SETUP_FINISHED_BODY = (
    '{"step":"finished","setup_at":"2026-03-04T11:22:31.482913"}'
)

# Édition cloud : la route rend "finished" sans même regarder la base. Le
# reconnaître ferait remonter l'offre hébergée elle-même.
DIFY_SETUP_CLOUD_FINISHED_BODY = '{"step":"finished"}'

# Un assistant d'installation quelconque : il numérote ses étapes et nomme un
# état non démarré. Les deux mots sont là, la paire n'y est pas.
OTHER_INSTALL_WIZARD_BODY = (
    '{"step":3,"total_steps":5,"status":"not_started",'
    '"wizard":"onboarding","product":"helpdesk"}'
)


def dify_setup_block():
    doc = load(DIFY_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/console/api/setup" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /console/api/setup — "
        "/console/api/system-features est un instantané publié avant toute "
        "authentification sur toute instance vivante, et /console/api/version "
        "fait sortir l'hôte vers CHECK_UPDATE_URL"
    )
    return blocks[0]


def test_dify_probe_never_claims_the_instance_nor_authenticates():
    doc = load(DIFY_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'état de l'installation se lit en GET : la même route en POST "
            "crée le compte owner de la plateforme et écrit la ligne DifySetup "
            "qui verrouille l'appropriation — le template prendrait la main sur "
            "ce qu'il audite, et en priverait l'exploitant"
        )
        for path in (block.get("path") or []):
            assert "/init" not in path, (
                "le template touche /console/api/init : en POST il soumet un "
                "mot de passe à INIT_PASSWORD, donc tente de s'authentifier, et "
                "en GET il rend \"finished\" aussi bien quand INIT_PASSWORD "
                "n'est pas posé que quand l'instance est déjà installée — il ne "
                "prouve rien"
            )
            assert "/version" not in path, (
                "le template appelle /console/api/version, qui n'est pas une "
                "lecture locale : le handler sort vers CHECK_UPDATE_URL depuis "
                "l'hôte, donc le template ferait appeler un tiers à l'instance "
                "qu'il découvre"
            )


def test_dify_matcher_proves_the_console_is_unclaimed_not_merely_that_it_is_dify():
    block = dify_setup_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la reconnaissance du "
        "produit suffirait à faire remonter une console déjà appropriée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(body_matcher_hits(m, DIFY_SETUP_NOT_STARTED_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /console/api/setup de Dify "
        "dont l'installation n'a pas eu lieu"
    )
    assert all(body_matcher_hits(m, DIFY_SETUP_NOT_STARTED_MODERN_BODY)
               for m in body_matchers), (
        "le template rate la sérialisation des versions récentes, qui ajoutent "
        "setup_at à null au même état"
    )
    assert all(body_matcher_hits(m, DIFY_SETUP_REFORMATTED_NOT_STARTED_BODY)
               for m in body_matchers), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not all(body_matcher_hits(m, DIFY_SETUP_FINISHED_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une console déjà appropriée : la route est "
        "non authentifiée par dessein, reconnaître Dify ne prouve rien"
    )
    assert not all(body_matcher_hits(m, DIFY_SETUP_CLOUD_FINISHED_BODY)
                   for m in body_matchers), (
        "le template déclenche sur l'édition cloud, qui rend \"finished\" sans "
        "même regarder la base"
    )
    assert not all(body_matcher_hits(m, OTHER_INSTALL_WIZARD_BODY)
                   for m in body_matchers), (
        "le template déclenche sur un assistant d'installation quelconque : il "
        "cherche \"step\" et \"not_started\" séparément au lieu d'exiger la "
        "paire, or numéroter une étape et nommer un état non démarré n'est le "
        "vocabulaire de personne"
    )


# --------------------------------------------------------------------------
# LiteLLM ne garde ses routes qu'avec un master_key, et rien ne l'impose au
# démarrage : user_api_key_auth rend un jeton valable dès que master_key vaut
# None, et n'exige une clé que dans le cas contraire. Un 200 anonyme sur une
# route portant cette dépendance est donc le constat entier. Mais /v1/models,
# la route que l'énoncé désigne, est bâtie avec provider="openai" en dur : son
# corps est la forme OpenAI nue, celle-là même que ce fichier tient pour la
# contre-épreuve depuis le template vLLM. La preuve doit donc se lire sur
# /model/info, qui porte la même dépendance et sert les clés du schéma de
# config.yaml — et le template ne doit toucher ni la route de complétion, qui
# dépenserait le budget du fournisseur, ni celle qui émet des clés virtuelles.

LITELLM_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "litellm-proxy-no-master-key.yaml")

# Réponse de /model/info sur une instance sans master_key (LiteLLM courant),
# tronquée : model_info porte en réalité plus de cent clés de tarification.
# api_key a été retiré de litellm_params par
# remove_sensitive_info_from_deployment().
LITELLM_MODEL_INFO_BODY = (
    '{"data":[{"model_name":"fake-openai-endpoint","litellm_params":'
    '{"api_base":"https://exampleopenaiendpoint-production.up.railway.app/",'
    '"use_in_pass_through":false,"use_litellm_proxy":false,'
    '"merge_reasoning_content_in_choices":false,"model":"openai/fake"},'
    '"model_info":{"id":"46577d4b09b8d111c341a16bc55d5771bb3972ec28e80e48dc21'
    'bbc6261f4ca1","db_model":false,"key":"openai/fake","max_tokens":null,'
    '"input_cost_per_token":0,"output_cost_per_token":0,'
    '"litellm_provider":"openai","mode":null,"tpm":null,"rpm":null}}]}'
)

# Même route sur une instance nettement plus ancienne : litellm_params n'a que
# les deux clés venues du config.yaml, et model_info aucune des clés ajoutées
# depuis. Le template doit toujours la reconnaître.
LITELLM_OLD_MODEL_INFO_BODY = (
    '{"data":[{"model_name":"fake-openai-endpoint","litellm_params":'
    '{"api_base":"https://exampleopenaiendpoint-production.up.railway.app/",'
    '"model":"openai/fake"},"model_info":{"id":"46577d4b09b8d111c341a16bc55d'
    '5771bb3972ec28e80e48dc21bbc6261f4ca1","max_tokens":null,'
    '"input_cost_per_token":0,"output_cost_per_token":0}}]}'
)

# Le serveur sérialise compact, mais un intermédiaire peut reformater le corps
# qu'il relaie. La même table de routage, réindentée.
LITELLM_REFORMATTED_MODEL_INFO_BODY = (
    '{\n  "data": [\n    {\n      "model_name": "fake-openai-endpoint",\n'
    '      "litellm_params": {"model": "openai/fake"},\n'
    '      "model_info": {"id": "46577d4b", "db_model": false}\n    }\n  ]\n}'
)

# /v1/models de LiteLLM : create_model_info_response() est appelée avec
# provider="openai" en dur, donc owned_by ne nomme même pas le produit. Ce corps
# est indiscernable d'OTHER_OPENAI_API_BODY — la preuve qu'aucune signature ne
# peut s'y poser.
LITELLM_OPENAI_MODELS_BODY = (
    '{"data":[{"id":"fake-openai-endpoint","object":"model",'
    '"created":1677610602,"owned_by":"openai"}],"object":"list"}'
)

# Même instance, master_key posé : user_api_key_auth atteint la branche
# « elif api_key is None » et refuse. C'est l'instance correctement fermée, le
# template ne doit pas déclencher.
LITELLM_MASTER_KEY_SET_BODY = (
    '{"error":{"message":"Authentication Error, No api key passed in.",'
    '"type":"auth_error","param":"None","code":"401"}}'
)

# Un registre de modèles quelconque énumère lui aussi des entrées nommées et
# décrites : "model_name" et "model_info" ne désignent aucun produit.
OTHER_MODEL_REGISTRY_BODY = (
    '{"data":[{"model_name":"llama-3.1-8b-instruct",'
    '"model_info":{"id":"7f3c","version":"3","framework":"onnxruntime"},'
    '"params":{"model":"/models/llama-3.1-8b","batch_size":8}},'
    '{"model_name":"bge-m3","model_info":{"id":"1a90","version":"1"},'
    '"params":{"model":"/models/bge-m3"}}]}'
)


def litellm_model_info_block():
    doc = load(LITELLM_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/model/info" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /model/info — /v1/models porte bien la "
        "même dépendance user_api_key_auth, mais LiteLLM l'assemble avec "
        "provider=\"openai\" en dur, donc son corps est la forme OpenAI nue que "
        "les templates vLLM, LM Studio et LocalAI revendiquent déjà"
    )
    return blocks[0]


def test_litellm_probe_neither_infers_nor_mints_a_key():
    doc = load(LITELLM_TEMPLATE)

    paths = [p for b in (doc.get("http") or []) for p in (b.get("path") or [])]
    assert "{{BaseURL}}/v1/models" not in paths, (
        "le template vise /v1/models, dont le corps est indiscernable de celui "
        "de n'importe quelle API compatible OpenAI : owned_by y vaut \"openai\" "
        "en dur, et les en-têtes x-litellm-* ne sont écrites que par le chemin "
        "des complétions"
    )

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "la table de routage se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            assert "/chat/completions" not in path, (
                "le template appelle la route de complétion : le proxy sortirait "
                "vers le fournisseur avec la clé de l'exploitant, donc le "
                "template dépenserait le budget qu'il est censé protéger"
            )
            assert "/key/generate" not in path, (
                "le template appelle /key/generate : sur un déploiement adossé "
                "à une base, la route émet une clé virtuelle qui resterait "
                "valide après la pose du master_key — le template survivrait à "
                "sa propre remédiation"
            )
            assert "/model/new" not in path, (
                "le template appelle /model/new : il inscrirait une entrée de "
                "routage dans l'instance qu'il audite"
            )


def test_litellm_matcher_rests_on_the_config_schema_not_on_a_model_inventory():
    block = litellm_model_info_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(body_matcher_hits(m, LITELLM_MODEL_INFO_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /model/info d'un proxy "
        "LiteLLM démarré sans master_key"
    )
    assert all(body_matcher_hits(m, LITELLM_OLD_MODEL_INFO_BODY)
               for m in body_matchers), (
        "le template exige des clés absentes des versions plus anciennes — "
        "db_model ou litellm_provider, ajoutées à model_info après coup — il "
        "raterait les instances qui traînent exposées"
    )
    assert all(body_matcher_hits(m, LITELLM_REFORMATTED_MODEL_INFO_BODY)
               for m in body_matchers), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not all(body_matcher_hits(m, LITELLM_MASTER_KEY_SET_BODY)
                   for m in body_matchers), (
        "le template déclenche sur le refus d'une instance dont le master_key "
        "est posé, c'est-à-dire sur l'instance correctement fermée"
    )
    assert not all(body_matcher_hits(m, LITELLM_OPENAI_MODELS_BODY)
                   for m in body_matchers), (
        "le template déclenche sur la forme OpenAI générique, que LiteLLM "
        "partage avec tous les runtimes du pack"
    )
    assert not all(body_matcher_hits(m, OTHER_MODEL_REGISTRY_BODY)
                   for m in body_matchers), (
        "le template déclenche sur un registre de modèles quelconque : "
        "model_name et model_info sont le vocabulaire de tout inventaire, seul "
        "litellm_params nomme le produit"
    )

    # Le refus doit tenir au corps, pas au seul code de statut : les instances
    # fermées répondent 401, mais une signature qui ne prouverait rien serait
    # rattrapée par n'importe quel intermédiaire renvoyant 200.
    statuses = [s for m in (block.get("matchers") or [])
                if m.get("type") == "status"
                for s in (m.get("status") or [])]
    assert statuses == [200], (
        f"le template accepte des statuts autres que 200 ({statuses}) — or "
        "c'est le 200 anonyme, et lui seul, qui prouve que master_key n'est pas "
        "posé : la même route rend 401 dès qu'il l'est"
    )

    # Collisions internes au pack : ces runtimes décrivent eux aussi les modèles
    # servis, et deux templates ne doivent pas revendiquer la même instance.
    for other_body in (VLLM_MODELS_BODY, LMSTUDIO_MODELS_BODY, TGI_INFO_BODY,
                       SGLANG_MODEL_INFO_BODY, XINFERENCE_REGISTRATIONS_BODY,
                       LOCALAI_SYSTEM_BODY):
        assert not all(body_matcher_hits(m, other_body) for m in body_matchers), (
            "le template déclenche sur un runtime déjà couvert par son propre "
            "template"
        )


# --------------------------------------------------------------------------
# Gradio sert la définition de son interface aux deux bouts : la racine l'injecte
# dans la page, /config la rend en JSON. Mais seule la seconde porte
# Depends(login_check) — la racine répond 200 et sa coquille HTML que l'instance
# soit protégée ou non, en y glissant un config réduit à "auth_required":true.
# Le template doit donc viser /config, et sa signature doit tenir aux clés que
# get_config_file() sérialise depuis les versions 3.x jusqu'à la 6.x courante,
# sans se rabattre sur le vocabulaire commun à tout fichier de configuration.

GRADIO_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "gradio-app-exposed.yaml")

# Réponse de /config sur une instance courante (6.x), tronquée : components
# énumère en réalité chaque composant de l'interface avec toutes ses props.
GRADIO_CONFIG_BODY = (
    '{"version":"6.22.0","api_prefix":"/gradio_api","mode":"interface",'
    '"app_id":15217808355328254446,"dev_mode":false,"vibe_mode":false,'
    '"analytics_enabled":true,"components":[{"id":4,"type":"row",'
    '"props":{"variant":"default","visible":true,"name":"row"},'
    '"skip_api":true,"key":null}],"css":null,"connect_heartbeat":false,'
    '"js":null,"head":null,"title":"Gradio","space_id":null,'
    '"enable_queue":true,"show_error":false,"footer_links":[],'
    '"is_colab":false,"max_file_size":null,"stylesheets":[],'
    '"theme":"default","protocol":"sse_v3","fill_height":false,'
    '"fill_width":false,"theme_hash":"8ad6f9b1","pwa":false,"pages":[""],'
    '"dependencies":[{"id":0,"targets":[[1,"click"]],"inputs":[],'
    '"outputs":[1],"backend_fn":true,"js":null,"queue":false,'
    '"api_name":"predict"}],"layout":{"id":2,"children":[{"id":4}]},'
    '"username":null,"root":"https://demo.interne"}'
)

# Même route sur une instance nettement plus ancienne (3.x). get_config_file()
# n'y sérialise ni analytics_enabled, ni space_id, ni protocol, ni api_prefix, et
# porte encore show_api, retiré depuis. Le template doit toujours la reconnaître :
# ce sont ces instances-là qui traînent exposées.
GRADIO_OLD_CONFIG_BODY = (
    '{"version":"3.12.0","mode":"blocks","dev_mode":false,'
    '"components":[{"id":1,"type":"textbox",'
    '"props":{"lines":1,"name":"textbox"}}],"theme":"default","css":null,'
    '"title":"Gradio","enable_queue":false,"show_error":false,'
    '"show_api":true,"is_colab":false,'
    '"layout":{"id":0,"children":[{"id":1}]},'
    '"dependencies":[{"targets":[2],"trigger":"click","inputs":[1],'
    '"outputs":[3],"backend_fn":true,"js":null,"queue":null,'
    '"api_name":"predict"}]}'
)

# Le serveur sérialise compact, mais un intermédiaire peut reformater le corps
# qu'il relaie. Le même document, réindenté.
GRADIO_REFORMATTED_CONFIG_BODY = (
    '{\n  "version": "5.9.1",\n  "mode": "blocks",\n  "dev_mode": false,\n'
    '  "components": [],\n  "title": "Gradio",\n  "enable_queue": true,\n'
    '  "is_colab": false,\n  "dependencies": [],\n  "layout": {"id": 0}\n}'
)

# Même instance, auth posé : login_check atteint le raise et /config répond 401.
# C'est l'instance correctement fermée, le template ne doit pas déclencher.
GRADIO_LOGIN_REQUIRED_BODY = (
    '{"detail":{"error":"Not authenticated","auth_message":null}}'
)

# Le même refus tel que les versions 3.x et 4.x le sérialisent : detail y est une
# chaîne, pas un objet.
GRADIO_OLD_LOGIN_REQUIRED_BODY = '{"detail":"Not authenticated"}'

# Le config réduit que la racine injecte dans sa page quand auth est posé et que
# le visiteur n'est pas connecté. Il porte components, dependencies, space_id,
# root et pages — donc tout le vocabulaire structurel de Gradio — mais aucune des
# clés du trio : viser la racine reviendrait à signaler l'instance protégée.
GRADIO_AUTH_REQUIRED_STUB_BODY = (
    '{"auth_required":true,"auth_message":null,"space_id":null,'
    '"root":"https://demo.interne","page":{"":{"layout":{}}},"pages":[""],'
    '"components":[],"dependencies":[],"current_page":""}'
)

# Une application quelconque qui publie sa configuration : elle nomme sa version,
# son mode, son titre, son thème, ses composants, sa mise en page et ses
# dépendances. Sept mots que Gradio écrit aussi, et qui ne désignent personne.
OTHER_APP_CONFIG_BODY = (
    '{"version":"2.4.1","mode":"production","title":"Tableau de bord",'
    '"theme":"dark","css":null,"components":[{"id":"chart-1","type":"chart"}],'
    '"layout":{"rows":[["chart-1"]]},"dependencies":["chart.js","d3"],'
    '"enable_queue":false}'
)


def gradio_config_block():
    doc = load(GRADIO_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/config" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /config — c'est pourtant la seule route qui "
        "conditionne le document de l'interface à l'authentification : la racine "
        "sert la même coquille HTML, protégée ou non"
    )
    return blocks[0]


def test_gradio_probe_never_runs_the_app_nor_writes_to_it():
    doc = load(GRADIO_TEMPLATE)

    paths = [p for b in (doc.get("http") or []) for p in (b.get("path") or [])]
    assert "{{BaseURL}}/" not in paths, (
        "le template vise la racine, qui répond 200 et la même coquille HTML que "
        "l'instance soit protégée ou non : il déclencherait sur les applications "
        "correctement fermées"
    )

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "le document de l'interface se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/call/", "le template appelle POST /gradio_api/call/{api_name} : "
                           "il exécuterait la fonction Python de l'application sur "
                           "le matériel de l'exploitant, c'est-à-dire l'abus même "
                           "qu'il est censé signaler"),
                ("/run/", "le template appelle la route de prédiction des versions "
                          "3.x : même exécution, même dépense"),
                ("/upload", "le template appelle POST /upload : il écrirait un "
                            "fichier dans le répertoire temporaire de l'instance "
                            "qu'il audite"),
                ("/component_server", "le template appelle POST /component_server : "
                                      "il ferait exécuter une méthode de composant "
                                      "côté serveur"),
                ("/file=", "le template lit un fichier servi par l'application : "
                           "signaler une exposition ne demande pas d'en extraire le "
                           "contenu"),
            ):
                assert forbidden not in path, why


def test_gradio_matcher_rests_on_the_config_schema_not_on_a_generic_config():
    block = gradio_config_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(body_matcher_hits(m, GRADIO_CONFIG_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /config d'une application "
        "Gradio courante"
    )
    assert all(body_matcher_hits(m, GRADIO_OLD_CONFIG_BODY)
               for m in body_matchers), (
        "le template exige des clés absentes des versions 3.x — analytics_enabled, "
        "protocol ou api_prefix, toutes ajoutées après coup — il raterait les "
        "instances qui traînent exposées"
    )
    assert all(body_matcher_hits(m, GRADIO_REFORMATTED_CONFIG_BODY)
               for m in body_matchers), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not all(body_matcher_hits(m, GRADIO_LOGIN_REQUIRED_BODY)
                   for m in body_matchers), (
        "le template déclenche sur le refus d'une instance dont auth est posé, "
        "c'est-à-dire sur l'application correctement fermée"
    )
    assert not all(body_matcher_hits(m, GRADIO_OLD_LOGIN_REQUIRED_BODY)
                   for m in body_matchers), (
        "le template déclenche sur le refus tel que les versions 3.x et 4.x le "
        "sérialisent"
    )
    assert not all(body_matcher_hits(m, GRADIO_AUTH_REQUIRED_STUB_BODY)
                   for m in body_matchers), (
        "le template déclenche sur le config réduit que la racine injecte quand "
        "auth est posé : il porte components, dependencies et pages, donc toute "
        "la structure de Gradio, et pourtant l'instance demande bien un mot de "
        "passe"
    )
    assert not all(body_matcher_hits(m, OTHER_APP_CONFIG_BODY)
                   for m in body_matchers), (
        "le template déclenche sur la configuration d'une application "
        "quelconque : version, mode, titre, thème, composants, mise en page et "
        "dépendances sont le vocabulaire de tout fichier de configuration, seul "
        "le trio dev_mode / enable_queue / is_colab nomme le produit"
    )

    # Le refus doit tenir au corps ET au statut : c'est le 200 anonyme, et lui
    # seul, qui prouve que login_check laisse passer — la même route rend 401 dès
    # qu'un auth ou un auth_dependency est posé.
    statuses = [s for m in (block.get("matchers") or [])
                if m.get("type") == "status"
                for s in (m.get("status") or [])]
    assert statuses == [200], (
        f"le template accepte des statuts autres que 200 ({statuses}) — or la "
        "route /config porte Depends(login_check), et c'est son 200 qui constitue "
        "le constat d'absence d'authentification"
    )

    # Collisions internes au pack : ces interfaces publient elles aussi leur
    # configuration sans authentification, et deux templates ne doivent pas
    # revendiquer la même instance.
    for other_body in (OPENWEBUI_CONFIG_SIGNUP_OPEN_BODY,
                       ANYTHINGLLM_SETUP_COMPLETE_OPEN_BODY,
                       LANGSERVE_OPENAPI_BODY, COMFYUI_SYSTEM_STATS_BODY,
                       LOCALAI_SYSTEM_BODY):
        assert not all(body_matcher_hits(m, other_body) for m in body_matchers), (
            "le template déclenche sur une interface déjà couverte par son "
            "propre template"
        )


# --------------------------------------------------------------------------
# ChromaDB sépare ce qui nomme le produit de ce qui prouve l'exposition, et le
# template doit épouser cette séparation. Le handler heartbeat n'appelle aucun
# contrôle d'accès — ni dans le serveur Rust des versions 1.x, ni dans le
# serveur Python d'avant — donc il répond 200 y compris derrière un proxy qui
# authentifie : le reconnaître seul ferait remonter les instances gardées.
# list_collections passe, lui, par authenticate_and_authorize avec l'action
# ListCollections, et c'est son 200 anonyme qui constitue le constat. Le
# template doit donc lier les deux réponses, couvrir les deux générations d'API
# — la 1.0 a déplacé le tout sous /api/v2 et rend 410 sur /api/v1, alors que le
# parc de 2023 ne connaît que /api/v1 — et conclure sur une instance neuve, dont
# l'index est un tableau vide.

CHROMADB_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "chromadb-open-instance.yaml")

CHROMA_V2_HEARTBEAT = "/api/v2/heartbeat"
CHROMA_V2_COLLECTIONS = ("/api/v2/tenants/default_tenant/databases/"
                         "default_database/collections")
CHROMA_V1_HEARTBEAT = "/api/v1/heartbeat"
CHROMA_V1_COLLECTIONS = "/api/v1/collections"

# HeartbeatResponse : le champ Rust nanosecond_heartbeat est explicitement
# renommé à la sérialisation, et le serveur Python écrivait déjà ce littéral.
# Une espace au milieu d'une clé JSON, personne ne l'écrit par accident.
CHROMA_HEARTBEAT_BODY = '{"nanosecond heartbeat":1785309961123456789}'

# Index des collections d'une instance qui sert un corpus. Forme du modèle
# Collection : id, name, configuration_json, metadata, dimension, tenant,
# database, log_position, version.
CHROMA_COLLECTIONS_BODY = (
    '[{"id":"6f1a9c40-3b7e-4d21-9a0c-1f8e5b2d7c33","name":"support-rag",'
    '"configuration_json":{"hnsw":{"space":"l2","ef_construction":100}},'
    '"metadata":null,"dimension":384,"tenant":"default_tenant",'
    '"database":"default_database","log_position":0,"version":0}]'
)

# La même route sur une instance qui vient d'être lancée : aucune collection
# n'a encore été créée.
CHROMA_EMPTY_COLLECTIONS_BODY = "[]"

# Refus de la route gardée quand un CHROMA_SERVER_AUTHN_PROVIDER est posé.
CHROMA_UNAUTHORIZED_BODY = '{"error":"Unauthorized"}'

# Ce que rend une instance 1.x sur l'ancienne API, tout chemin confondu.
CHROMA_V1_GONE_BODY = (
    '{"error":"Unimplemented",'
    '"message":"The v1 API is deprecated. Please use /v2 apis"}'
)

# Ce que rend une instance 0.5.x sur la nouvelle : la route n'existe pas encore.
CHROMA_NOT_FOUND_BODY = '{"detail":"Not Found"}'


def chroma_scenario(**routes):
    """
    Un scénario associe une réponse (statut, corps) à chacun des quatre chemins
    que le template interroge. Les clés sont nommées pour que l'intention reste
    lisible ; l'ordre, lui, est imposé par le template au moment de l'évaluation.
    """
    return {
        CHROMA_V2_HEARTBEAT: routes["v2_heartbeat"],
        CHROMA_V2_COLLECTIONS: routes["v2_collections"],
        CHROMA_V1_HEARTBEAT: routes["v1_heartbeat"],
        CHROMA_V1_COLLECTIONS: routes["v1_collections"],
    }


V1_GONE = (410, CHROMA_V1_GONE_BODY)
V2_ABSENT = (404, CHROMA_NOT_FOUND_BODY)

# Instance 1.x servant un corpus, rien devant elle.
CHROMA_MODERN = chroma_scenario(
    v2_heartbeat=(200, CHROMA_HEARTBEAT_BODY),
    v2_collections=(200, CHROMA_COLLECTIONS_BODY),
    v1_heartbeat=V1_GONE, v1_collections=V1_GONE,
)

# Même instance au lendemain de son démarrage : l'index est vide. C'est celle
# qu'on trouve oubliée sur un port ouvert, et elle doit remonter.
CHROMA_MODERN_IDLE = chroma_scenario(
    v2_heartbeat=(200, CHROMA_HEARTBEAT_BODY),
    v2_collections=(200, CHROMA_EMPTY_COLLECTIONS_BODY),
    v1_heartbeat=V1_GONE, v1_collections=V1_GONE,
)

# Un intermédiaire réindente ce qu'il relaie : le corps n'est plus compact et
# l'index ne commence plus par son crochet.
CHROMA_MODERN_REFORMATTED = chroma_scenario(
    v2_heartbeat=(200, '{\n  "nanosecond heartbeat": 1785309961123456789\n}'),
    v2_collections=(200, '\n[\n  {\n    "id": "6f1a9c40",\n'
                         '    "name": "support-rag"\n  }\n]\n'),
    v1_heartbeat=V1_GONE, v1_collections=V1_GONE,
)

# Instance 0.5.x sans CHROMA_SERVER_AUTHN_PROVIDER : le réglage vaut None par
# défaut, donc l'API de gestion répond à l'anonyme. La nouvelle API n'existe pas
# encore sur cette version.
CHROMA_LEGACY = chroma_scenario(
    v2_heartbeat=V2_ABSENT, v2_collections=V2_ABSENT,
    v1_heartbeat=(200, CHROMA_HEARTBEAT_BODY),
    v1_collections=(200, CHROMA_COLLECTIONS_BODY),
)

# Même version, jeton posé : authenticate_or_raise refuse l'index, mais le
# heartbeat reste servi — il n'est gardé par rien. C'est l'instance fermée.
CHROMA_LEGACY_AUTHN = chroma_scenario(
    v2_heartbeat=V2_ABSENT, v2_collections=V2_ABSENT,
    v1_heartbeat=(200, CHROMA_HEARTBEAT_BODY),
    v1_collections=(401, CHROMA_UNAUTHORIZED_BODY),
)

# Instance 1.x dont seul le plan de données est gardé par un proxy : le
# heartbeat passe, l'index non. Le serveur libre ne sachant plus refuser une
# requête, c'est la seule façon de fermer une 1.x — et le template ne doit pas
# la faire remonter.
CHROMA_MODERN_BEHIND_PROXY = chroma_scenario(
    v2_heartbeat=(200, CHROMA_HEARTBEAT_BODY),
    v2_collections=(401, CHROMA_UNAUTHORIZED_BODY),
    v1_heartbeat=V1_GONE, v1_collections=V1_GONE,
)

# Le même proxy, réglé pour tout garder.
CHROMA_BEHIND_AUTH_PROXY = chroma_scenario(
    v2_heartbeat=(401, CHROMA_UNAUTHORIZED_BODY),
    v2_collections=(401, CHROMA_UNAUTHORIZED_BODY),
    v1_heartbeat=(401, CHROMA_UNAUTHORIZED_BODY),
    v1_collections=(401, CHROMA_UNAUTHORIZED_BODY),
)

# Un serveur quelconque qui répond 200 à tout ce qu'on lui demande.
OTHER_SERVER_ALWAYS_200 = chroma_scenario(
    v2_heartbeat=(200, '{"status":"ok"}'),
    v2_collections=(200, '{"status":"ok"}'),
    v1_heartbeat=(200, '{"status":"ok"}'),
    v1_collections=(200, '{"status":"ok"}'),
)

# Le pire de ce genre : il répond 200 et un tableau vide partout, donc satisfait
# tout ce que le template attend de l'index. Seule la signature du heartbeat
# l'en sépare.
OTHER_SERVER_ALWAYS_EMPTY_ARRAY = chroma_scenario(
    v2_heartbeat=(200, "[]"), v2_collections=(200, "[]"),
    v1_heartbeat=(200, "[]"), v1_collections=(200, "[]"),
)

# Portail captif devant une vraie instance : il laisse filer le heartbeat et
# répond 200 à l'index, mais avec sa page de connexion.
CHROMA_BEHIND_CAPTIVE_PORTAL = chroma_scenario(
    v2_heartbeat=(200, CHROMA_HEARTBEAT_BODY),
    v2_collections=(200, "<html><body>Connexion requise</body></html>"),
    v1_heartbeat=V1_GONE, v1_collections=V1_GONE,
)


def dsl_matcher_hits(matcher, responses):
    """
    Sémantique nuclei d'un matcher `dsl` sous req-condition : les réponses déjà
    reçues peuplent body_N et status_code_N, chaque expression est évaluée
    contre cet espace de noms, et la condition vaut `or` par défaut.

    Le sous-ensemble du langage employé ici — contains, starts_with, trim_space,
    regex, `&&` et `||` — se traduit terme à terme en Python. L'espace de noms est
    clos : aucune autre fonction n'y est atteignable.

    `regex` prend le motif d'abord, comme la fonction nuclei du même nom, et rend
    un booléen : une correspondance n'importe où dans le sujet, donc `re.search`
    et non `re.match`. Les échappements du littéral de chaîne sont les mêmes des
    deux côtés — `\\"` pour un guillemet, `\\\\s` pour la classe d'espaces — donc
    l'expression lue dans le template est évaluée telle quelle.
    """
    env = {
        "contains": lambda s, sub: sub in s,
        "starts_with": lambda s, *prefixes: any(s.startswith(p) for p in prefixes),
        "trim_space": lambda s: s.strip(),
        "regex": lambda pattern, s: re.search(pattern, s) is not None,
    }
    for i, (status, body) in enumerate(responses, start=1):
        env[f"status_code_{i}"] = status
        env[f"body_{i}"] = body

    def hit(expr):
        python_expr = expr.replace("&&", " and ").replace("||", " or ")
        return bool(eval(python_expr, {"__builtins__": {}}, env))  # noqa: S307

    exprs = matcher.get("dsl") or []
    assert exprs, "matcher dsl sans expression"
    if matcher.get("condition") == "and":
        return all(hit(e) for e in exprs)
    return any(hit(e) for e in exprs)


def chromadb_block():
    doc = load(CHROMADB_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith("/heartbeat") for p in (b.get("path") or []))]
    assert blocks, (
        "le template n'interroge pas le heartbeat — c'est pourtant la seule "
        "route qui nomme le produit, l'index des collections étant vide sur "
        "une instance neuve"
    )
    return blocks[0]


def chromadb_responses(scenario):
    """
    Range les réponses d'un scénario dans l'ordre des chemins déclarés par le
    template : c'est cet ordre qui donne son numéro à chaque body_N.
    """
    ordered = []
    for path in chromadb_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        assert route in scenario, (
            f"le template interroge un chemin que ChromaDB ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def chromadb_fires(scenario):
    block = chromadb_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = chromadb_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_chromadb_probe_only_reads_and_never_touches_the_data_plane():
    doc = load(CHROMADB_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'index des collections se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/reset", "le template appelle POST /api/v2/reset, qui vide "
                           "l'instance : il détruirait le corpus qu'il est censé "
                           "protéger"),
                ("/get", "le template appelle /get, qui rend les documents et "
                         "leurs embeddings : Chroma stocke le texte en clair, "
                         "donc le template exfiltrerait le corpus qu'il signale"),
                ("/query", "le template appelle /query : il ferait classer le "
                           "corpus par proximité sémantique, c'est-à-dire "
                           "désigner les passages sensibles"),
                ("/add", "le template écrit dans une collection de l'instance "
                         "qu'il audite"),
                ("/update", "le template récrit des documents que l'assistant "
                            "citera ensuite comme sources"),
                ("/upsert", "le template écrit dans une collection de "
                            "l'instance qu'il audite"),
                ("/delete", "le template supprime des documents de l'instance "
                            "qu'il audite"),
            ):
                assert forbidden not in path, why


def test_chromadb_probe_covers_both_api_generations():
    paths = [p for p in chromadb_block().get("path") or []]

    assert any(CHROMA_V2_COLLECTIONS in p for p in paths), (
        "le template n'interroge pas l'index sous /api/v2 — depuis la version "
        "1.0 c'est la seule API servie, /api/v1 y répond 410"
    )
    assert any(p.endswith(CHROMA_V1_COLLECTIONS) for p in paths), (
        "le template n'interroge pas l'index sous /api/v1 — les instances 0.4 "
        "et 0.5 ne connaissent que celle-là, et ce sont elles qui traînent "
        "exposées"
    )
    assert chromadb_block().get("req-condition") is True, (
        "sans req-condition, les deux réponses ne peuvent pas être liées : le "
        "heartbeat conclurait seul, or il n'est gardé par rien"
    )


def test_chromadb_matcher_needs_the_guarded_route_not_just_the_heartbeat():
    assert chromadb_fires(CHROMA_MODERN), (
        "le template ne reconnaît pas une instance 1.x dont l'index des "
        "collections répond à l'anonyme"
    )
    assert chromadb_fires(CHROMA_MODERN_IDLE), (
        "le template exige une collection dans l'index : il raterait l'instance "
        "qui vient d'être lancée, précisément celle qu'on trouve oubliée sur un "
        "port ouvert"
    )
    assert chromadb_fires(CHROMA_MODERN_REFORMATTED), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )
    assert chromadb_fires(CHROMA_LEGACY), (
        "le template ne couvre pas les instances 0.4 et 0.5, qui ne servent que "
        "/api/v1 — or l'authentification y était facultative et elles sont les "
        "plus anciennes du parc"
    )

    assert not chromadb_fires(CHROMA_LEGACY_AUTHN), (
        "le template déclenche sur une instance dont CHROMA_SERVER_AUTHN_PROVIDER "
        "est posé : son index rend 401, seul le heartbeat répond encore"
    )
    assert not chromadb_fires(CHROMA_MODERN_BEHIND_PROXY), (
        "le template conclut du seul heartbeat : ce handler n'appelle aucun "
        "contrôle d'accès, donc il répond même à travers le proxy qui est la "
        "seule façon de fermer une instance 1.x"
    )
    assert not chromadb_fires(CHROMA_BEHIND_AUTH_PROXY), (
        "le template déclenche sur une instance entièrement gardée"
    )
    assert not chromadb_fires(OTHER_SERVER_ALWAYS_200), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )
    assert not chromadb_fires(OTHER_SERVER_ALWAYS_EMPTY_ARRAY), (
        "le template déclenche sur un serveur qui rend un tableau vide partout : "
        "il satisfait tout ce qu'on attend de l'index, seule la signature du "
        "heartbeat l'en sépare"
    )
    assert not chromadb_fires(CHROMA_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise d'index : un portail captif "
        "qui répond 200 suffirait à le faire remonter"
    )


# --------------------------------------------------------------------------
# Qdrant a la même fracture que ChromaDB, mais le serveur l'écrit noir sur
# blanc : api_key_whitelist épargne quatre routes de l'authentification — / en
# exact, /healthz en exact, /readyz et /livez en préfixe — et la première est
# justement la seule qui nomme le produit, index() rendant VersionInfo. Une
# instance dont la clé est posée sert donc toujours sa bannière ; la reconnaître
# seule ferait remonter les instances correctement fermées. GET /collections ne
# figure sur aucune de ces entrées et rend 401 dès qu'une clé existe — y compris
# une simple read_only_api_key, puisque AuthKeys::try_create ne rend None que si
# les trois clés sont absentes. Le template doit donc lier les deux réponses, et
# conclure sur une instance neuve, dont l'index est un tableau vide.

QDRANT_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "qdrant-no-api-key.yaml")

QDRANT_ROOT = "/"
QDRANT_COLLECTIONS = "/collections"

# VersionInfo::default() : le titre est écrit en dur dans le serveur, la version
# vient du paquet, et commit n'est sérialisé que s'il a été passé au build.
QDRANT_VERSION_BODY = (
    '{"title":"qdrant - vector search engine","version":"1.18.3",'
    '"commit":"db8fa43fcb6aedec1e739487e17a99731b74590a"}'
)

# ApiResponse<CollectionsResponse> : result, status, time — et
# CollectionDescription ne porte que le champ name.
QDRANT_COLLECTIONS_BODY = (
    '{"result":{"collections":[{"name":"support-rag"},'
    '{"name":"contrats-2026"}]},"status":"ok","time":0.000122}'
)

# La même route sur une instance qui vient d'être lancée : aucune collection
# n'a encore été créée.
QDRANT_EMPTY_COLLECTIONS_BODY = (
    '{"result":{"collections":[]},"status":"ok","time":0.000018}'
)

# Avec service.hardware_reporting, l'enveloppe porte un bloc usage de plus.
QDRANT_COLLECTIONS_USAGE_BODY = (
    '{"result":{"collections":[{"name":"support-rag"}]},"status":"ok",'
    '"time":0.000122,"usage":{"hardware":{"cpu":1,"payload_io_read":0,'
    '"payload_io_write":0,"payload_index_io_read":0,"payload_index_io_write":0,'
    '"vector_io_read":0,"vector_io_write":0},"inference":null}}'
)

# Ce que rend le middleware quand une clé est posée et qu'aucune n'est fournie :
# du texte brut, pas du JSON — HttpResponse::Unauthorized().body(e).
QDRANT_UNAUTHORIZED_BODY = "Must provide an API key or an Authorization bearer token"


def qdrant_scenario(root, collections):
    return {QDRANT_ROOT: root, QDRANT_COLLECTIONS: collections}


QDRANT_UNAUTHORIZED = (401, QDRANT_UNAUTHORIZED_BODY)

# Instance servant un corpus, sans aucune clé posée.
QDRANT_OPEN = qdrant_scenario(
    root=(200, QDRANT_VERSION_BODY),
    collections=(200, QDRANT_COLLECTIONS_BODY),
)

# La même au lendemain de son démarrage : l'index est vide. C'est celle qu'on
# trouve oubliée sur un port ouvert, et elle doit remonter.
QDRANT_OPEN_IDLE = qdrant_scenario(
    root=(200, QDRANT_VERSION_BODY),
    collections=(200, QDRANT_EMPTY_COLLECTIONS_BODY),
)

# service.hardware_reporting activé : une clé de plus dans l'enveloppe.
QDRANT_OPEN_HARDWARE_REPORTING = qdrant_scenario(
    root=(200, QDRANT_VERSION_BODY),
    collections=(200, QDRANT_COLLECTIONS_USAGE_BODY),
)

# Un intermédiaire réindente ce qu'il relaie : le corps n'est plus compact.
QDRANT_OPEN_REFORMATTED = qdrant_scenario(
    root=(200, '{\n  "title": "qdrant - vector search engine",\n'
               '  "version": "1.18.3"\n}'),
    collections=(200, '\n{\n  "result": {\n    "collections": [\n'
                      '      {\n        "name": "support-rag"\n      }\n'
                      '    ]\n  },\n  "status": "ok",\n  "time": 0.000122\n}\n'),
)

# service.api_key posé. La bannière reste servie — elle est sur la liste
# blanche — mais l'index est refusé. C'est l'instance fermée, et c'est le
# scénario qui sépare ce template d'un simple détecteur de produit.
QDRANT_API_KEY_SET = qdrant_scenario(
    root=(200, QDRANT_VERSION_BODY),
    collections=QDRANT_UNAUTHORIZED,
)

# Seule read_only_api_key est posée : try_create ne rend None que si les trois
# clés manquent, donc le middleware est monté et l'anonyme est refusé pareil.
QDRANT_READ_ONLY_API_KEY_SET = qdrant_scenario(
    root=(200, QDRANT_VERSION_BODY),
    collections=QDRANT_UNAUTHORIZED,
)

# Un proxy réglé pour tout garder, bannière comprise.
QDRANT_BEHIND_AUTH_PROXY = qdrant_scenario(
    root=(401, "Unauthorized"),
    collections=(401, "Unauthorized"),
)

# Portail captif devant une vraie instance : il laisse filer la bannière et
# répond 200 à l'index, mais avec sa page de connexion.
QDRANT_BEHIND_CAPTIVE_PORTAL = qdrant_scenario(
    root=(200, QDRANT_VERSION_BODY),
    collections=(200, "<html><body>Connexion requise</body></html>"),
)

# Un proxy qui sert la racine sur tout ce qu'on lui demande : la bannière est
# authentique, mais l'index n'a jamais répondu.
QDRANT_ROOT_MIRRORED = qdrant_scenario(
    root=(200, QDRANT_VERSION_BODY),
    collections=(200, QDRANT_VERSION_BODY),
)

# Un autre service qui sert la même enveloppe partout : il satisfait tout ce
# qu'on attend de l'index, seule la bannière l'en sépare.
OTHER_SERVER_SERVES_THE_ENVELOPE = qdrant_scenario(
    root=(200, QDRANT_COLLECTIONS_BODY),
    collections=(200, QDRANT_COLLECTIONS_BODY),
)

# Un serveur quelconque qui répond 200 à tout ce qu'on lui demande.
OTHER_SERVER_ALWAYS_OK = qdrant_scenario(
    root=(200, '{"status":"ok"}'),
    collections=(200, '{"status":"ok"}'),
)


def qdrant_block():
    doc = load(QDRANT_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(QDRANT_COLLECTIONS) for p in (b.get("path") or []))]
    assert blocks, (
        "le template n'interroge pas GET /collections — c'est pourtant la seule "
        "route du constat, la bannière de version étant épargnée par la liste "
        "blanche du middleware"
    )
    return blocks[0]


def qdrant_responses(scenario):
    """
    Range les réponses d'un scénario dans l'ordre des chemins déclarés par le
    template : c'est cet ordre qui donne son numéro à chaque body_N.
    """
    ordered = []
    for path in qdrant_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        assert route in scenario, (
            f"le template interroge un chemin que Qdrant ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def qdrant_fires(scenario):
    block = qdrant_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = qdrant_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_qdrant_probe_only_reads_and_never_touches_the_data_plane():
    doc = load(QDRANT_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'index des collections se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/points", "le template touche au plan de données : /points/scroll "
                            "rendrait les payloads, où une chaîne RAG range le texte "
                            "source en clair, et les verbes d'écriture du même "
                            "préfixe récriraient le corpus qu'il est censé protéger"),
                ("/query", "le template appelle /points/query : il ferait classer le "
                           "corpus par proximité sémantique, c'est-à-dire désigner "
                           "les passages sensibles"),
                ("/search", "le template appelle /points/search : même effet, il "
                            "ferait ressortir les documents qu'il signale"),
                ("/snapshots", "le template déclenche un instantané, donc écrit un "
                               "fichier sur le disque de l'hôte audité — ou en "
                               "télécharge un, c'est-à-dire la collection entière"),
                ("/recover", "le template appelle snapshots/recover, qui fait sortir "
                             "le serveur vers une URL et écrase la collection"),
                ("/facet", "le template agrège les payloads de l'instance qu'il "
                           "audite"),
            ):
                assert forbidden not in path, why


def test_qdrant_probe_links_the_banner_to_the_guarded_index():
    block = qdrant_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]

    assert QDRANT_ROOT in paths, (
        "le template n'interroge pas GET / — c'est la seule route qui nomme le "
        "produit, l'index des collections étant vide sur une instance neuve"
    )
    assert QDRANT_COLLECTIONS in paths, (
        "le template n'interroge pas GET /collections, la seule route dont le "
        "200 anonyme prouve qu'aucune clé n'est posée"
    )
    assert block.get("req-condition") is True, (
        "sans req-condition, les deux réponses ne peuvent pas être liées : la "
        "bannière conclurait seule, or la liste blanche du middleware l'épargne"
    )

    # Sous req-condition, le moteur évalue les extracteurs contre chacune des
    # deux réponses et émet un résultat par extracteur qui rend quelque chose :
    # deux extracteurs feraient remonter deux fois la même instance.
    assert len(block.get("extractors") or []) <= 1, (
        "le template porte plus d'un extracteur : sous req-condition, chacun "
        "rendant quelque chose ajoute un résultat, donc la même instance est "
        "signalée plusieurs fois dans un rapport de scan"
    )


def test_qdrant_matcher_needs_the_guarded_index_not_the_whitelisted_banner():
    assert qdrant_fires(QDRANT_OPEN), (
        "le template ne reconnaît pas une instance dont GET /collections répond "
        "à l'anonyme"
    )
    assert qdrant_fires(QDRANT_OPEN_IDLE), (
        "le template exige une collection dans l'index : il raterait l'instance "
        "qui vient d'être lancée, précisément celle qu'on trouve oubliée sur un "
        "port ouvert"
    )
    assert qdrant_fires(QDRANT_OPEN_HARDWARE_REPORTING), (
        "le template dépend de l'absence du bloc usage : service."
        "hardware_reporting le ferait apparaître et mettrait le matcher en défaut"
    )
    assert qdrant_fires(QDRANT_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not qdrant_fires(QDRANT_API_KEY_SET), (
        "le template déclenche sur une instance dont service.api_key est posé : "
        "son index rend 401, et seule la bannière répond encore — c'est "
        "exactement ce que la liste blanche du middleware laisse passer"
    )
    assert not qdrant_fires(QDRANT_READ_ONLY_API_KEY_SET), (
        "le template déclenche alors qu'une read_only_api_key suffit à monter le "
        "middleware : try_create ne rend None que si les trois clés manquent"
    )
    assert not qdrant_fires(QDRANT_BEHIND_AUTH_PROXY), (
        "le template déclenche sur une instance entièrement gardée"
    )
    assert not qdrant_fires(QDRANT_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise d'index : un portail captif "
        "qui répond 200 suffirait à le faire remonter"
    )
    assert not qdrant_fires(QDRANT_ROOT_MIRRORED), (
        "le template conclut d'une bannière servie sur les deux chemins : "
        "l'index n'a jamais répondu, rien ne prouve qu'il répondrait"
    )
    assert not qdrant_fires(OTHER_SERVER_SERVES_THE_ENVELOPE), (
        "le template déclenche sur un service qui sert l'enveloppe attendue "
        "partout : il satisfait tout ce qu'on attend de l'index, seule la "
        "bannière l'en sépare"
    )
    assert not qdrant_fires(OTHER_SERVER_ALWAYS_OK), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


# --------------------------------------------------------------------------
# Weaviate inverse la structure des deux templates précédents. Chez ChromaDB et
# Qdrant, la route qui nomme le produit échappe à l'authentification, et c'est
# une seconde route qui porte la preuve. Ici le middleware anonyme est global —
# anonymous.Client.Middleware enveloppe la pile entière et rend « next » tel quel
# quand l'anonyme est activé — donc GET /v1/meta est gardé comme le reste et son
# 200 est déjà le constat.
#
# Le piège est ailleurs, et il est de bonne foi : on attendrait de GET /v1/schema
# qu'il refuse en 403 quand l'autorisation écarte l'anonyme, puisque getSchema
# prévoit une branche SchemaDumpForbidden. Elle n'est jamais atteinte par cette
# route — GetConsistentSchema n'appelle pas Authorize, il passe par
# ResourceFilter.Filter, qui rend nil quand le principal est écarté, et ce vide
# est sérialisé en 200. Un dump vide ne distingue donc pas l'instance neuve de
# l'instance restreinte, et un template qui exigerait une classe pour trancher
# raterait précisément celle qu'on trouve oubliée sur un port ouvert. Ces tests
# fixent ce que le template prouve — l'accès anonyme — et ce qu'il ne prétend pas
# prouver.

WEAVIATE_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "weaviate-anonymous-access.yaml")

WEAVIATE_META = "/v1/meta"
WEAVIATE_SCHEMA = "/v1/schema"

# models.Meta sérialisé par go-swagger : les champs sortent dans l'ordre du
# struct, donc alphabétique. grpcMaxMessageSize n'existe que sur les versions
# récentes.
WEAVIATE_META_BODY = (
    '{"grpcMaxMessageSize":104858000,"hostname":"http://[::]:8080",'
    '"modules":{"text2vec-openai":{"documentationHref":'
    '"https://platform.openai.com/docs/guides/embeddings",'
    '"name":"OpenAI Module"},"generative-openai":{"documentationHref":'
    '"https://platform.openai.com/docs/api-reference/completions",'
    '"name":"Generative Search - OpenAI"}},"version":"1.34.2"}'
)

# Même route sur une instance antérieure à l'ajout de grpcMaxMessageSize, et sans
# aucun module activé : GetMeta initialise la carte avant de la remplir, donc la
# clé est sérialisée vide plutôt qu'omise. Le template doit toujours reconnaître
# celle-ci — ce sont les instances anciennes qui traînent exposées.
WEAVIATE_OLD_META_BODY = (
    '{"hostname":"http://[::]:8080","modules":{},"version":"1.19.6"}'
)

# Le dump du schéma d'une instance qui sert un corpus.
WEAVIATE_SCHEMA_BODY = (
    '{"classes":[{"class":"SupportRag","description":"Base de connaissance",'
    '"vectorizer":"text2vec-openai","vectorIndexType":"hnsw",'
    '"moduleConfig":{"text2vec-openai":{"model":"text-embedding-3-small",'
    '"vectorizeClassName":true}},'
    '"properties":[{"name":"contenu","dataType":["text"]},'
    '{"name":"source","dataType":["text"]}]},'
    '{"class":"Contrats2026","vectorizer":"text2vec-openai",'
    '"properties":[{"name":"texte","dataType":["text"]}]}]}'
)

# La même route sur une instance qui vient d'être lancée : aucune classe n'a
# encore été créée. Classes n'étant pas omitempty, la clé reste sérialisée.
WEAVIATE_EMPTY_SCHEMA_BODY = '{"classes":[]}'

# Ce qu'écrit anonymous.Client.Middleware quand l'anonyme est coupé et qu'aucun
# jeton n'est présenté — noter l'espace après "message", le corps étant assemblé
# à la main par un Sprintf plutôt que sérialisé.
WEAVIATE_ANON_DISABLED_BODY = (
    '{"code":401,"message": "anonymous access not enabled. Please authenticate '
    'through one of the available methods: [API-keys]" }'
)

# Ce que rend le dump quand l'autorisateur écarte le principal alors que le RBAC
# n'est pas actif : ResourceFilter.Filter fait « return nil » sur l'échec du seul
# Authorize qu'il tente, et une tranche nulle se sérialise en null — Classes
# n'étant pas omitempty, la clé reste écrite.
WEAVIATE_FILTERED_NULL_SCHEMA_BODY = '{"classes":null}'


def weaviate_scenario(meta, schema):
    return {WEAVIATE_META: meta, WEAVIATE_SCHEMA: schema}


# Instance servant un corpus, sans aucun schéma d'authentification configuré :
# le repli sur DefaultAuthentication a allumé l'anonyme.
WEAVIATE_OPEN = weaviate_scenario(
    meta=(200, WEAVIATE_META_BODY),
    schema=(200, WEAVIATE_SCHEMA_BODY),
)

# La même au lendemain de son démarrage : le schéma est vide. C'est celle qu'on
# trouve oubliée sur un port ouvert, et elle doit remonter.
WEAVIATE_OPEN_IDLE = weaviate_scenario(
    meta=(200, WEAVIATE_META_BODY),
    schema=(200, WEAVIATE_EMPTY_SCHEMA_BODY),
)

# Une version antérieure, sans grpcMaxMessageSize ni module activé.
WEAVIATE_OPEN_OLD = weaviate_scenario(
    meta=(200, WEAVIATE_OLD_META_BODY),
    schema=(200, WEAVIATE_SCHEMA_BODY),
)

# Un intermédiaire réindente ce qu'il relaie : le corps n'est plus compact et les
# deux-points ne touchent plus les clés.
WEAVIATE_OPEN_REFORMATTED = weaviate_scenario(
    meta=(200, '{\n  "hostname": "http://[::]:8080",\n  "modules": {},\n'
               '  "version": "1.34.2"\n}'),
    schema=(200, '\n{\n  "classes": [\n    {\n'
                 '      "class": "SupportRag"\n    }\n  ]\n}\n'),
)

# AUTHENTICATION_APIKEY_ENABLED posé : le repli ne s'applique plus, le middleware
# anonyme refuse tout ce qui n'a pas de jeton — /v1/meta compris.
WEAVIATE_ANONYMOUS_DISABLED = weaviate_scenario(
    meta=(401, WEAVIATE_ANON_DISABLED_BODY),
    schema=(401, WEAVIATE_ANON_DISABLED_BODY),
)

# L'anonyme est authentifié, mais AUTHORIZATION_ADMINLIST_ENABLED ne l'inscrit
# sur aucune de ses deux listes. Le dump n'est pas refusé pour autant : Filter
# rend nil et le serveur répond 200 null.
WEAVIATE_ADMINLIST_RESTRICTED = weaviate_scenario(
    meta=(200, WEAVIATE_META_BODY),
    schema=(200, WEAVIATE_FILTERED_NULL_SCHEMA_BODY),
)

# Même situation sous le RBAC des versions 1.29 et suivantes : le principal
# anonyme n'a aucun rôle. La branche RBAC de Filter construit une tranche vide
# plutôt que nulle, donc le corps est indiscernable de celui d'une instance
# neuve.
WEAVIATE_RBAC_RESTRICTED = weaviate_scenario(
    meta=(200, WEAVIATE_META_BODY),
    schema=(200, WEAVIATE_EMPTY_SCHEMA_BODY),
)

# Un proxy réglé pour tout garder, /v1/meta compris.
WEAVIATE_BEHIND_AUTH_PROXY = weaviate_scenario(
    meta=(401, "Unauthorized"),
    schema=(401, "Unauthorized"),
)

# Un proxy qui n'ouvre /v1/meta qu'à sa supervision et exige une
# authentification sur tout le reste : la bannière répond, le dump non.
WEAVIATE_BEHIND_PARTIAL_PROXY = weaviate_scenario(
    meta=(200, WEAVIATE_META_BODY),
    schema=(401, "Unauthorized"),
)

# Portail captif devant une vraie instance : il laisse filer /v1/meta et répond
# 200 au dump, mais avec sa page de connexion.
WEAVIATE_BEHIND_CAPTIVE_PORTAL = weaviate_scenario(
    meta=(200, WEAVIATE_META_BODY),
    schema=(200, "<html><body>Connexion requise</body></html>"),
)

# Un proxy qui sert /v1/meta sur tout ce qu'on lui demande : la bannière est
# authentique, mais le dump n'a jamais répondu.
WEAVIATE_META_MIRRORED = weaviate_scenario(
    meta=(200, WEAVIATE_META_BODY),
    schema=(200, WEAVIATE_META_BODY),
)

# Une sonde de supervision quelconque : un hôte, une version, une liste de
# modules chargés. Ces trois clés sont exactement celles de /v1/meta, et elles
# n'appartiennent à personne — seul le dump du schéma l'en sépare.
OTHER_AGENT_META_BODY = (
    '{"hostname":"gpu-node-04","version":"2.4.1",'
    '"modules":["cpu","mem","nvidia"],"uptime":918273}'
)

OTHER_MONITORING_AGENT = weaviate_scenario(
    meta=(200, OTHER_AGENT_META_BODY),
    schema=(404, '{"error":"not found"}'),
)

# Le pire de ce genre : la même sonde derrière un routeur qui lui renvoie tout,
# donc elle satisfait le premier chemin sur les deux.
OTHER_MONITORING_AGENT_MIRRORED = weaviate_scenario(
    meta=(200, OTHER_AGENT_META_BODY),
    schema=(200, OTHER_AGENT_META_BODY),
)

# Un serveur quelconque qui répond 200 à tout ce qu'on lui demande.
OTHER_SERVER_ALWAYS_UP = weaviate_scenario(
    meta=(200, '{"status":"ok"}'),
    schema=(200, '{"status":"ok"}'),
)

# Les trois qui suivent partagent le même piège, et c'est le plus sérieux du
# lot : « classes » n'appartient pas à Weaviate. Un service d'ontologie, un
# registre de schémas, un annuaire de formations en servent tous une liste, et
# rien n'empêche qu'ils la publient sous /v1/schema. Ce qui les écarte n'est donc
# pas le second chemin mais le premier — les trois clés de models.Meta réunies.
# Chacun de ces corps en porte deux sur trois, de sorte qu'aucun des trois termes
# de la signature ne peut être retiré sans qu'un de ces services remonte.

# Un service de taxonomie : il se décrit par un nom et une version.
OTHER_ONTOLOGY_SERVICE = weaviate_scenario(
    meta=(200, '{"service":"taxonomy-api","version":"3.2.0","build":"9f3c1ab"}'),
    schema=(200, '{"classes":["Person","Organisation"],'
                 '"properties":["name","memberOf"]}'),
)

# Un registre de schémas qui nomme son hôte et sa version, sans notion de module.
OTHER_SCHEMA_REGISTRY = weaviate_scenario(
    meta=(200, '{"hostname":"registry-02.corp.internal","version":"7.1.4",'
               '"uptime":918273}'),
    schema=(200, '{"classes":[{"name":"Invoice","namespace":"billing"}]}'),
)

# Un hôte d'extensions qui énumère ses modules et sa version, sans nommer sa
# machine, et dont le registre de types est encore vide.
OTHER_PLUGIN_HOST = weaviate_scenario(
    meta=(200, '{"version":"2.0.1","modules":{"auth":{"enabled":true},'
               '"billing":{"enabled":false}},"env":"prod"}'),
    schema=(200, '{"classes":[]}'),
)

# Une page d'état applicative : elle nomme sa machine et les modules qu'elle a
# chargés, mais ne publie pas de version.
OTHER_RUNTIME_STATUS = weaviate_scenario(
    meta=(200, '{"hostname":"app-07.corp.internal","node":"app@app-07",'
               '"modules":{"cache":"running","queue":"running"},"pid":4412}'),
    schema=(200, '{"classes":[{"name":"Invoice"},{"name":"Customer"}]}'),
)


def weaviate_block():
    doc = load(WEAVIATE_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(WEAVIATE_SCHEMA) for p in (b.get("path") or []))]
    assert blocks, (
        "le template n'interroge pas GET /v1/schema — c'est pourtant la seule "
        "route du constat, /v1/meta n'appelant aucun autorisateur et répondant "
        "donc encore sur une instance dont l'anonyme n'a aucun droit"
    )
    return blocks[0]


def weaviate_responses(scenario):
    """
    Range les réponses d'un scénario dans l'ordre des chemins déclarés par le
    template : c'est cet ordre qui donne son numéro à chaque body_N.
    """
    ordered = []
    for path in weaviate_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        assert route in scenario, (
            f"le template interroge un chemin que Weaviate ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def weaviate_fires(scenario):
    block = weaviate_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = weaviate_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_weaviate_probe_only_reads_and_never_touches_the_data_plane():
    doc = load(WEAVIATE_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "le dump du schéma se lit en GET : le template ne doit rien envoyer "
            "à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/objects", "le template appelle /v1/objects, qui rend les "
                             "propriétés des objets : Weaviate y range le texte "
                             "source en clair, donc le template exfiltrerait le "
                             "corpus qu'il signale"),
                ("/graphql", "le template appelle /v1/graphql : il ferait classer "
                             "le corpus par proximité sémantique, et sur une "
                             "classe vectorisée par un module hébergé il ferait "
                             "au passage vectoriser sa requête avec la clé du "
                             "fournisseur, aux frais de l'exploitant"),
                ("/batch", "le template écrit en masse dans l'instance qu'il "
                           "audite"),
                ("/backups", "le template déclenche une sauvegarde, donc écrit "
                             "sur le disque de l'hôte audité l'archive du corpus "
                             "entier"),
                ("/classifications", "le template lance une classification, qui "
                                     "récrit les objets de l'instance qu'il "
                                     "audite"),
            ):
                assert forbidden not in path, why

        # Le dump se lit sur /v1/schema tout court : le même chemin suffixé d'un
        # nom de classe accepte DELETE, qui emporte la classe et tous ses objets.
        for path in (block.get("path") or []):
            route = path.replace("{{BaseURL}}", "")
            assert not route.startswith(WEAVIATE_SCHEMA + "/"), (
                f"le template vise une classe nommée ({route}) plutôt que le "
                "dump : c'est le préfixe dont le verbe DELETE emporte la classe "
                "et tous ses objets"
            )


def test_weaviate_probe_links_the_unauthorized_meta_to_the_authorized_schema():
    block = weaviate_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]

    assert WEAVIATE_META in paths, (
        "le template n'interroge pas GET /v1/meta — c'est la seule route qui "
        "nomme le produit, le dump du schéma étant vide sur une instance neuve"
    )
    assert WEAVIATE_SCHEMA in paths, (
        "le template n'interroge pas GET /v1/schema, la seule route dont le 200 "
        "anonyme prouve que l'autorisation elle aussi laisse passer"
    )
    assert block.get("req-condition") is True, (
        "sans req-condition, les deux réponses ne peuvent pas être liées : "
        "/v1/meta conclurait seul, or son handler n'appelle aucun autorisateur"
    )

    # Sous req-condition, le moteur évalue les extracteurs contre chacune des
    # deux réponses et émet un résultat par extracteur qui rend quelque chose :
    # deux extracteurs feraient remonter deux fois la même instance.
    assert len(block.get("extractors") or []) <= 1, (
        "le template porte plus d'un extracteur : sous req-condition, chacun "
        "rendant quelque chose ajoute un résultat, donc la même instance est "
        "signalée plusieurs fois dans un rapport de scan"
    )


def test_weaviate_matcher_needs_the_authorized_dump_not_just_the_meta_route():
    assert weaviate_fires(WEAVIATE_OPEN), (
        "le template ne reconnaît pas une instance dont GET /v1/schema répond à "
        "l'anonyme"
    )
    assert weaviate_fires(WEAVIATE_OPEN_IDLE), (
        "le template exige une classe dans le dump : il raterait l'instance qui "
        "vient d'être lancée, précisément celle qu'on trouve oubliée sur un port "
        "ouvert"
    )
    assert weaviate_fires(WEAVIATE_OPEN_OLD), (
        "le template exige des clés absentes des versions plus anciennes — "
        "grpcMaxMessageSize est omitempty et n'a été ajouté que tard, et modules "
        "est sérialisé vide quand aucun n'est activé — il raterait les instances "
        "qui traînent exposées"
    )
    assert weaviate_fires(WEAVIATE_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not weaviate_fires(WEAVIATE_ANONYMOUS_DISABLED), (
        "le template déclenche sur une instance dont un autre schéma "
        "d'authentification est configuré : le repli sur DefaultAuthentication ne "
        "s'applique plus et le middleware anonyme refuse tout"
    )
    assert not weaviate_fires(WEAVIATE_BEHIND_AUTH_PROXY), (
        "le template déclenche sur une instance entièrement gardée"
    )
    assert not weaviate_fires(WEAVIATE_BEHIND_PARTIAL_PROXY), (
        "le template conclut de la seule bannière : un proxy peut n'ouvrir "
        "/v1/meta qu'à sa supervision et garder tout le reste, auquel cas l'API "
        "n'est pas atteignable — c'est le statut du second chemin qui l'établit"
    )
    assert not weaviate_fires(WEAVIATE_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise de dump : un portail captif "
        "qui répond 200 suffirait à le faire remonter"
    )
    assert not weaviate_fires(WEAVIATE_META_MIRRORED), (
        "le template conclut d'un /v1/meta servi sur les deux chemins : le dump "
        "n'a jamais répondu, rien ne prouve qu'il répondrait"
    )
    assert not weaviate_fires(OTHER_MONITORING_AGENT), (
        "le template déclenche sur une sonde de supervision qui n'est pas "
        "Weaviate : hostname, version et modules sont les trois clés qu'écrirait "
        "n'importe quel agent décrivant sa machine"
    )
    assert not weaviate_fires(OTHER_MONITORING_AGENT_MIRRORED), (
        "le template déclenche sur la même sonde derrière un routeur qui lui "
        "renvoie tout : elle satisfait le premier chemin sur les deux, seul le "
        "dump du schéma l'en sépare"
    )
    assert not weaviate_fires(OTHER_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )

    # « classes » est un mot banal : ce sont les trois clés de models.Meta,
    # réunies, qui désignent le produit. Chacun de ces services en porte deux,
    # donc chacun remonterait si l'une des trois était retirée de la signature.
    assert not weaviate_fires(OTHER_ONTOLOGY_SERVICE), (
        "le template déclenche sur un service de taxonomie qui publie ses "
        "classes sous /v1/schema : une version ne désigne aucun produit"
    )
    assert not weaviate_fires(OTHER_SCHEMA_REGISTRY), (
        "le template déclenche sur un registre de schémas qui nomme son hôte et "
        "sa version : sans « modules », la signature n'est plus celle de "
        "models.Meta"
    )
    assert not weaviate_fires(OTHER_PLUGIN_HOST), (
        "le template déclenche sur un hôte d'extensions qui énumère ses modules "
        "et sa version : sans « hostname », la signature n'est plus celle de "
        "models.Meta"
    )
    assert not weaviate_fires(OTHER_RUNTIME_STATUS), (
        "le template déclenche sur une page d'état qui nomme sa machine et ses "
        "modules : sans « version », la signature n'est plus celle de models.Meta"
    )


def test_weaviate_reports_anonymous_access_and_claims_nothing_of_authorization():
    """
    La frontière que le template revendique, fixée dans les deux sens.

    Une instance dont l'anonyme est authentifié mais dont l'autorisation ne lui
    accorde rien remonte quand même, et c'est délibéré : le dump n'est pas
    refusé mais filtré, donc son vide est indiscernable de celui d'une instance
    neuve — sous RBAC, Filter construit une tranche vide, exactement le corps
    d'un serveur qui n'a rien indexé. Trancher demanderait d'exiger une classe,
    ce qui reviendrait à ne plus voir l'instance oubliée sur un port ouvert.

    Le constat rapporté est donc l'accès anonyme lui-même, ce qui se tient :
    l'autorisation est facultative et absente par défaut, configureAuthorizer
    retombant sur DummyAuthorizer, qui accorde tout. Ce test existe pour que ce
    choix reste un choix — si quelqu'un resserre le matcher au point de rejeter
    ces deux scénarios, il aura du même coup rendu le template aveugle à
    l'instance neuve, et c'est ici qu'il doit s'en apercevoir.
    """
    assert weaviate_fires(WEAVIATE_ADMINLIST_RESTRICTED), (
        "le template ne remonte pas une instance dont l'anonyme est authentifié "
        "et dont le dump rend 200 null : le corps est celui qu'écrit Filter en "
        "écartant le principal, mais rien ne le distingue d'un serveur dont la "
        "tranche de classes est nulle faute de classe"
    )
    assert weaviate_fires(WEAVIATE_RBAC_RESTRICTED), (
        "le template ne remonte pas une instance sous RBAC dont l'anonyme n'a "
        "aucun rôle : son dump rend 200 et une liste vide, soit exactement le "
        "corps d'une instance neuve — le rejeter reviendrait à rater cette "
        "dernière"
    )

    # La contrepartie de ce choix : ces deux corps doivent rester ceux d'une
    # instance neuve, sans quoi le raisonnement ci-dessus ne tient plus.
    assert WEAVIATE_EMPTY_SCHEMA_BODY in (
        WEAVIATE_RBAC_RESTRICTED[WEAVIATE_SCHEMA][1],
        WEAVIATE_FILTERED_NULL_SCHEMA_BODY,
    ), "le scénario RBAC ne modélise plus le corps d'un dump filtré à vide"


# --------------------------------------------------------------------------
# Milvus est le cas où le template a le plus de chances d'être écrit faux, et de
# deux façons opposées.
#
# La première est de le poser sur 9091, seul port réputé servir de l'HTTP. Ce
# port ne porte que la supervision — /healthz, /livez, /metrics, /webui/ et les
# routes /management/* — et son « OK » ne nomme aucun produit. L'API RESTful est
# ailleurs : proxy.http.enabled vaut true et proxy.http.port est laissé vide dans
# le milvus.yaml livré, donc le mode port partagé s'applique et le routeur gin
# est servi sous h2c sur 19530, derrière un httpHandler qui n'aiguille vers le
# serveur gRPC que les requêtes portant « Content-Type: application/grpc ».
#
# La seconde est de conclure d'un seul 200. Le groupe /v2/vectordb rend
# {"code":0,"data":[…]} sur ses deux routes d'énumération, et cette enveloppe
# n'appartient à personne : c'est celle de quantité d'API sans rapport. Ce qui
# désigne Milvus est le contenu invariant du registre des bases — « default » y
# figure toujours, CheckIfDatabaseDroppable refusant de le supprimer et
# reloadDatabases le recréant au démarrage.
#
# Ces tests fixent les deux bornes : le template doit reconnaître l'instance
# neuve, dont l'index des collections est vide, et rejeter aussi bien
# l'authentification posée que l'enveloppe générique.

MILVUS_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "milvus-exposed.yaml")

MILVUS_DATABASES = "/v2/vectordb/databases/list"
MILVUS_COLLECTIONS = "/v2/vectordb/collections/list"

# Le registre des bases d'une instance qui en a créé une seconde.
MILVUS_DATABASES_BODY = '{"code":0,"data":["default","rag_prod"]}'

# La même sur une instance qui n'a jamais rien créé : « default » demeure.
MILVUS_DEFAULT_DATABASE_ONLY_BODY = '{"code":0,"data":["default"]}'

# L'index des corpus d'une instance qui en sert.
MILVUS_COLLECTIONS_BODY = '{"code":0,"data":["support_rag","contrats_2026"]}'

# Le même au lendemain du démarrage : wrapperReturnList sérialise « data » même
# quand la tranche est nulle, donc la clé reste écrite.
MILVUS_EMPTY_COLLECTIONS_BODY = '{"code":0,"data":[]}'

# Ce qu'écrit le middleware authenticate quand authorizationEnabled est posé et
# qu'aucune identité n'est présentée : merr.ErrNeedAuthenticate porte le code
# 1800 et ce message.
MILVUS_NEED_AUTHENTICATE_BODY = (
    '{"code":1800,"message":"user hasn\'t authenticated"}'
)

# Une erreur applicative, rendue par HTTPAbortReturn : le statut reste 200, mais
# le corps ne porte que « code » et « message ». C'est ce cas que la clé
# « data » sépare du chemin nominal.
MILVUS_APPLICATION_ERROR_BODY = (
    '{"code":800,"message":"database not found, database: absente"}'
)


def milvus_scenario(databases, collections):
    return {MILVUS_DATABASES: databases, MILVUS_COLLECTIONS: collections}


# Instance servant un corpus, authorizationEnabled laissé à false : le
# middleware authenticate n'est pas monté du tout.
MILVUS_OPEN = milvus_scenario(
    databases=(200, MILVUS_DATABASES_BODY),
    collections=(200, MILVUS_COLLECTIONS_BODY),
)

# La même au lendemain de son démarrage : aucune collection, aucune base créée.
# C'est celle qu'on trouve oubliée sur un port ouvert, et elle doit remonter.
MILVUS_OPEN_IDLE = milvus_scenario(
    databases=(200, MILVUS_DEFAULT_DATABASE_ONLY_BODY),
    collections=(200, MILVUS_EMPTY_COLLECTIONS_BODY),
)

# Un intermédiaire réindente ce qu'il relaie : le corps n'est plus compact et les
# deux-points ne touchent plus les clés.
MILVUS_OPEN_REFORMATTED = milvus_scenario(
    databases=(200, '{\n  "code": 0,\n  "data": [\n    "default"\n  ]\n}'),
    collections=(200, '\n{\n  "code": 0,\n  "data": [\n    "support_rag"\n  ]\n}\n'),
)

# common.security.authorizationEnabled posé : le middleware est global et
# n'épargne aucune route, donc les deux chemins refusent.
MILVUS_AUTHORIZATION_ENABLED = milvus_scenario(
    databases=(401, MILVUS_NEED_AUTHENTICATE_BODY),
    collections=(401, MILVUS_NEED_AUTHENTICATE_BODY),
)

# Un proxy réglé pour tout garder.
MILVUS_BEHIND_AUTH_PROXY = milvus_scenario(
    databases=(401, "Unauthorized"),
    collections=(401, "Unauthorized"),
)

# Un proxy qui n'ouvre le registre des bases qu'à sa supervision et exige une
# authentification sur tout le reste : la signature répond, l'index non.
MILVUS_BEHIND_PARTIAL_PROXY = milvus_scenario(
    databases=(200, MILVUS_DATABASES_BODY),
    collections=(401, "Unauthorized"),
)

# Portail captif devant une vraie instance : sa page de connexion répond 200 et
# embarque son état initial, donc les deux clés de l'enveloppe s'y trouvent.
MILVUS_BEHIND_CAPTIVE_PORTAL = milvus_scenario(
    databases=(200, MILVUS_DATABASES_BODY),
    collections=(200, '<html><body>Connexion requise'
                      '<script>window.__STATE__={"code":0,"data":[]}</script>'
                      '</body></html>'),
)

# Les deux qui suivent modélisent le même intermédiaire : un cache placé devant
# l'instance, réglé pour exiger une identité depuis qu'authorizationEnabled a été
# posé, mais qui relaie encore le corps qu'il détient sous le statut du refus.
# Ils n'existent que pour que le statut de chaque réponse reste vérifié : le
# corps, lui, est authentique et satisferait toutes les autres conditions.
MILVUS_CACHED_DATABASES_UNDER_REFUSAL = milvus_scenario(
    databases=(401, MILVUS_DATABASES_BODY),
    collections=(200, MILVUS_COLLECTIONS_BODY),
)

MILVUS_CACHED_COLLECTIONS_UNDER_REFUSAL = milvus_scenario(
    databases=(200, MILVUS_DATABASES_BODY),
    collections=(401, MILVUS_COLLECTIONS_BODY),
)

# L'index a bien répondu 200, mais sur une erreur applicative : pas de « data ».
MILVUS_APPLICATION_ERROR = milvus_scenario(
    databases=(200, MILVUS_DATABASES_BODY),
    collections=(200, MILVUS_APPLICATION_ERROR_BODY),
)

# L'enveloppe {"code":…,"data":…} est la convention de quantité d'API sans
# rapport avec Milvus. Celle-ci répond 200 sur les deux chemins ; seul
# « default » l'en sépare.
OTHER_CODE_DATA_ENVELOPE = milvus_scenario(
    databases=(200, '{"code":0,"data":[],"message":"success"}'),
    collections=(200, '{"code":0,"data":[],"message":"success"}'),
)

# Un serveur quelconque qui répond 200 à tout ce qu'on lui demande.
MILVUS_SERVER_ALWAYS_UP = milvus_scenario(
    databases=(200, '{"status":"ok"}'),
    collections=(200, '{"status":"ok"}'),
)


def milvus_block():
    doc = load(MILVUS_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(MILVUS_COLLECTIONS) for p in (b.get("path") or []))]
    assert blocks, (
        "le template n'interroge pas POST /v2/vectordb/collections/list — c'est "
        "l'index des corpus, donc le constat, et le port 9091 ne sert que la "
        "supervision"
    )
    return blocks[0]


def milvus_responses(scenario):
    """
    Range les réponses d'un scénario dans l'ordre des chemins déclarés par le
    template : c'est cet ordre qui donne son numéro à chaque body_N.
    """
    ordered = []
    for path in milvus_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        assert route in scenario, (
            f"le template interroge un chemin que Milvus ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def milvus_fires(scenario):
    block = milvus_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = milvus_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_milvus_probe_targets_the_restful_api_not_the_metrics_port():
    block = milvus_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]

    assert MILVUS_DATABASES in paths, (
        "le template n'interroge pas POST /v2/vectordb/databases/list — c'est la "
        "seule route dont le corps désigne le produit, « default » y figurant "
        "toujours, l'index des collections étant vide sur une instance neuve"
    )
    assert MILVUS_COLLECTIONS in paths, (
        "le template n'interroge pas POST /v2/vectordb/collections/list, l'index "
        "des corpus"
    )
    assert all(p.startswith("/v2/vectordb/") for p in paths), (
        "le template sort du groupe /v2/vectordb : le port 9091 ne sert que la "
        "supervision — /healthz rend « OK », qui ne nomme aucun produit — et "
        "l'API v1 héritée ne couvre pas ce que couvre déjà v2"
    )
    for path in paths:
        assert "healthz" not in path and "livez" not in path, (
            "le template conclut d'une sonde de vivacité : elle répond « OK » "
            "aussi bien sur une instance dont authorizationEnabled est posé, "
            "donc elle ne prouve rien"
        )

    assert block.get("method") == "POST", (
        "le groupe /v2/vectordb n'enregistre que des routes POST : un GET y "
        "rendrait le 404 de gin, qui ne prouverait rien"
    )
    assert block.get("req-condition") is True, (
        "sans req-condition, les deux réponses ne peuvent pas être liées : "
        "l'index des collections conclurait seul, or son corps ne porte aucune "
        "signature quand l'instance est neuve"
    )


def test_milvus_probe_only_reads_and_never_touches_the_data_plane():
    doc = load(MILVUS_TEMPLATE)

    for block in (doc.get("http") or []):
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/entities/", "le template appelle une route /entities/ : "
                               "/query et /get rendent les champs scalaires, où "
                               "une chaîne RAG range le texte source en clair, "
                               "/search classerait le corpus par proximité "
                               "sémantique, et /insert, /upsert et /delete y "
                               "écriraient — le template exfiltrerait ou "
                               "récrirait le corpus qu'il signale"),
                ("/drop", "le template appelle une route de suppression sur "
                          "l'instance qu'il audite"),
                ("/truncate", "le template vide une collection de l'instance "
                              "qu'il audite"),
                ("/jobs/", "le template appelle une route d'import : le serveur "
                           "irait chercher les fichiers qu'on lui désigne"),
                ("/users/", "le template touche le plan d'administration des "
                            "comptes : /users/create y inscrirait un compte qui "
                            "survivrait à l'activation de l'authentification"),
                ("/roles/", "le template touche le plan d'administration des "
                            "rôles"),
                ("/create", "le template crée un objet sur l'instance qu'il "
                            "audite"),
            ):
                assert forbidden not in path, why

        # Ces routes ne se lisent qu'en POST, donc le corps envoyé est le seul
        # garde-fou : c'est lui qui doit rester vide.
        sent = json.loads(block.get("body") or "null")
        assert sent == {}, (
            f"le template envoie autre chose qu'un corps vide ({sent!r}) : les "
            "champs de ces requêtes — collectionName, filter, data — sont "
            "précisément ceux par lesquels ces routes rendent ou modifient des "
            "données"
        )


def test_milvus_extractor_is_scoped_to_the_collection_index():
    block = milvus_block()
    extractors = block.get("extractors") or []

    # Sous req-condition, le moteur évalue les extracteurs contre chacune des
    # deux réponses et émet un résultat par extracteur qui rend quelque chose :
    # deux extracteurs feraient remonter deux fois la même instance.
    assert len(extractors) <= 1, (
        "le template porte plus d'un extracteur : sous req-condition, chacun "
        "rendant quelque chose ajoute un résultat, donc la même instance est "
        "signalée plusieurs fois dans un rapport de scan"
    )

    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]
    for extractor in extractors:
        part = extractor.get("part")
        assert part == f"body_{paths.index(MILVUS_COLLECTIONS) + 1}", (
            "l'extracteur n'est pas borné à la réponse de l'index des "
            f"collections (part={part!r}) : les deux chemins rendent leur "
            "contenu sous la même clé « data », donc « default » entrerait dans "
            "le rapport comme s'il était une collection"
        )


def test_milvus_matcher_needs_the_default_database_not_a_generic_envelope():
    assert milvus_fires(MILVUS_OPEN), (
        "le template ne reconnaît pas une instance dont l'API RESTful répond à "
        "une requête sans en-tête d'autorisation"
    )
    assert milvus_fires(MILVUS_OPEN_IDLE), (
        "le template exige une collection dans l'index : il raterait l'instance "
        "qui vient d'être lancée, précisément celle qu'on trouve oubliée sur un "
        "port ouvert — wrapperReturnList sérialise pourtant « data » même vide"
    )
    assert milvus_fires(MILVUS_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not milvus_fires(MILVUS_AUTHORIZATION_ENABLED), (
        "le template déclenche sur une instance dont "
        "common.security.authorizationEnabled est posé : le middleware "
        "authenticate est alors global et rend 401 avec le code 1800 sur les "
        "deux chemins"
    )
    assert not milvus_fires(MILVUS_BEHIND_AUTH_PROXY), (
        "le template déclenche sur une instance entièrement gardée"
    )
    assert not milvus_fires(MILVUS_BEHIND_PARTIAL_PROXY), (
        "le template conclut de la seule signature : un proxy peut n'ouvrir le "
        "registre des bases qu'à sa supervision et garder tout le reste, auquel "
        "cas l'index n'est pas atteignable — c'est le statut du second chemin "
        "qui l'établit"
    )
    assert not milvus_fires(MILVUS_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise d'index : un portail captif "
        "qui embarque son état initial porte les deux clés de l'enveloppe et "
        "suffirait à le faire remonter"
    )
    assert not milvus_fires(MILVUS_CACHED_DATABASES_UNDER_REFUSAL), (
        "le template conclut du seul corps du registre des bases : un cache "
        "placé devant l'instance peut relayer celui qu'il détient sous le "
        "statut du refus, et ce corps-là ne prouve plus rien"
    )
    assert not milvus_fires(MILVUS_CACHED_COLLECTIONS_UNDER_REFUSAL), (
        "le template conclut du seul corps de l'index : le même cache le "
        "relaierait sous un 401, alors que l'API, elle, a refusé"
    )
    assert not milvus_fires(MILVUS_APPLICATION_ERROR), (
        "le template conclut du seul statut de l'index : HTTPAbortReturn rend "
        "les erreurs en 200, et seule l'absence de « data » les distingue du "
        "chemin nominal"
    )
    assert not milvus_fires(OTHER_CODE_DATA_ENVELOPE), (
        "le template déclenche sur une API qui n'est pas Milvus : "
        "{\"code\":…,\"data\":…} est une enveloppe banale, et c'est « default » "
        "dans le registre des bases qui désigne le produit"
    )
    assert not milvus_fires(MILVUS_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


# --------------------------------------------------------------------------
# MLflow est le premier du pack dont une seule requête porte tout le constat, et
# c'est une propriété du serveur, pas un raccourci : le crochet before_request de
# l'application d'authentification est global et n'épargne que trois préfixes —
# _UNPROTECTED_PATH_PREFIXES vaut ("/static", "/favicon.ico", "/health"). Une
# instance fermée refuse donc /api/2.0/mlflow/experiments/search comme le reste,
# et son 200 anonyme suffit. Le corollaire est que /health est exactement la
# route à ne pas interroger : elle rend « OK » dans les deux cas.
#
# Le piège de rédaction est ailleurs, et il est sérieux : « experiments » et
# « experiment_id » sont mot pour mot le vocabulaire des plateformes
# d'expérimentation A/B, qui servent la même liste sous les mêmes noms. Ce qui
# désigne MLflow est la paire suivante — « artifact_location », le dépôt où
# atterrissent les poids, et « lifecycle_stage », dont le domaine se réduit à
# « active » et « deleted ».
#
# Les corps ci-dessous fixent les deux bornes : le template doit reconnaître
# l'instance neuve comme celle dont l'expérience « Default » a été rangée, tenir
# quelle que soit l'indentation — message_to_json sérialise avec pretty=True
# depuis peu, non indenté auparavant — et rejeter aussi bien l'authentification
# posée que le vocabulaire voisin. Chacun des quatre corps étrangers porte trois
# des quatre clés, de sorte qu'aucun terme de la signature ne peut être retiré
# sans qu'un de ces services remonte.

MLFLOW_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                               "mlflow-tracking-server-unauth.yaml")

MLFLOW_SEARCH = "/api/2.0/mlflow/experiments/search"

# Réponse de _search_experiments telle que message_to_json la sérialise
# aujourd'hui : preserving_proto_field_name=True, pretty=True donc indent=2, et
# les int64 rendus en nombres.
MLFLOW_EXPERIMENTS_BODY = """{
  "experiments": [
    {
      "experiment_id": "0",
      "name": "Default",
      "artifact_location": "mlflow-artifacts:/0",
      "lifecycle_stage": "active",
      "last_update_time": 1753900000000,
      "creation_time": 1753900000000
    },
    {
      "experiment_id": "3",
      "name": "support-rag-finetune",
      "artifact_location": "s3://ml-artifacts-prod/3",
      "lifecycle_stage": "active",
      "last_update_time": 1754000000000,
      "creation_time": 1753950000000
    }
  ]
}"""

# La même instance au lendemain de son démarrage. _initialize_store_state appelle
# _create_default_experiment quand l'identifiant 0 manque, donc l'index n'est
# jamais vide — c'est celle qu'on trouve oubliée sur un port ouvert, et elle doit
# remonter.
MLFLOW_FRESH_INSTALL_BODY = """{
  "experiments": [
    {
      "experiment_id": "0",
      "name": "Default",
      "artifact_location": "mlflow-artifacts:/0",
      "lifecycle_stage": "active",
      "last_update_time": 1753900000000,
      "creation_time": 1753900000000
    }
  ]
}"""

# L'inverse : un exploitant qui a supprimé l'expérience « Default ». Rien ne
# l'en empêche — à la différence de la base « default » de Milvus — et
# search_experiments ne rend par défaut que les actives, donc le nom disparaît de
# la réponse. Le template ne doit pas en dépendre.
MLFLOW_WITHOUT_DEFAULT_EXPERIMENT_BODY = """{
  "experiments": [
    {
      "experiment_id": "7",
      "name": "forecast-conso",
      "artifact_location": "wasbs://artifacts@mlstore.blob.core.windows.net/7",
      "lifecycle_stage": "active",
      "last_update_time": 1754100000000,
      "creation_time": 1754050000000
    }
  ]
}"""

# La sérialisation des versions antérieures à l'ajout du paramètre pretty, et
# aussi bien ce qu'un intermédiaire recompacte en relayant : plus d'indentation,
# les deux-points collés aux clés.
MLFLOW_COMPACT_BODY = (
    '{"experiments":[{"experiment_id":"0","name":"Default",'
    '"artifact_location":"./mlruns/0","lifecycle_stage":"active",'
    '"creation_time":1753900000000,"last_update_time":1753900000000}]}'
)

# Ce qu'écrit make_basic_auth_response quand « --app-name basic-auth » est posé :
# 401, l'en-tête WWW-Authenticate, et un texte — make_response sur une chaîne,
# donc text/html, pas du JSON.
MLFLOW_BASIC_AUTH_BODY = (
    "You are not authenticated. Please see "
    "https://www.mlflow.org/docs/latest/auth/index.html#authenticating-to-mlflow "
    "on how to authenticate."
)

# Une plateforme d'expérimentation A/B : même mot, même clé d'identifiant, aucun
# rapport. C'est le faux positif que le template doit écarter en premier.
OTHER_AB_TESTING_BODY = (
    '{"experiments":[{"experiment_id":"exp_7f2","name":"checkout-cta",'
    '"status":"running","variants":[{"key":"control","weight":50},'
    '{"key":"treatment","weight":50}],"created_at":"2026-05-02T09:14:00Z"}]}'
)

# Un autre suivi d'entraînement, qui nomme son identifiant « id » : sans
# « experiment_id », le vocabulaire n'est plus celui de MLflow.
OTHER_TRACKER_WITHOUT_EXPERIMENT_ID_BODY = (
    '{"experiments":[{"id":"14","name":"tabular-baseline",'
    '"artifact_location":"s3://runs/14","lifecycle_stage":"active"}]}'
)

# Un catalogue interne d'expériences, qui a repris le vocabulaire de cycle de vie
# de MLflow — beaucoup d'outils maison le copient — mais ne range aucun artefact,
# donc n'a pas de dépôt à nommer. C'est le corps qui rend « artifact_location »
# indispensable : sans cette clé, la signature ne sépare plus le serveur de ce
# qui l'imite, et le renseignement qui fait la sévérité — l'emplacement des
# poids — disparaît du constat.
OTHER_CATALOG_WITHOUT_ARTIFACT_LOCATION_BODY = (
    '{"experiments":[{"experiment_id":"14","name":"tabular-baseline",'
    '"lifecycle_stage":"active","owner":"ml-platform",'
    '"updated_at":"2026-06-11T08:02:00Z"}]}'
)

# Le même en sens inverse : il connaît l'identifiant et le dépôt, mais parle
# d'état plutôt que de cycle de vie.
OTHER_TRACKER_WITHOUT_LIFECYCLE_BODY = (
    '{"experiments":[{"experiment_id":"14","name":"tabular-baseline",'
    '"artifact_location":"gs://ml-runs/14","status":"ACTIVE"}]}'
)

# Un agrégateur qui republie des enregistrements MLflow sous sa propre
# enveloppe : les trois clés de l'objet y sont, la clé de collection non. Ce
# n'est pas le serveur, et ce n'est donc pas le constat.
OTHER_AGGREGATOR_BODY = (
    '{"items":[{"experiment_id":"14","name":"tabular-baseline",'
    '"artifact_location":"s3://ml-runs/14","lifecycle_stage":"active"}],'
    '"next_page_token":"eyJvIjoyMH0"}'
)

# Portail captif devant une vraie instance : sa page de connexion répond 200 et
# embarque son état initial, donc les quatre clés s'y trouvent. Seul le type de
# contenu l'en sépare.
MLFLOW_CAPTIVE_PORTAL_BODY = (
    '<!doctype html><html><head><title>SSO</title></head><body>'
    '<script>window.__STATE__={"experiments":[{"experiment_id":"0",'
    '"name":"Default","artifact_location":"mlflow-artifacts:/0",'
    '"lifecycle_stage":"active"}]}</script></body></html>'
)


def mlflow_response(status, body, content_type="application/json"):
    """
    Une réponse HTTP réduite à ce que les matchers du template observent : le
    statut, le bloc d'en-têtes brut — c'est contre lui que nuclei évalue
    `part: header` — et le corps.
    """
    return {
        "status": status,
        "headers": (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {content_type}\r\n"
            "Server: gunicorn\r\n"
        ),
        "body": body,
    }


# Instance servie sans « --app-name basic-auth » : aucun crochet before_request
# n'est enregistré, la route répond.
MLFLOW_OPEN = mlflow_response(200, MLFLOW_EXPERIMENTS_BODY)

# La même au lendemain de son démarrage, puis celle dont « Default » a été
# supprimée, puis la sérialisation non indentée.
MLFLOW_OPEN_FRESH = mlflow_response(200, MLFLOW_FRESH_INSTALL_BODY)
MLFLOW_OPEN_WITHOUT_DEFAULT = mlflow_response(
    200, MLFLOW_WITHOUT_DEFAULT_EXPERIMENT_BODY)
MLFLOW_OPEN_COMPACT = mlflow_response(200, MLFLOW_COMPACT_BODY)

# Un proxy qui ajoute le jeu de caractères au type de contenu qu'il relaie.
MLFLOW_OPEN_BEHIND_PROXY = mlflow_response(
    200, MLFLOW_EXPERIMENTS_BODY, content_type="application/json; charset=utf-8")

# « --app-name basic-auth » posé : le crochet est global et n'épargne pas cette
# route.
MLFLOW_BASIC_AUTH_ENABLED = mlflow_response(
    401, MLFLOW_BASIC_AUTH_BODY, content_type="text/html; charset=utf-8")

# Un proxy réglé pour tout garder.
MLFLOW_BEHIND_AUTH_PROXY = mlflow_response(
    403, "<html><body><h1>403 Forbidden</h1></body></html>",
    content_type="text/html")

# Un cache placé devant l'instance, réglé pour exiger une identité depuis que
# l'authentification a été posée, mais qui relaie encore le corps qu'il détient
# sous le statut du refus. Il n'existe que pour que le statut reste vérifié : le
# corps, lui, est authentique.
MLFLOW_CACHED_BODY_UNDER_REFUSAL = mlflow_response(401, MLFLOW_EXPERIMENTS_BODY)

MLFLOW_AB_TESTING_PLATFORM = mlflow_response(200, OTHER_AB_TESTING_BODY)
MLFLOW_TRACKER_WITHOUT_EXPERIMENT_ID = mlflow_response(
    200, OTHER_TRACKER_WITHOUT_EXPERIMENT_ID_BODY)
MLFLOW_CATALOG_WITHOUT_ARTIFACT_LOCATION = mlflow_response(
    200, OTHER_CATALOG_WITHOUT_ARTIFACT_LOCATION_BODY)
MLFLOW_TRACKER_WITHOUT_LIFECYCLE = mlflow_response(
    200, OTHER_TRACKER_WITHOUT_LIFECYCLE_BODY)
MLFLOW_AGGREGATOR = mlflow_response(200, OTHER_AGGREGATOR_BODY)
MLFLOW_BEHIND_CAPTIVE_PORTAL = mlflow_response(
    200, MLFLOW_CAPTIVE_PORTAL_BODY, content_type="text/html; charset=utf-8")

# Un serveur quelconque qui répond 200 à tout ce qu'on lui demande.
MLFLOW_SERVER_ALWAYS_UP = mlflow_response(200, "OK", content_type="text/plain")


def mlflow_search_block():
    doc = load(MLFLOW_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.replace("{{BaseURL}}", "") == MLFLOW_SEARCH
                     for p in (b.get("path") or []))]
    assert blocks, f"le template ne vise pas GET {MLFLOW_SEARCH}"
    return blocks[0]


def mlflow_fires(response):
    """
    Sémantique nuclei du bloc entier contre une réponse unique : statut,
    en-têtes et corps. Le template n'ayant qu'un chemin, il n'y a pas de
    req-condition et chaque matcher voit la même réponse.
    """
    block = mlflow_search_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"

    verdicts = []
    for matcher in matchers:
        kind = matcher.get("type")
        if kind == "status":
            verdicts.append(response["status"] in (matcher.get("status") or []))
        elif matcher.get("part") == "header":
            verdicts.append(word_matcher_hits(matcher, response["headers"]))
        else:
            verdicts.append(body_matcher_hits(matcher, response["body"]))

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_mlflow_probe_reads_the_search_route_and_never_touches_the_artifacts():
    doc = load(MLFLOW_TEMPLATE)
    block = mlflow_search_block()

    assert block.get("method") == "GET", (
        "l'index des expériences se lit en GET — service.proto déclare "
        "searchExperiments sur POST et sur GET depuis la version 2.0 — donc le "
        "template ne doit rien envoyer à une instance qu'il découvre"
    )
    assert block.get("body") is None, (
        "le template envoie un corps : la route se lit sans paramètre, "
        "_get_request_message ne consultant flask_request.args que si la requête "
        "en porte"
    )

    for other in (doc.get("http") or []):
        for path in (other.get("path") or []):
            assert "?" not in path, (
                "le template passe des paramètres de requête : une chaîne vide "
                "laisse max_results à son défaut de 1000 et view_type à "
                "ACTIVE_ONLY, il n'y a rien à préciser"
            )
            for forbidden, why in (
                ("/mlflow-artifacts/",
                 "le template appelle la route de relais des artefacts : elle "
                 "rend les fichiers — poids, jeux de données, ce que le code "
                 "d'entraînement a enregistré — avec les identifiants de dépôt "
                 "du serveur, donc le template exfiltrerait ce qu'il signale"),
                ("get-artifact",
                 "le template télécharge un artefact de l'instance qu'il audite"),
                ("/runs/",
                 "le template lit le plan des exécutions : les paramètres "
                 "enregistrés par mlflow.log_param et mlflow.autolog y portent "
                 "les chaînes de connexion du code d'entraînement"),
                ("/registered-models/",
                 "le template touche le registre des modèles : une version ou un "
                 "alias posés là survivraient à la fermeture de l'instance"),
                ("/create",
                 "le template crée un objet sur l'instance qu'il audite"),
                ("/delete",
                 "le template appelle une route de suppression sur l'instance "
                 "qu'il audite"),
                ("/set-",
                 "le template écrit une étiquette sur l'instance qu'il audite"),
            ):
                assert forbidden not in path, why

            assert "/health" not in path, (
                "le template interroge /health : c'est l'un des trois préfixes "
                "que le crochet before_request épargne — "
                "_UNPROTECTED_PATH_PREFIXES vaut (\"/static\", \"/favicon.ico\", "
                "\"/health\") — donc il rend « OK » sur une instance "
                "correctement fermée aussi, et il ne nomme aucun produit"
            )


def test_mlflow_extractors_stay_on_the_experiment_index():
    block = mlflow_search_block()
    extractors = block.get("extractors") or []
    assert extractors, (
        "le template ne remonte rien à l'exploitant : signaler que le port "
        "répond ne lui dit ni quels projets sont lisibles ni où sont les "
        "artefacts"
    )

    # Plusieurs extracteurs ne sont admissibles que parce qu'il n'y a qu'un
    # chemin : sous req-condition, chacun rendant quelque chose ajouterait un
    # résultat, donc la même instance remonterait plusieurs fois.
    assert block.get("req-condition") is not True, (
        "le bloc porte req-condition alors qu'il n'interroge qu'un chemin : les "
        "extracteurs y seraient évalués réponse par réponse"
    )

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "l'extracteur ne lit pas le JSON de la réponse : une expression "
            "libre remonterait aussi bien des fragments de page"
        )
        for expression in (extractor.get("json") or []):
            assert expression.startswith(".experiments[]"), (
                f"l'extracteur n'est pas borné à l'index des expériences "
                f"({expression!r})"
            )


def test_mlflow_matcher_needs_the_tracking_vocabulary_not_a_generic_experiment_list():
    assert mlflow_fires(MLFLOW_OPEN), (
        "le template ne reconnaît pas une instance dont le serveur de suivi "
        "répond à une requête sans en-tête d'autorisation"
    )
    assert mlflow_fires(MLFLOW_OPEN_FRESH), (
        "le template exige plus que l'expérience « Default » : il raterait "
        "l'instance qui vient d'être lancée, précisément celle qu'on trouve "
        "oubliée sur un port ouvert"
    )
    assert mlflow_fires(MLFLOW_OPEN_WITHOUT_DEFAULT), (
        "le template dépend du nom « Default » : rien n'empêche de supprimer "
        "cette expérience — à la différence de la base « default » de Milvus — "
        "et search_experiments ne rend par défaut que les actives"
    )
    assert mlflow_fires(MLFLOW_OPEN_COMPACT), (
        "le template dépend de l'indentation posée par message_to_json : le "
        "paramètre pretty est récent, les versions antérieures sérialisaient "
        "sans indenter, et un intermédiaire qui recompacte le corps mettrait le "
        "matcher en défaut"
    )
    assert mlflow_fires(MLFLOW_OPEN_BEHIND_PROXY), (
        "le template exige un type de contenu exact : un proxy qui ajoute le jeu "
        "de caractères en relayant le mettrait en défaut"
    )

    assert not mlflow_fires(MLFLOW_BASIC_AUTH_ENABLED), (
        "le template déclenche sur une instance démarrée avec « --app-name "
        "basic-auth » : le crochet before_request est alors global et cette "
        "route reçoit le 401 de make_basic_auth_response"
    )
    assert not mlflow_fires(MLFLOW_BEHIND_AUTH_PROXY), (
        "le template déclenche sur une instance entièrement gardée"
    )
    assert not mlflow_fires(MLFLOW_CACHED_BODY_UNDER_REFUSAL), (
        "le template conclut du seul corps : un cache placé devant l'instance "
        "peut relayer celui qu'il détient sous le statut du refus, alors que "
        "l'API, elle, a refusé"
    )
    assert not mlflow_fires(MLFLOW_AB_TESTING_PLATFORM), (
        "le template déclenche sur une plateforme d'expérimentation A/B : "
        "« experiments » et « experiment_id » sont mot pour mot son vocabulaire, "
        "et ce sont « artifact_location » et « lifecycle_stage » qui désignent "
        "MLflow"
    )
    assert not mlflow_fires(MLFLOW_TRACKER_WITHOUT_EXPERIMENT_ID), (
        "le template déclenche sur un suivi d'entraînement qui nomme son "
        "identifiant « id » : sans « experiment_id », le vocabulaire n'est plus "
        "celui de MLflow"
    )
    assert not mlflow_fires(MLFLOW_CATALOG_WITHOUT_ARTIFACT_LOCATION), (
        "le template déclenche sur un catalogue interne qui a copié le "
        "vocabulaire de cycle de vie de MLflow sans ranger d'artefact : "
        "« artifact_location » est ce qui rattache la réponse au serveur, et "
        "c'est aussi le renseignement qui fait la sévérité — le dépôt où "
        "atterrissent les poids, servi par la même porte ouverte"
    )
    assert not mlflow_fires(MLFLOW_TRACKER_WITHOUT_LIFECYCLE), (
        "le template déclenche sur un suivi qui parle d'état plutôt que de cycle "
        "de vie : « lifecycle_stage », dont le domaine se réduit à « active » et "
        "« deleted », fait partie de la signature"
    )
    assert not mlflow_fires(MLFLOW_AGGREGATOR), (
        "le template déclenche sur un agrégateur qui republie des "
        "enregistrements MLflow sous sa propre enveloppe : la clé de collection "
        "« experiments » est ce qui rattache la réponse au serveur lui-même"
    )
    assert not mlflow_fires(MLFLOW_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise d'index : un portail captif "
        "qui embarque son état initial porte les quatre clés, et seul le type de "
        "contenu l'en sépare — _search_experiments construit sa réponse avec "
        "Response(mimetype=\"application/json\")"
    )
    assert not mlflow_fires(MLFLOW_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


# --------------------------------------------------------------------------
# Jupyter est le cas où la route qui porte la sévérité est aussi celle qui ne
# prouve rien toute seule. GET /api/kernels est bien la route du sujet — le verbe
# POST y démarre un noyau, donc exécute du code — mais MainKernelHandler.get
# sérialise list_kernels(), qui parcourt les noyaux en cours : sur une instance au
# repos le corps vaut « [] », et un tableau vide ne désigne aucun produit. Or
# l'instance au repos est précisément celle qu'on trouve oubliée sur un port
# ouvert ; exiger un noyau vivant reviendrait à ne signaler que les serveurs en
# cours d'usage.
#
# D'où la seconde lecture, GET /api/kernelspecs, gardée par les mêmes décorateurs
# — @web.authenticated puis @authorized — donc dont le 200 anonyme prouve
# exactement la même chose, et dont le corps, lui, est celui du protocole de
# noyau : « kernelspecs » est la clé de collection de cette API, « argv » et
# « interrupt_mode » viennent de KernelSpec.to_dict, qui les sérialise sans
# condition depuis les versions 5.x de jupyter_client.
#
# Deux pièges de rédaction encadrent ce choix, et les scénarios ci-dessous les
# fixent. Le premier est de conclure de la seule route qui nomme le produit : un
# proxy peut n'ouvrir que le catalogue, auquel cas la route qui démarre un noyau
# n'est pas atteignable. Le second est de se poser sur GET /api, seule route de
# l'API décorée @allow_unauthenticated, qui rend la version sur l'instance fermée
# comme sur l'ouverte — c'est ici l'équivalent du /health de MLflow.

JUPYTER_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "jupyter-no-token.yaml")

JUPYTER_KERNELSPECS = "/api/kernelspecs"
JUPYTER_KERNELS = "/api/kernels"

# Catalogue d'une instance récente : le modèle que MainKernelSpecHandler assemble,
# chaque entrée portant le dict de KernelSpec.to_dict et les ressources ajoutées
# par kernelspec_model.
JUPYTER_KERNELSPECS_BODY = (
    '{"default":"python3","kernelspecs":{"python3":{"name":"python3",'
    '"spec":{"argv":["/opt/conda/bin/python","-m","ipykernel_launcher","-f",'
    '"{connection_file}"],"env":{},"display_name":"Python 3 (ipykernel)",'
    '"language":"python","interrupt_mode":"signal",'
    '"metadata":{"debugger":true},"kernel_protocol_version":""},'
    '"resources":{"logo-32x32":"/kernelspecs/python3/logo-32x32.png",'
    '"logo-64x64":"/kernelspecs/python3/logo-64x64.png",'
    '"logo-svg":"/kernelspecs/python3/logo-svg.svg"}}}}'
)

# Le même catalogue sur une instance plus ancienne — notebook 6 et les
# jupyter_client antérieurs à la version 8 : ni kernel_protocol_version dans le
# dict, ni debugger dans les métadonnées, ni logo vectoriel dans les ressources.
# Le template doit toujours la reconnaître : ce sont elles qui traînent exposées.
JUPYTER_OLD_KERNELSPECS_BODY = (
    '{"default":"python3","kernelspecs":{"python3":{"name":"python3",'
    '"spec":{"argv":["/usr/bin/python3","-m","ipykernel_launcher","-f",'
    '"{connection_file}"],"env":{},"display_name":"Python 3",'
    '"language":"python","interrupt_mode":"signal","metadata":{}},'
    '"resources":{"logo-64x64":"/kernelspecs/python3/logo-64x64.png"}}}}'
)

# Une instance sur laquelle aucun kernelspec n'est installé. La clé de collection
# est bien là, mais vide : aucun noyau ne peut démarrer, donc l'exécution de code
# que le template signale n'existe pas. C'est le corps qui rend « argv » et
# « interrupt_mode » indispensables.
JUPYTER_EMPTY_KERNELSPECS_BODY = '{"default":"python3","kernelspecs":{}}'

# Un noyau en cours, tel que kernel_model le rend.
JUPYTER_KERNELS_BODY = (
    '[{"id":"6f1a9c40-3b7e-4d21-9a0c-1f8e5b2d7c33","name":"python3",'
    '"last_activity":"2026-07-19T14:05:02.886901Z","execution_state":"idle",'
    '"connections":1}]'
)

# La même instance au repos : list_kernels() ne parcourt rien. C'est celle qu'on
# trouve oubliée sur un port ouvert, et elle doit remonter.
JUPYTER_NO_KERNEL_BODY = "[]"

# Ce qu'écrit write_error quand le jeton est en place : APIHandler surcharge
# get_login_url pour lever 403 plutôt que rediriger vers /login, et le corps du
# refus est du JSON lui aussi.
JUPYTER_FORBIDDEN_BODY = '{"message": "Forbidden", "reason": null}'

# Un superviseur de processus quelconque : il énumère des commandes avec leur
# ligne d'appel et le signal qui les interrompt, donc porte « argv » et
# « interrupt_mode » sans être Jupyter. Ces deux clés seules ne prouvent rien.
OTHER_PROCESS_SUPERVISOR_BODY = (
    '{"processes":[{"name":"ingest-worker",'
    '"argv":["/usr/bin/python3","-m","worker","--queue","ingest"],"env":{},'
    '"interrupt_mode":"signal","state":"RUNNING","pid":4412}]}'
)


def jupyter_scenario(kernelspecs, kernels):
    """
    Un scénario associe une réponse (statut, corps) à chacune des deux routes que
    le template interroge. L'ordre, lui, est imposé par le template au moment de
    l'évaluation.
    """
    return {JUPYTER_KERNELSPECS: kernelspecs, JUPYTER_KERNELS: kernels}


# Instance démarrée avec le jeton vidé : auth_enabled est faux, _get_user fabrique
# un utilisateur anonyme, les deux routes répondent.
JUPYTER_OPEN = jupyter_scenario(
    kernelspecs=(200, JUPYTER_KERNELSPECS_BODY),
    kernels=(200, JUPYTER_KERNELS_BODY),
)

# La même au repos : aucun noyau n'a encore été démarré.
JUPYTER_OPEN_IDLE = jupyter_scenario(
    kernelspecs=(200, JUPYTER_KERNELSPECS_BODY),
    kernels=(200, JUPYTER_NO_KERNEL_BODY),
)

# Une instance ancienne, au repos elle aussi.
JUPYTER_OPEN_OLD = jupyter_scenario(
    kernelspecs=(200, JUPYTER_OLD_KERNELSPECS_BODY),
    kernels=(200, JUPYTER_NO_KERNEL_BODY),
)

# Un intermédiaire réindente ce qu'il relaie : le corps n'est plus compact et le
# tableau des noyaux ne commence plus par son crochet.
JUPYTER_OPEN_REFORMATTED = jupyter_scenario(
    kernelspecs=(200, '{\n  "default": "python3",\n  "kernelspecs": {\n'
                      '    "python3": {\n      "name": "python3",\n'
                      '      "spec": {\n        "argv": [\n'
                      '          "/usr/bin/python3",\n          "-m",\n'
                      '          "ipykernel_launcher"\n        ],\n'
                      '        "interrupt_mode": "signal"\n      }\n'
                      '    }\n  }\n}'),
    kernels=(200, "\n[\n]\n"),
)

# Jeton en place — l'instance par défaut, donc : les deux routes reçoivent le 403
# que lève get_login_url.
JUPYTER_TOKEN_ENABLED = jupyter_scenario(
    kernelspecs=(403, JUPYTER_FORBIDDEN_BODY),
    kernels=(403, JUPYTER_FORBIDDEN_BODY),
)

# Un proxy réglé pour tout garder.
JUPYTER_BEHIND_AUTH_PROXY = jupyter_scenario(
    kernelspecs=(401, "<html><body><h1>401 Unauthorized</h1></body></html>"),
    kernels=(401, "<html><body><h1>401 Unauthorized</h1></body></html>"),
)

# Le même proxy réglé pour n'ouvrir que le catalogue — la route qui démarre un
# noyau n'est alors pas atteignable, et il n'y a pas de constat.
JUPYTER_KERNEL_API_GUARDED = jupyter_scenario(
    kernelspecs=(200, JUPYTER_KERNELSPECS_BODY),
    kernels=(403, JUPYTER_FORBIDDEN_BODY),
)

# Un cache placé devant l'instance, réglé pour exiger une identité depuis que le
# jeton a été reposé, mais qui relaie encore le catalogue qu'il détient sous le
# statut du refus. Il n'existe que pour que le statut du catalogue reste vérifié :
# le corps, lui, est authentique.
JUPYTER_CACHED_BODY_UNDER_REFUSAL = jupyter_scenario(
    kernelspecs=(403, JUPYTER_KERNELSPECS_BODY),
    kernels=(200, JUPYTER_NO_KERNEL_BODY),
)

# Le même cache, du côté de l'API des noyaux : il relaie la liste qu'il détient
# sous le statut du refus. La forme du corps est alors celle qu'attend le
# template, et seul le statut sépare cette instance-là de l'instance ouverte.
JUPYTER_CACHED_KERNELS_UNDER_REFUSAL = jupyter_scenario(
    kernelspecs=(200, JUPYTER_KERNELSPECS_BODY),
    kernels=(403, JUPYTER_KERNELS_BODY),
)

# Portail captif devant une vraie instance : il répond 200 et sa page de connexion
# à tout ce qu'on lui demande.
JUPYTER_BEHIND_CAPTIVE_PORTAL = jupyter_scenario(
    kernelspecs=(200, "<html><body>Connexion requise</body></html>"),
    kernels=(200, "<html><body>Connexion requise</body></html>"),
)

# Le même portail, mais qui laisse filer le catalogue et n'intercepte que l'API
# des noyaux : le statut ne l'en sépare plus, seule la forme de la réponse le
# fait.
JUPYTER_KERNEL_API_INTERCEPTED = jupyter_scenario(
    kernelspecs=(200, JUPYTER_KERNELSPECS_BODY),
    kernels=(200, "<html><body>Connexion requise</body></html>"),
)

# Une instance ouverte, mais sans aucun kernelspec installé : rien à démarrer,
# donc rien à signaler.
JUPYTER_WITHOUT_KERNELSPEC = jupyter_scenario(
    kernelspecs=(200, JUPYTER_EMPTY_KERNELSPECS_BODY),
    kernels=(200, JUPYTER_NO_KERNEL_BODY),
)

# Le superviseur de processus, derrière un routeur qui lui renvoie tout.
OTHER_SUPERVISOR = jupyter_scenario(
    kernelspecs=(200, OTHER_PROCESS_SUPERVISOR_BODY),
    kernels=(200, OTHER_PROCESS_SUPERVISOR_BODY),
)

# Un serveur quelconque qui répond 200 à tout ce qu'on lui demande.
JUPYTER_SERVER_ALWAYS_UP = jupyter_scenario(
    kernelspecs=(200, '{"status":"ok"}'), kernels=(200, '{"status":"ok"}'))

# Le pire de ce genre : il répond 200 et un tableau vide partout, donc satisfait
# tout ce que le template attend de l'API des noyaux. Seule la signature du
# catalogue l'en sépare.
JUPYTER_SERVER_ALWAYS_EMPTY_ARRAY = jupyter_scenario(
    kernelspecs=(200, "[]"), kernels=(200, "[]"))


def jupyter_block():
    doc = load(JUPYTER_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.replace("{{BaseURL}}", "") == JUPYTER_KERNELS
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas GET {JUPYTER_KERNELS} — c'est pourtant la "
        "route du constat, celle que le verbe POST double pour démarrer un noyau"
    )
    return blocks[0]


def jupyter_responses(scenario):
    """
    Range les réponses d'un scénario dans l'ordre des chemins déclarés par le
    template : c'est cet ordre qui donne son numéro à chaque body_N.
    """
    ordered = []
    for path in jupyter_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        assert route in scenario, (
            f"le template interroge un chemin que Jupyter ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def jupyter_fires(scenario):
    block = jupyter_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = jupyter_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_jupyter_probe_never_starts_a_kernel_nor_reads_the_working_tree():
    doc = load(JUPYTER_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'API des noyaux se lit en GET : le même chemin en POST démarre un "
            "noyau, donc lance un processus sur l'hôte audité"
        )
        assert block.get("body") is None, (
            "le template envoie un corps : les deux routes se lisent sans "
            "paramètre, et un corps sur ce chemin est ce qui décrit le noyau à "
            "démarrer"
        )
        for path in (block.get("path") or []):
            route = path.replace("{{BaseURL}}", "")

            for forbidden, why in (
                ("/channels",
                 "le template ouvre la websocket d'un noyau : c'est elle qui "
                 "porte les execute_request, donc l'exécution de code qu'il est "
                 "censé signaler"),
                ("/api/sessions",
                 "le template touche les sessions : en démarrer une lance un "
                 "noyau, exactement comme la route des noyaux"),
                ("/api/terminals",
                 "le template touche les terminaux : en ouvrir un donne un shell "
                 "sur l'hôte audité"),
                ("/api/contents",
                 "le template lit l'arborescence servie sous root_dir : elle "
                 "rend les carnets avec leurs sorties, donc le template "
                 "exfiltrerait ce qu'il signale"),
                ("/files/",
                 "le template télécharge un fichier de l'instance qu'il audite"),
                ("/nbconvert",
                 "le template fait convertir un carnet, ce qui l'exécute selon "
                 "l'exportateur demandé"),
                ("/restart",
                 "le template redémarre un noyau, donc emporte le travail en "
                 "cours de l'exploitant"),
                ("/interrupt",
                 "le template interrompt un noyau de l'instance qu'il audite"),
                ("/login",
                 "le template poste sur le formulaire de connexion : il "
                 "tenterait de s'authentifier plutôt que de constater qu'aucune "
                 "authentification n'est demandée"),
            ):
                assert forbidden not in route, why

            # L'API des noyaux se lit sur /api/kernels tout court : le même chemin
            # suffixé d'un identifiant accepte DELETE, qui arrête le noyau.
            assert not route.startswith(JUPYTER_KERNELS + "/"), (
                f"le template vise un noyau nommé ({route}) plutôt que la liste : "
                "c'est le préfixe dont le verbe DELETE arrête le noyau et emporte "
                "l'état de la session en cours"
            )


def test_jupyter_probe_links_the_kernel_api_to_the_kernelspec_catalogue():
    block = jupyter_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]

    assert JUPYTER_KERNELSPECS in paths, (
        "le template n'interroge pas GET /api/kernelspecs — c'est la seule des "
        "deux routes qui nomme le produit, l'API des noyaux rendant « [] » sur "
        "une instance au repos"
    )
    assert JUPYTER_KERNELS in paths, (
        "le template n'interroge pas GET /api/kernels, la route dont le 200 "
        "anonyme établit que l'API qui démarre un noyau est atteignable"
    )
    assert block.get("req-condition") is True, (
        "sans req-condition, les deux réponses ne peuvent pas être liées : le "
        "catalogue conclurait seul, or il dit que c'est Jupyter, pas que l'API "
        "des noyaux répond"
    )

    for route in paths:
        assert route.rstrip("/") != "/api", (
            "le template interroge GET /api : APIVersionHandler y est décoré "
            "@allow_unauthenticated par construction — « not authenticated, so "
            "give as few info as possible » — donc cette route rend la version "
            "sur une instance correctement fermée aussi, et ne prouve rien"
        )

    # Sous req-condition, chaque extracteur qui rend quelque chose ajoute un
    # résultat : deux extracteurs feraient remonter deux fois la même instance.
    assert len(block.get("extractors") or []) <= 1, (
        "le template porte plus d'un extracteur : sous req-condition, chacun "
        "rendant quelque chose ajoute un résultat, donc la même instance est "
        "signalée plusieurs fois dans un rapport de scan"
    )


def test_jupyter_extractor_is_evaluated_against_the_catalogue():
    """
    L'ordre des deux chemins n'est pas indifférent, et le contraire ne se voit
    pas : sous req-condition, « part: body » désigne la dernière réponse reçue.
    Le catalogue interrogé en premier, l'extracteur serait évalué contre le
    tableau des noyaux, ne rendrait jamais rien, et le template signalerait sans
    dire quels interpréteurs un anonyme peut lancer — sans qu'aucun matcher ne
    s'en trouve changé, donc sans que rien ne le trahisse.
    """
    block = jupyter_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]
    extractors = block.get("extractors") or []

    assert extractors, (
        "le template ne remonte rien à l'exploitant : signaler que le port "
        "répond ne lui dit pas quels noyaux un anonyme peut y démarrer"
    )

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "l'extracteur ne lit pas le JSON de la réponse : une expression "
            "libre remonterait aussi bien des fragments de page"
        )
        for expression in (extractor.get("json") or []):
            assert expression.startswith(".kernelspecs[]"), (
                f"l'extracteur n'est pas borné au catalogue des noyaux "
                f"({expression!r})"
            )
        if extractor.get("part", "body") == "body":
            assert paths[-1] == JUPYTER_KERNELSPECS, (
                "l'extracteur lit le catalogue mais celui-ci n'est pas le "
                "dernier chemin interrogé : sous req-condition, « part: body » "
                "désigne la dernière réponse reçue, donc l'expression serait "
                "évaluée contre le tableau des noyaux et ne rendrait rien"
            )


def test_jupyter_matcher_needs_the_kernel_protocol_not_an_empty_array():
    assert jupyter_fires(JUPYTER_OPEN), (
        "le template ne reconnaît pas une instance dont l'API des noyaux répond "
        "à une requête sans jeton"
    )
    assert jupyter_fires(JUPYTER_OPEN_IDLE), (
        "le template exige un noyau en cours : list_kernels() rend « [] » tant "
        "qu'aucun n'a été démarré, donc il raterait l'instance au repos — "
        "précisément celle qu'on trouve oubliée sur un port ouvert"
    )
    assert jupyter_fires(JUPYTER_OPEN_OLD), (
        "le template exige des clés absentes des versions plus anciennes — "
        "kernel_protocol_version n'a été ajouté au dict de KernelSpec.to_dict que "
        "tard, et les métadonnées du débogueur plus tard encore — il raterait les "
        "instances qui traînent exposées"
    )
    assert jupyter_fires(JUPYTER_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps, ou qui préfixe une nouvelle ligne "
        "au tableau des noyaux, le mettrait en défaut"
    )

    assert not jupyter_fires(JUPYTER_TOKEN_ENABLED), (
        "le template déclenche sur une instance dont le jeton est en place : "
        "auth_enabled y est vrai, _get_user ne fabrique aucun utilisateur "
        "anonyme, et get_login_url lève 403 sur les deux routes"
    )
    assert not jupyter_fires(JUPYTER_BEHIND_AUTH_PROXY), (
        "le template déclenche sur une instance entièrement gardée"
    )
    assert not jupyter_fires(JUPYTER_KERNEL_API_GUARDED), (
        "le template conclut du seul catalogue : un proxy peut n'ouvrir "
        "/api/kernelspecs qu'à l'inventaire de son parc et garder le reste, "
        "auquel cas la route qui démarre un noyau n'est pas atteignable — c'est "
        "le statut de cette route-là qui l'établit"
    )
    assert not jupyter_fires(JUPYTER_CACHED_BODY_UNDER_REFUSAL), (
        "le template conclut du seul corps du catalogue : un cache placé devant "
        "l'instance peut relayer celui qu'il détient sous le statut du refus, "
        "alors que l'API, elle, a refusé"
    )
    assert not jupyter_fires(JUPYTER_CACHED_KERNELS_UNDER_REFUSAL), (
        "le template conclut de la seule forme du tableau des noyaux : le même "
        "cache peut relayer la liste qu'il détient sous le statut du refus, "
        "auquel cas l'API des noyaux, elle, a refusé"
    )
    assert not jupyter_fires(JUPYTER_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise de catalogue : un portail "
        "captif qui répond 200 à tout suffirait à le faire remonter"
    )
    assert not jupyter_fires(JUPYTER_KERNEL_API_INTERCEPTED), (
        "le template accepte une page HTML en guise de liste de noyaux : le "
        "handler sérialise une liste, donc le corps commence par son crochet, "
        "vide ou non — sans cette forme, un portail qui laisse filer le "
        "catalogue et intercepte le reste remonterait"
    )
    assert not jupyter_fires(OTHER_SUPERVISOR), (
        "le template déclenche sur un superviseur de processus qui n'est pas "
        "Jupyter : « argv » et « interrupt_mode » sont ce qu'écrit n'importe quel "
        "gestionnaire décrivant les commandes qu'il lance, et c'est "
        "« kernelspecs » qui rattache la réponse au produit"
    )
    assert not jupyter_fires(JUPYTER_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )
    assert not jupyter_fires(JUPYTER_SERVER_ALWAYS_EMPTY_ARRAY), (
        "le template déclenche sur un serveur qui rend un tableau vide partout : "
        "c'est exactement ce que sert l'API des noyaux au repos, et seule la "
        "signature du catalogue l'en sépare"
    )


def test_jupyter_stays_silent_when_no_kernel_can_be_started():
    """
    La frontière que le template revendique, fixée dans le sens qui coûte.

    Une instance ouverte mais sans aucun kernelspec ne remonte pas, et c'est
    délibéré : sans spec, POST /api/kernels n'a rien à démarrer, donc l'exécution
    de code qui fonde la sévérité critical n'existe pas. C'est ce scénario qui
    rend « argv » et « interrupt_mode » nécessaires plutôt qu'ornementaux — la
    clé de collection, elle, est bien présente dans ce corps.

    Ce test existe pour que ce choix reste un choix : quiconque relâcherait la
    signature jusqu'à la seule clé « kernelspecs » ferait remonter une instance
    incapable d'exécuter quoi que ce soit sous une sévérité critical, et c'est
    ici qu'il doit s'en apercevoir.
    """
    assert not jupyter_fires(JUPYTER_WITHOUT_KERNELSPEC), (
        "le template remonte une instance dont le catalogue est vide : aucun "
        "noyau ne peut y démarrer, donc rien n'y justifie une sévérité critical"
    )

    # La contrepartie de ce choix : ce corps doit rester celui d'un catalogue
    # vide, sans quoi le raisonnement ci-dessus ne tient plus.
    assert '"kernelspecs":{}' in JUPYTER_EMPTY_KERNELSPECS_BODY, (
        "le scénario ne modélise plus une instance sans kernelspec"
    )


# --------------------------------------------------------------------------
# Kubeflow Pipelines se joint par deux préfixes — le serveur d'API sert
# « /apis/v1beta1/... », le serveur d'IHM monte le même proxy sous
# « ${basePath}/${apiVersion1Prefix}/* », d'où /pipeline/apis/v1beta1/... derrière
# l'ingress — et sa réponse passe par un marshaler qui n'écrit pas les champs
# restés à leur valeur nulle. Les deux faits commandent le template : il doit
# interroger les deux montages, et sa signature ne peut tenir qu'aux clés d'une
# liste peuplée.

KUBEFLOW_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "kubeflow-pipelines-exposed.yaml")

KUBEFLOW_API_MOUNT = "/apis/v1beta1/pipelines"
KUBEFLOW_UI_MOUNT = "/pipeline/apis/v1beta1/pipelines"

# Index d'une installation autonome telle qu'on la trouve : les deux pipelines
# de tutoriel que sample_config.json fait recharger à chaque démarrage, chacun
# porté par toApiPipelineV1 avec Id, CreatedAt, Name, Description et
# DefaultVersion.
KUBEFLOW_PIPELINES_BODY = (
    '{"pipelines":[{"id":"7f9a1c2e-4b03-4c51-9a77-2d1e5f6b8c40",'
    '"created_at":"2026-07-29T08:14:03Z",'
    '"name":"tutorial-data-passing-in-python-components",'
    '"description":"[source code](https://github.com/kubeflow/pipelines/tree/'
    'master/samples/tutorials) Shows how to pass data between python '
    'components.","default_version":{'
    '"id":"1c0d7b93-5e2a-42f8-8a16-9b4c3d7e1f52",'
    '"name":"tutorial-data-passing-in-python-components",'
    '"created_at":"2026-07-29T08:14:03Z","resource_references":[{'
    '"key":{"type":"PIPELINE","id":"7f9a1c2e-4b03-4c51-9a77-2d1e5f6b8c40"},'
    '"relationship":"OWNER"}]}},'
    '{"id":"b58e3a11-90cd-4f2b-bd07-6e8a4c25d913",'
    '"created_at":"2026-07-29T08:14:04Z",'
    '"name":"tutorial-dsl-control-structures",'
    '"default_version":{"id":"d2f4a706-31bc-49e5-9c88-0a7b6e5d4c31",'
    '"name":"tutorial-dsl-control-structures",'
    '"created_at":"2026-07-29T08:14:04Z"}}],"total_size":2}'
)

# Le même index dépouillé : un pipeline téléversé sans description, dont la
# version par défaut ne porte ni paramètre ni référence de ressource. Ne restent
# que les champs que toApiPipelineV1 affecte sans condition — c'est le corps le
# plus maigre qu'une instance ouverte puisse rendre, et il doit remonter.
KUBEFLOW_MINIMAL_BODY = (
    '{"pipelines":[{"id":"3a6c8d10-77f4-4be2-9d31-5c0e1a8b7f26",'
    '"created_at":"2026-06-02T11:47:20Z","name":"prod-scoring-daily",'
    '"default_version":{"id":"3a6c8d10-77f4-4be2-9d31-5c0e1a8b7f26",'
    '"name":"prod-scoring-daily","created_at":"2026-06-02T11:47:20Z"}}],'
    '"total_size":1}'
)

# Le même index relayé par un intermédiaire qui réindente ce qu'il transporte.
# La graphie serpent est garantie par UseProtoNames, la sérialisation compacte
# ne l'est pas.
KUBEFLOW_REFORMATTED_BODY = json.dumps(json.loads(KUBEFLOW_MINIMAL_BODY),
                                       indent=2)

# Une instance ouverte dont l'index est vide. EmitUnpopulated valant false,
# ListPipelinesResponse ne sérialise aucun de ses trois champs : il ne reste
# rien à reconnaître.
KUBEFLOW_EMPTY_BODY = "{}"

# Ce que rend le serveur en mode multi-utilisateur quand l'identité manque :
# canAccessPipeline enveloppe l'erreur d'IsAuthorized dans le message que
# ListPipelinesV1 porte, et util.NewUnauthenticatedError donne le code gRPC 16,
# rendu 401 par la passerelle.
KUBEFLOW_UNAUTHENTICATED_BODY = (
    '{"error":"Failed to list pipelines due to authorization error. Check if '
    'you have read permission to namespace ","code":16,'
    '"message":"Failed to list pipelines due to authorization error. Check if '
    'you have read permission to namespace ","details":[]}'
)

# Le refus que le maillage oppose avant même d'atteindre le serveur, quand la
# politique d'autorisation d'ml-pipeline tient la porte.
KUBEFLOW_MESH_DENIED_BODY = "RBAC: access denied"

# Un ordonnanceur de tâches quelconque : il énumère des « pipelines » avec leur
# identifiant, leur date de création et le compte total, sous la même enveloppe
# de pagination. Tout le vocabulaire générique y est, et il n'est pas Kubeflow —
# c'est ce corps qui rend « default_version » nécessaire plutôt qu'ornemental.
OTHER_ORCHESTRATOR_PIPELINES_BODY = (
    '{"pipelines":[{"id":"pl-3391","name":"nightly-etl",'
    '"created_at":"2026-07-29T02:00:00Z","status":"succeeded",'
    '"duration_ms":184203},{"id":"pl-3392","name":"hourly-ingest",'
    '"created_at":"2026-07-29T03:00:00Z","status":"running"}],'
    '"total_size":17,"next_page_token":"eyJvIjoyfQ=="}'
)


def kubeflow_response(status, body, content_type="application/json"):
    """
    Une réponse HTTP réduite à ce que les matchers du template observent : le
    statut, le bloc d'en-têtes brut — c'est contre lui que nuclei évalue
    `part: header` — et le corps.
    """
    return {
        "status": status,
        "headers": (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {content_type}\r\n"
            "Server: envoy\r\n"
        ),
        "body": body,
    }


# Une instance ouverte, sur l'un ou l'autre de ses deux montages.
KUBEFLOW_OPEN = kubeflow_response(200, KUBEFLOW_PIPELINES_BODY)
KUBEFLOW_OPEN_MINIMAL = kubeflow_response(200, KUBEFLOW_MINIMAL_BODY)
KUBEFLOW_OPEN_REFORMATTED = kubeflow_response(200, KUBEFLOW_REFORMATTED_BODY)

# Une instance ouverte mais sans aucun pipeline.
KUBEFLOW_OPEN_EMPTY = kubeflow_response(200, KUBEFLOW_EMPTY_BODY)

# Une instance gardée : par le serveur lui-même en mode multi-utilisateur, puis
# par le maillage placé devant.
KUBEFLOW_GUARDED = kubeflow_response(401, KUBEFLOW_UNAUTHENTICATED_BODY)
KUBEFLOW_MESH_GUARDED = kubeflow_response(
    403, KUBEFLOW_MESH_DENIED_BODY, content_type="text/plain")

# Un cache placé devant l'instance relaie l'index qu'il détient sous le statut du
# refus : le serveur, lui, a refusé.
KUBEFLOW_CACHED_UNDER_REFUSAL = kubeflow_response(401, KUBEFLOW_PIPELINES_BODY)

# Un portail captif qui répond 200 et une page à tout ce qu'on lui demande, y
# compris en embarquant ce vocabulaire dans son état initial.
KUBEFLOW_BEHIND_CAPTIVE_PORTAL = kubeflow_response(
    200,
    '<!doctype html><html><body><script>window.__STATE__={"pipelines":[],'
    '"total_size":0,"created_at":null,"default_version":null}</script>'
    "</body></html>",
    content_type="text/html; charset=utf-8",
)

# Un serveur quelconque qui répond 200 à tout.
KUBEFLOW_SERVER_ALWAYS_UP = kubeflow_response(200, "OK",
                                              content_type="text/plain")

# Le même vocabulaire, autre produit.
KUBEFLOW_OTHER_ORCHESTRATOR = kubeflow_response(
    200, OTHER_ORCHESTRATOR_PIPELINES_BODY)


def kubeflow_block():
    doc = load(KUBEFLOW_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.replace("{{BaseURL}}", "") == KUBEFLOW_API_MOUNT
                     for p in (b.get("path") or []))]
    assert blocks, f"le template ne vise pas GET {KUBEFLOW_API_MOUNT}"
    return blocks[0]


def kubeflow_fires(response):
    """
    Sémantique nuclei du bloc entier contre une réponse unique : statut, en-têtes
    et corps. Les deux chemins déclarés sont deux montages du même service, non
    deux moitiés de preuve — il n'y a pas de req-condition, donc chaque matcher
    voit la même réponse.
    """
    block = kubeflow_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"

    verdicts = []
    for matcher in matchers:
        kind = matcher.get("type")
        if kind == "status":
            verdicts.append(response["status"] in (matcher.get("status") or []))
        elif matcher.get("part") == "header":
            verdicts.append(word_matcher_hits(matcher, response["headers"]))
        else:
            verdicts.append(body_matcher_hits(matcher, response["body"]))

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_kubeflow_probe_covers_both_mount_points_without_double_reporting():
    block = kubeflow_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]

    assert KUBEFLOW_UI_MOUNT in paths, (
        "le template n'interroge que le serveur d'API : le serveur d'IHM monte "
        "le même proxy sous « ${basePath}/${apiVersion1Prefix}/* », donc une "
        "instance jointe par l'ingress Kubeflow répond sur "
        f"{KUBEFLOW_UI_MOUNT} et serait manquée"
    )
    assert block.get("req-condition") is not True, (
        "le template lie les deux réponses : ce sont deux montages du même "
        "service, une instance donnée répond sur l'un ou sur l'autre, et les "
        "exiger ensemble ne remonterait plus rien"
    )
    assert block.get("stop-at-first-match") is True, (
        "sans stop-at-first-match, une IHM qui sert les deux préfixes — elle "
        "monte le proxy avec et sans basePath — fait remonter deux fois la même "
        "instance"
    )


def test_kubeflow_probe_reads_the_index_and_touches_nothing_else():
    doc = load(KUBEFLOW_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method") == "GET", (
            "l'index se lit en GET — pipeline.proto annote ListPipelinesV1 de "
            "« get: \"/apis/v1beta1/pipelines\" » — et le même chemin en POST "
            "crée un pipeline sur l'instance auditée"
        )
        assert block.get("body") is None, (
            "le template envoie un corps : la route se lit sans paramètre, les "
            "défauts du serveur suffisent"
        )

        for path in (block.get("path") or []):
            assert "?" not in path, (
                "le template passe des paramètres de requête : rien n'a à être "
                "précisé pour lire l'index"
            )
            for forbidden, why in (
                ("/templates",
                 "le template lit le manifeste du pipeline : il porte les "
                 "images employées, les arguments de chaque composant et les "
                 "noms des secrets montés"),
                ("/runs",
                 "le template touche les exécutions : ce chemin rend en GET les "
                 "paramètres soumis et lance en POST des conteneurs sur le "
                 "cluster audité"),
                ("/pipeline_versions",
                 "le template touche les versions : une version inscrite là "
                 "survivrait à la fermeture du port"),
                ("default_version",
                 "le template touche la version par défaut : la changer "
                 "désigne ce que la prochaine exécution lancera"),
                ("/upload",
                 "le template téléverse sur l'instance qu'il audite"),
                ("/experiments",
                 "le template lit les expériences, hors du constat qu'il "
                 "revendique"),
            ):
                assert forbidden not in path, why

            assert "/healthz" not in path, (
                "le template interroge /apis/v1beta1/healthz : GetHealthzResponse "
                "ne porte qu'un booléen multi_user, et EmitUnpopulated valant "
                "false il n'est pas écrit lorsqu'il est faux — la route rend "
                "donc « {} » sur l'instance ouverte, ce qui ne prouve rien"
            )


def test_kubeflow_matcher_needs_the_pipeline_index_not_a_generic_task_list():
    assert kubeflow_fires(KUBEFLOW_OPEN), (
        "le template ne reconnaît pas l'index d'une installation autonome, "
        "celle-là même que IsAuthorized laisse passer sans rien vérifier"
    )
    assert kubeflow_fires(KUBEFLOW_OPEN_MINIMAL), (
        "le template exige des champs que toApiPipelineV1 laisse subordonnés à "
        "un test — description, paramètres, références de ressource — il "
        "raterait un pipeline téléversé sans description"
    )
    assert kubeflow_fires(KUBEFLOW_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui réindente ce qu'il relaie le mettrait en défaut, "
        "alors que UseProtoNames ne garantit que la graphie des clés"
    )

    assert not kubeflow_fires(KUBEFLOW_OTHER_ORCHESTRATOR), (
        "le template déclenche sur un ordonnanceur qui n'est pas Kubeflow : "
        "« pipelines », « created_at » et « total_size » sont le vocabulaire de "
        "n'importe quelle liste de tâches paginée, et c'est "
        "« default_version » qui rattache la réponse au produit"
    )
    assert not kubeflow_fires(KUBEFLOW_GUARDED), (
        "le template déclenche sur une instance en mode multi-utilisateur : "
        "l'identité manquante y fait rendre util.NewUnauthenticatedError, soit "
        "401"
    )
    assert not kubeflow_fires(KUBEFLOW_MESH_GUARDED), (
        "le template déclenche sur une instance dont la politique "
        "d'autorisation du maillage tient la porte"
    )
    assert not kubeflow_fires(KUBEFLOW_CACHED_UNDER_REFUSAL), (
        "le template conclut du seul corps : un cache placé devant l'instance "
        "peut relayer l'index qu'il détient sous le statut du refus, alors que "
        "le serveur, lui, a refusé"
    )
    assert not kubeflow_fires(KUBEFLOW_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise d'index : un portail captif "
        "qui répond 200 à tout suffirait à le faire remonter"
    )
    assert not kubeflow_fires(KUBEFLOW_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


def test_kubeflow_stays_silent_on_an_empty_index():
    """
    La frontière que le template revendique, fixée dans le sens qui coûte.

    CustomMarshaler pose EmitUnpopulated: false, donc ListPipelinesResponse ne
    sérialise aucun de ses trois champs quand la liste est vide : une instance
    ouverte sans pipeline rend « {} », et il n'y a rien à reconnaître là-dedans
    qui ne déclencherait pas sur n'importe quel serveur. Elle ne remonte donc
    pas — et c'est cohérent avec ce que le template affirme, l'index étant le
    constat lui-même.

    Ce test existe pour que ce choix reste un choix : quiconque relâcherait la
    signature pour rattraper ce cas ferait remonter tout objet JSON vide, et
    c'est ici qu'il doit s'en apercevoir.
    """
    assert not kubeflow_fires(KUBEFLOW_OPEN_EMPTY), (
        "le template remonte une réponse vide : « {} » ne désigne aucun "
        "produit, et l'accepter ferait déclencher sur tout service rendant un "
        "objet JSON vide"
    )

    # La contrepartie de ce choix : ce corps doit rester celui que le marshaler
    # produit sur une liste vide, sans quoi le raisonnement ci-dessus ne tient
    # plus.
    assert json.loads(KUBEFLOW_EMPTY_BODY) == {}, (
        "le scénario ne modélise plus une instance sans pipeline"
    )


def test_kubeflow_extractors_stay_on_the_pipeline_index():
    block = kubeflow_block()
    extractors = block.get("extractors") or []
    assert extractors, (
        "le template ne remonte rien à l'exploitant : signaler que le port "
        "répond ne lui dit pas quels pipelines un anonyme peut y lire"
    )

    # Plusieurs extracteurs ne sont admissibles que parce qu'il n'y a pas de
    # req-condition : sous req-condition, chacun rendant quelque chose
    # ajouterait un résultat pour la même instance.
    assert block.get("req-condition") is not True, (
        "le template porte plusieurs extracteurs sous req-condition : chacun "
        "rendant quelque chose ajoute un résultat, donc la même instance est "
        "signalée plusieurs fois"
    )

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "l'extracteur ne lit pas le JSON de la réponse : une expression "
            "libre remonterait aussi bien des fragments de page"
        )
        for expression in (extractor.get("json") or []):
            assert expression.startswith((".pipelines[]", ".total_size")), (
                f"l'extracteur sort de l'index des pipelines ({expression!r})"
            )
            assert "default_version" not in expression, (
                "l'extracteur remonte l'URL du paquet de la version par "
                "défaut : c'est un chemin à joindre, pas un renseignement à "
                "recopier dans un rapport de scan"
            )


# --------------------------------------------------------------------------
# ClearML sépare nettement les deux questions, et le template doit les poser
# séparément. /debug.ping dit quel produit répond — son schéma pose
# « authorize: false », donc il répond aussi bien sur l'instance fermée et ne
# prouve rien de l'authentification. /login.supported_modes dit l'état de
# celle-ci, mais par la valeur qu'il porte et non par le fait de répondre : son
# schéma pose « authorize: null », le cas que validate_auth décrit par « the
# validation will be tried, but it does not have to succeed », donc la route
# répond des deux côtés de la frontière.

CLEARML_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "clearml-server-exposed.yaml")

CLEARML_PING = "/debug.ping"
CLEARML_LOGIN_MODES = "/login.supported_modes"


def clearml_envelope(endpoint_name, data, requested="2.35", actual="1.0"):
    """
    L'enveloppe que get_response construit pour tout appel : meta.endpoint porte
    le nom appelé encadré de requested_version et actual_version, puis les codes
    de résultat, puis les données du point d'entrée sous « data ».
    """
    return (
        '{"meta":{"id":"9c3f8b7a5e1d4a02b6c7d8e9f0a1b2c3",'
        '"trx":"9c3f8b7a5e1d4a02b6c7d8e9f0a1b2c3","endpoint":{'
        f'"name":"{endpoint_name}","requested_version":"{requested}",'
        f'"actual_version":"{actual}"}},'
        '"result_code":200,"result_subcode":0,"result_msg":"OK",'
        '"error_stack":null,"error_data":{}},'
        f'"data":{data}}}'
    )


# Réponse de /debug.ping appelé sans corps ni paramètre : ping pose
# {"msg": "ClearML server"} et n'a rien reçu à y verser.
CLEARML_PING_BODY = clearml_envelope("debug.ping", '{"msg":"ClearML server"}')

# Le même appel sur un serveur plus ancien : seule la version d'API maximale
# change, et c'est précisément ce que le template en extrait plutôt que d'en
# exiger la valeur.
CLEARML_PING_OLD_BODY = clearml_envelope(
    "debug.ping", '{"msg":"ClearML server"}', requested="2.20")

# Le même corps relayé par un intermédiaire qui réindente ce qu'il transporte.
CLEARML_PING_REFORMATTED_BODY = json.dumps(json.loads(CLEARML_PING_BODY),
                                           indent=2)

# /login.supported_modes sur l'instance livrée telle quelle : la section
# auth.fixed_users est commentée dans apiserver.conf, FixedUser.enabled() rend
# donc son défaut False, et l'écran de connexion ne demande qu'un nom.
CLEARML_LOGIN_OPEN_BODY = clearml_envelope(
    "login.supported_modes",
    '{"authenticated":false,"basic":{"enabled":false,"guest":{"enabled":false}},'
    '"server_errors":{"es_connection_error":false,"missed_es_upgrade":false},'
    '"sso":{},"sso_providers":[]}',
    actual="2.9",
)

# Le même corps réindenté : la graphie des clés est stable, sa sérialisation
# compacte ne l'est pas.
CLEARML_LOGIN_OPEN_REFORMATTED_BODY = json.dumps(
    json.loads(CLEARML_LOGIN_OPEN_BODY), indent=2)

# La même route sur une instance fermée : le bloc auth.fixed_users a été ajouté,
# donc basic.enabled vaut true. Le « enabled » de guest, lui, reste faux —
# c'est ce corps qui exige que le motif soit borné à l'objet basic.
CLEARML_LOGIN_FIXED_USERS_BODY = clearml_envelope(
    "login.supported_modes",
    '{"authenticated":false,"basic":{"enabled":true,"guest":{"enabled":false}},'
    '"server_errors":{"es_connection_error":false,"missed_es_upgrade":false},'
    '"sso":{},"sso_providers":[]}',
    actual="2.9",
)

# Utilisateurs fixes posés et mode invité activé par-dessus :
# FixedUser.get_guest_user() recopie le nom, l'identifiant et le mot de passe de
# l'invité dans une réponse que n'importe qui obtient. C'est une exposition, mais
# ce n'est pas celle que ce template revendique.
CLEARML_LOGIN_GUEST_BODY = clearml_envelope(
    "login.supported_modes",
    '{"authenticated":false,"basic":{"enabled":true,"guest":{"enabled":true,'
    '"name":"Guest","password":"guest-secret","username":"guest"}},'
    '"server_errors":{"es_connection_error":false,"missed_es_upgrade":false},'
    '"sso":{},"sso_providers":[]}',
    actual="2.9",
)

# Une passerelle quelconque qui publie elle aussi ses modes de connexion : elle
# emploie le même vocabulaire — basic, enabled, authenticated, sso_providers —
# sans être ClearML. C'est ce corps qui rend l'enveloppe de /debug.ping
# nécessaire plutôt qu'ornementale.
#
# Elle recopie en outre dans sa réponse le nom de la route qu'elle a résolue,
# comme le font les passerelles qui tracent : « debug.ping » se retrouve donc
# dans le corps sans que rien de l'enveloppe n'y soit. C'est ce détail qui rend
# requested_version et actual_version nécessaires plutôt qu'ornementaux — le nom
# seul est un mot que n'importe quel intermédiaire peut renvoyer.
def other_login_modes_body(route):
    return (
        '{"basic":{"enabled":false},"sso_providers":[],"authenticated":false,'
        f'"realm":"corp-sso","version":"4.2.0","endpoint":"{route.lstrip("/")}"}}'
    )


def clearml_scenario(ping, login_modes):
    return {CLEARML_PING: ping, CLEARML_LOGIN_MODES: login_modes}


# Une instance livrée telle quelle : les deux routes répondent, et la seconde
# annonce qu'aucun utilisateur fixe n'est posé.
CLEARML_OPEN = clearml_scenario(
    ping=(200, CLEARML_PING_BODY), login_modes=(200, CLEARML_LOGIN_OPEN_BODY))

# La même, sur un serveur plus ancien.
CLEARML_OPEN_OLD = clearml_scenario(
    ping=(200, CLEARML_PING_OLD_BODY),
    login_modes=(200, CLEARML_LOGIN_OPEN_BODY))

# La même, derrière un intermédiaire qui réindente ce qu'il relaie.
CLEARML_OPEN_REFORMATTED = clearml_scenario(
    ping=(200, CLEARML_PING_REFORMATTED_BODY),
    login_modes=(200, CLEARML_LOGIN_OPEN_REFORMATTED_BODY))

# Une instance fermée : le bloc auth.fixed_users a été ajouté.
CLEARML_FIXED_USERS = clearml_scenario(
    ping=(200, CLEARML_PING_BODY),
    login_modes=(200, CLEARML_LOGIN_FIXED_USERS_BODY))

# Fermée, avec le mode invité activé par-dessus.
CLEARML_GUEST_MODE = clearml_scenario(
    ping=(200, CLEARML_PING_BODY),
    login_modes=(200, CLEARML_LOGIN_GUEST_BODY))

# Un mandataire n'ouvre /debug.ping qu'à sa supervision et garde le reste : le
# produit est nommé, mais l'état de l'authentification n'a pas été établi.
CLEARML_LOGIN_MODES_GUARDED = clearml_scenario(
    ping=(200, CLEARML_PING_BODY),
    login_modes=(403, '{"meta":{"result_code":403},"data":{}}'))

# Un cache placé devant relaie le corps qu'il détient sous le statut du refus,
# d'un côté puis de l'autre.
CLEARML_CACHED_UNDER_REFUSAL = clearml_scenario(
    ping=(200, CLEARML_PING_BODY),
    login_modes=(401, CLEARML_LOGIN_OPEN_BODY))
CLEARML_PING_CACHED_UNDER_REFUSAL = clearml_scenario(
    ping=(403, CLEARML_PING_BODY),
    login_modes=(200, CLEARML_LOGIN_OPEN_BODY))

# Un cache indexé sur l'hôte et non sur le chemin sert la même réponse aux deux
# routes. Dans un sens rien ne dit l'état de l'authentification ; dans l'autre
# rien n'a établi que /debug.ping ait répondu — et c'est le nom que porte chaque
# enveloppe qui rattache une réponse à l'appel qui l'a produite.
CLEARML_PING_ON_BOTH_PATHS = clearml_scenario(
    ping=(200, CLEARML_PING_BODY), login_modes=(200, CLEARML_PING_BODY))
CLEARML_LOGIN_MODES_ON_BOTH_PATHS = clearml_scenario(
    ping=(200, CLEARML_LOGIN_OPEN_BODY),
    login_modes=(200, CLEARML_LOGIN_OPEN_BODY))

# Un portail SSO qui possède le préfixe /login devant l'application, montage
# courant : /debug.ping traverse jusqu'au serveur ClearML, mais c'est le portail
# qui répond à /login.supported_modes, avec son propre descripteur — où
# « basic » est bien à false, puisqu'il n'authentifie pas en basique. Le premier
# corps est authentique, le second ne vient pas du serveur, et seul le nom que
# porte l'enveloppe les distingue.
CLEARML_BEHIND_SSO_PORTAL = clearml_scenario(
    ping=(200, CLEARML_PING_BODY),
    login_modes=(200, '{"basic":{"enabled":false},"oidc":{"enabled":true},'
                      '"portal":"sso.internal","redirect":"/oauth2/start"}'))

# La passerelle qui publie ses modes de connexion, derrière un routeur qui lui
# renvoie tout — et qui rapporte à chaque fois la route qu'elle a résolue.
OTHER_LOGIN_GATEWAY = clearml_scenario(
    ping=(200, other_login_modes_body(CLEARML_PING)),
    login_modes=(200, other_login_modes_body(CLEARML_LOGIN_MODES)))

# Un portail captif qui répond 200 et sa page à tout ce qu'on lui demande.
CLEARML_BEHIND_CAPTIVE_PORTAL = clearml_scenario(
    ping=(200, "<html><body>Connexion requise</body></html>"),
    login_modes=(200, "<html><body>Connexion requise</body></html>"))

# Un serveur quelconque qui répond 200 à tout.
CLEARML_SERVER_ALWAYS_UP = clearml_scenario(
    ping=(200, '{"status":"ok"}'), login_modes=(200, '{"status":"ok"}'))


def clearml_block():
    doc = load(CLEARML_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.replace("{{BaseURL}}", "") == CLEARML_LOGIN_MODES
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {CLEARML_LOGIN_MODES} — c'est pourtant la "
        "seule route qui dit l'état de l'authentification web, /debug.ping "
        "répondant sur l'instance fermée comme sur l'ouverte"
    )
    return blocks[0]


def clearml_responses(scenario):
    """
    Range les réponses d'un scénario dans l'ordre des chemins déclarés par le
    template : c'est cet ordre qui donne son numéro à chaque body_N.
    """
    ordered = []
    for path in clearml_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        assert route in scenario, (
            f"le template interroge un chemin que ClearML ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def clearml_fires(scenario):
    block = clearml_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = clearml_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_clearml_probe_sends_nothing_that_the_ping_would_echo_back():
    """
    La singularité de /debug.ping : ping fait « res.update(call.data) », et
    _update_call_data verse dans call.data le corps JSON comme la chaîne de
    requête. Tout ce que le template enverrait lui reviendrait donc à l'intérieur
    de la réponse qu'il examine — un template qui poserait sa propre signature en
    paramètre la retrouverait sur n'importe quel serveur ClearML, et un attaquant
    la retrouverait sur n'importe quoi.
    """
    doc = load(CLEARML_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("body") is None, (
            "le template envoie un corps : debug.ping le reverse tel quel dans "
            "sa réponse, donc le template se fournirait à lui-même la signature "
            "qu'il cherche"
        )
        for path in (block.get("path") or []):
            assert "?" not in path, (
                "le template passe des paramètres de requête : "
                "_apply_multi_dict les verse dans call.data, que debug.ping "
                "reverse dans sa réponse — même effet qu'un corps"
            )


def test_clearml_probe_reads_the_two_open_routes_and_touches_nothing_else():
    doc = load(CLEARML_TEMPLATE)

    assert clearml_block().get("req-condition") is True, (
        "le template ne lie pas les deux réponses : sans req-condition, ni "
        "body_N ni status_code_N n'existent, chaque réponse est jugée seule, et "
        "/debug.ping conclurait de son côté — or son schéma pose "
        "« authorize: false », donc il répond aussi sur l'instance fermée"
    )

    for block in (doc.get("http") or []):
        assert block.get("method") == "POST", (
            "les points d'entrée de cette API se demandent en POST : la "
            "documentation annonce « POST /debug.ping », et le template ne doit "
            "pas dépendre d'un verbe que le service n'annonce pas"
        )

        for path in (block.get("path") or []):
            route = path.replace("{{BaseURL}}", "")

            for forbidden, why in (
                ("auth.login",
                 "le template ouvre une session sur l'instance qu'il audite"),
                ("auth.create_credentials",
                 "le template inscrit un couple clé/secret : il survivrait à la "
                 "fermeture du port qu'il signale"),
                ("users.create",
                 "le template crée un compte sur l'instance qu'il audite"),
                ("tasks.clone",
                 "le template recopie une tâche : c'est la première moitié du "
                 "détournement qu'il est censé signaler"),
                ("tasks.edit",
                 "le template récrit le dépôt, le commit ou l'image d'une "
                 "tâche, donc ce qu'un agent exécutera"),
                ("tasks.enqueue",
                 "le template pose une tâche dans une file : un clearml-agent "
                 "viendrait l'exécuter sur les machines de l'exploitant"),
                ("tasks.get_all",
                 "le template lit les expériences : hyperparamètres et blobs de "
                 "configuration, où Task.connect inscrit sans trier ce que le "
                 "code d'entraînement lui a passé"),
                ("events.",
                 "le template lit les sorties console, qui n'ont jamais été "
                 "filtrées pour être lues par un tiers"),
                ("models.get_all",
                 "le template lit l'uri des poids, servie par un fileserver qui "
                 "n'a pas d'authentification propre"),
                ("server.config",
                 "le template fait rendre la configuration du serveur, hors du "
                 "constat qu'il revendique"),
            ):
                assert forbidden not in route, why


def test_clearml_matcher_needs_both_the_api_envelope_and_the_open_login_mode():
    assert clearml_fires(CLEARML_OPEN), (
        "le template ne reconnaît pas une instance livrée telle quelle, celle "
        "dont la section auth.fixed_users n'a jamais été ajoutée"
    )
    assert clearml_fires(CLEARML_OPEN_OLD), (
        "le template dépend de la version d'API maximale que le serveur rend "
        "dans requested_version : elle monte à chaque publication, donc "
        "l'exiger raterait les instances anciennes, précisément celles qui "
        "traînent exposées"
    )
    assert clearml_fires(CLEARML_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte de rapidjson : un "
        "intermédiaire qui réindente ce qu'il relaie le mettrait en défaut"
    )

    assert not clearml_fires(OTHER_LOGIN_GATEWAY), (
        "le template déclenche sur une passerelle qui n'est pas ClearML : "
        "« basic », « enabled » et « sso_providers » sont le vocabulaire de "
        "n'importe quel service publiant ses modes de connexion, et c'est "
        "l'enveloppe de /debug.ping qui rattache la réponse au produit — or "
        "cette passerelle rapporte la route résolue, donc « debug.ping » figure "
        "dans son corps sans que requested_version ni actual_version y soient"
    )
    assert not clearml_fires(CLEARML_PING_ON_BOTH_PATHS), (
        "le template conclut de la seule enveloppe : un service qui renvoie la "
        "réponse de /debug.ping sur les deux chemins la satisfait, alors que "
        "rien n'y dit l'état de l'authentification"
    )
    assert not clearml_fires(CLEARML_LOGIN_MODES_ON_BOTH_PATHS), (
        "le template ne vérifie pas que chaque réponse nomme l'appel qui l'a "
        "produite : un cache indexé sur l'hôte et non sur le chemin sert la "
        "même réponse aux deux, et le constat porterait alors sur une seule "
        "route interrogée deux fois"
    )
    assert not clearml_fires(CLEARML_BEHIND_SSO_PORTAL), (
        "le template accepte pour réponse du serveur celle d'un portail qui "
        "possède le préfixe /login devant lui : son descripteur porte lui aussi "
        "un « basic » à false, et c'est le nom que porte l'enveloppe qui établit "
        "que la seconde réponse vient bien du serveur ClearML"
    )
    assert not clearml_fires(CLEARML_LOGIN_MODES_GUARDED), (
        "le template conclut de /debug.ping seul : son schéma pose "
        "« authorize: false », donc la route répond sur l'instance fermée, et "
        "un mandataire peut ne l'ouvrir qu'à sa supervision en gardant le reste"
    )
    assert not clearml_fires(CLEARML_CACHED_UNDER_REFUSAL), (
        "le template conclut du seul corps : un cache placé devant l'instance "
        "peut relayer celui qu'il détient sous le statut du refus, alors que le "
        "serveur, lui, a refusé"
    )
    assert not clearml_fires(CLEARML_PING_CACHED_UNDER_REFUSAL), (
        "le template ne contrôle le statut que de la seconde réponse : le même "
        "cache peut relayer l'enveloppe de /debug.ping sous un statut de refus, "
        "auquel cas le produit n'a pas été identifié par le service lui-même"
    )
    assert not clearml_fires(CLEARML_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML en guise de réponse d'API : un "
        "portail captif qui répond 200 à tout suffirait à le faire remonter"
    )
    assert not clearml_fires(CLEARML_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


def test_clearml_stays_silent_when_fixed_users_are_enabled():
    """
    La frontière que le template revendique, fixée dans le sens qui coûte.

    login.supported_modes répond des deux côtés — son schéma pose
    « authorize: null », le cas que validate_auth décrit par « the validation
    will be tried, but it does not have to succeed » — donc c'est la valeur de
    basic.enabled, et elle seule, qui sépare l'instance ouverte de l'instance
    fermée. Le piège est que guest porte son propre « enabled », faux sur toute
    instance sans invité : un motif cherché au large du corps ferait remonter
    l'instance fermée.

    Le second corps dit la contrepartie de ce silence : quand le mode invité est
    activé par-dessus les utilisateurs fixes, la même route rend au même anonyme
    le mot de passe de l'invité en clair. C'est une exposition, ce n'est pas
    celle-ci, et le template ne les confond pas.
    """
    assert not clearml_fires(CLEARML_FIXED_USERS), (
        "le template remonte une instance dont le bloc auth.fixed_users est "
        "posé : basic.enabled y vaut true, et c'est le « enabled » imbriqué de "
        "guest qui le fait déclencher — le motif n'est pas borné à basic"
    )
    assert not clearml_fires(CLEARML_GUEST_MODE), (
        "le template remonte une instance dont les utilisateurs fixes sont "
        "posés : le mode invité est une autre exposition, qui appelle un autre "
        "constat"
    )

    # La contrepartie de ce choix : ces deux corps doivent rester ceux d'une
    # instance fermée, sans quoi le raisonnement ci-dessus ne tient plus.
    for body, why in (
        (CLEARML_LOGIN_FIXED_USERS_BODY,
         "le scénario ne modélise plus une instance à utilisateurs fixes"),
        (CLEARML_LOGIN_GUEST_BODY,
         "le scénario ne modélise plus une instance à mode invité"),
    ):
        assert json.loads(body)["data"]["basic"]["enabled"] is True, why
    assert (json.loads(CLEARML_LOGIN_FIXED_USERS_BODY)
            ["data"]["basic"]["guest"]["enabled"] is False), (
        "le scénario ne porte plus le « enabled » imbriqué qu'il sert à écarter"
    )


def test_clearml_extractor_reports_the_api_version_of_the_ping_response():
    block = clearml_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]
    extractors = block.get("extractors") or []

    assert extractors, (
        "le template ne remonte rien à l'exploitant : signaler que le port "
        "répond ne lui dit pas de quelle version de serveur il s'agit"
    )
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le moteur "
        "émet un résultat par extracteur qui rend quelque chose, donc la même "
        "instance est signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "l'extracteur ne lit pas le JSON de la réponse : une expression libre "
        "remonterait aussi bien des fragments de page"
    )
    assert extractor.get("part") == f"body_{paths.index(CLEARML_PING) + 1}", (
        "l'extracteur n'est pas borné à la réponse de /debug.ping : sous "
        "req-condition il serait évalué contre les deux, et la signature de "
        "version se lit dans l'enveloppe de celle-là"
    )
    for expression in (extractor.get("json") or []):
        assert expression.startswith(".meta.endpoint."), (
            f"l'extracteur sort de l'enveloppe de version ({expression!r})"
        )

    # Et il doit rendre quelque chose sur la réponse qu'il vise.
    extracted = [json.loads(CLEARML_PING_BODY)["meta"]["endpoint"][
        expression.rsplit(".", 1)[-1]]
        for expression in (extractor.get("json") or [])]
    assert all(extracted), (
        "l'expression ne désigne aucun champ de l'enveloppe : l'extracteur ne "
        "rendrait rien"
    )


# --------------------------------------------------------------------------
# BentoML sépare lui aussi les deux questions, mais autrement que ClearML : ici
# aucune route ne dit l'état de l'authentification, puisqu'il n'y en a pas —
# get_system_routes greffe /livez, /healthz et /readyz sans intercalaire, et
# aucune branche du code ne consulte l'identité de l'appelant. Ce qui reste à
# établir est donc, d'un côté, que le service tourne et sert effectivement
# l'inférence — c'est readyz, que le serveur lui-même distingue de livez — et de
# l'autre quel produit répond. Les sondes ne peuvent rien pour la seconde
# question : elles rendent « PlainTextResponse("\n") », et un saut de ligne
# n'appartient à personne. C'est /docs.json qui la tranche, et par deux chaînes
# écrites en dur plutôt que par une forme, « openapi », « paths » et « /livez »
# étant le vocabulaire de n'importe quelle application FastAPI munie de sondes
# Kubernetes.

BENTOML_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "bentoml-yatai-exposed.yaml")

BENTOML_LIVEZ = "/livez"
BENTOML_READYZ = "/readyz"
BENTOML_DOCS = "/docs.json"

# Ce que rendent livez et readyz : PlainTextResponse("\n", status_code=200).
BENTOML_PROBE_BODY = "\n"

# Les deux libellés que generate_spec pose dans le document. Ils sont écrits en
# dur dans _internal/service/openapi — APP_TAG et INFRA_TAG — et la fabrique de
# service actuelle réemploie les mêmes constantes que la génération à runners de
# la 1.1 : c'est ce qui rend la signature stable d'une version à l'autre.
BENTOML_APP_TAG = {"name": "Service APIs",
                   "description": "BentoML Service API endpoints for inference."}
BENTOML_INFRA_TAG = {
    "name": "Infrastructure",
    "description": "Common infrastructure endpoints for observability.",
}

# Les quatre entrées que make_infra_endpoints écrit sans condition, avec les
# descriptions d'INFRA_DECRIPTION.
BENTOML_INFRA_PATHS = {
    "/healthz": "Health check endpoint. Expecting an empty response with status "
                "code <code>200</code> when the service is in health state. The "
                "<code>/healthz</code> endpoint is <b>deprecated</b>. (since "
                "Kubernetes v1.16)",
    "/livez": "Health check endpoint for Kubernetes. Healthy endpoint responses "
              "with a <code>200</code> OK status.",
    "/readyz": "A <code>200</code> OK status from <code>/readyz</code> endpoint "
               "indicated the service is ready to accept traffic. From that "
               "point and onward, Kubernetes will use <code>/livez</code> "
               "endpoint to perform periodic health checks.",
    "/metrics": "Prometheus metrics endpoint. The <code>/metrics</code> "
                "responses with a <code>200</code>. The output can then be used "
                "by a Prometheus sidecar to scrape the metrics of the service.",
}


def bentoml_docs_body(title="summarization", version="hkwqxdst5ct4jnry",
                      api_path="/summarize", api_name="summarize",
                      description="Un service de résumé.", components=True):
    """
    Le document que /docs.json rend : la structure d'OpenAPISpecification, telle
    que JSONResponse la sérialise — d'où les séparateurs compacts, qui sont ceux
    du rendu de Starlette et non un choix de ce fichier.

    Les deux paramètres qui portent une variation réelle : `description` vaut
    None quand le service n'a pas de docstring, et `components` est absent quand
    aucune méthode ne déclare de modèle d'entrée — dans les deux cas
    __omit_if_default__ retire la clé du document plutôt que d'y écrire un null.
    Le template ne doit dépendre ni de l'une ni de l'autre.
    """
    info = {"title": title, "version": version}
    if description is not None:
        info["description"] = description
    info["contact"] = {"name": "BentoML Team", "email": "contact@bentoml.com"}

    paths = {
        endpoint: {"get": {
            "responses": {"200": {"description": "Successful Response"}},
            "tags": [BENTOML_INFRA_TAG["name"]],
            "description": text,
        }}
        for endpoint, text in BENTOML_INFRA_PATHS.items()
    }
    paths[api_path] = {"post": {
        "tags": [BENTOML_APP_TAG["name"]],
        "operationId": f"{title}__{api_name}",
        "responses": {"200": {"description": "Successful Response",
                              "content": {"application/json": {
                                  "schema": {"type": "string"}}}}},
    }}

    spec = {
        "openapi": "3.0.2",
        "info": info,
        "servers": [{"url": "."}],
        "tags": [BENTOML_APP_TAG, BENTOML_INFRA_TAG],
        "paths": paths,
    }
    if components:
        schema_name = f"{title.capitalize()}{api_name.capitalize()}Input"
        spec["paths"][api_path]["post"]["requestBody"] = {
            "content": {"application/json": {
                "schema": {"$ref": f"#/components/schemas/{schema_name}"}}}}
        spec["components"] = {"schemas": {schema_name: {
            "type": "object", "properties": {"text": {"type": "string"}},
            "title": "Input"}}}

    return json.dumps(spec, ensure_ascii=False, separators=(",", ":"))


# Un service courant : une méthode d'inférence, un modèle d'entrée déclaré.
BENTOML_DOCS_BODY = bentoml_docs_body()

# Le même document sur un service sans docstring et dont la méthode ne déclare
# aucun modèle d'entrée : ni info.description ni components ne sont écrits. Le
# template doit toujours le reconnaître.
BENTOML_DOCS_MINIMAL_BODY = bentoml_docs_body(
    title="iris_classifier", version="rfwc3ndq2gsbg6qr",
    api_path="/classify", api_name="classify",
    description=None, components=False)

# Le même corps relayé par un intermédiaire qui réindente ce qu'il transporte.
BENTOML_DOCS_REFORMATTED_BODY = json.dumps(json.loads(BENTOML_DOCS_BODY),
                                           ensure_ascii=False, indent=2)

# Une autre passerelle d'inférence, application FastAPI munie des mêmes sondes
# Kubernetes et publiant son schéma au même endroit : « openapi », « paths »,
# « /livez », « /readyz », « /healthz », « /metrics » et une route POST
# d'inférence. Tout le vocabulaire y est, aucun des deux libellés n'y est.
OTHER_FASTAPI_DOCS_BODY = json.dumps({
    "openapi": "3.1.0",
    "info": {"title": "inference-gateway", "version": "2.3.0"},
    "paths": {
        "/livez": {"get": {"summary": "Livez", "tags": ["health"]}},
        "/readyz": {"get": {"summary": "Readyz", "tags": ["health"]}},
        "/healthz": {"get": {"summary": "Healthz", "tags": ["health"]}},
        "/metrics": {"get": {"summary": "Metrics", "tags": ["health"]}},
        "/predict": {"post": {"summary": "Predict", "tags": ["inference"],
                              "operationId": "predict_predict_post"}},
    },
}, ensure_ascii=False, separators=(",", ":"))

# La même passerelle, mais placée devant un service BentoML dont elle recopie la
# description de la route proxifiée — cas ordinaire d'un agrégateur qui republie
# les schémas qu'il rassemble. Le libellé d'APP_TAG figure donc mot pour mot dans
# son document sans qu'il soit BentoML, et celui d'INFRA_TAG n'y est pas : c'est
# ce corps qui rend nécessaire d'exiger les deux ensemble.
OTHER_GATEWAY_QUOTING_BENTOML_BODY = json.dumps({
    "openapi": "3.1.0",
    "info": {"title": "inference-gateway", "version": "2.3.0",
             "description": BENTOML_APP_TAG["description"]},
    "paths": {
        "/livez": {"get": {"summary": "Livez"}},
        "/readyz": {"get": {"summary": "Readyz"}},
        "/upstream/summarize": {"post": {
            "summary": "Summarize",
            "description": BENTOML_APP_TAG["description"]}},
    },
}, ensure_ascii=False, separators=(",", ":"))


def bentoml_scenario(livez, readyz, docs):
    return {BENTOML_LIVEZ: livez, BENTOML_READYZ: readyz, BENTOML_DOCS: docs}


BENTOML_PROBE_OK = (200, BENTOML_PROBE_BODY)

# Une instance servie telle quelle : les sondes répondent, le document se lit.
BENTOML_OPEN = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK,
    docs=(200, BENTOML_DOCS_BODY))

# La même, sur un service sans docstring ni modèle d'entrée déclaré.
BENTOML_OPEN_MINIMAL = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK,
    docs=(200, BENTOML_DOCS_MINIMAL_BODY))

# La même, derrière un intermédiaire qui réindente le document et normalise la
# fin de ligne des sondes.
BENTOML_OPEN_REFORMATTED = bentoml_scenario(
    livez=(200, "\r\n"), readyz=(200, "\r\n"),
    docs=(200, BENTOML_DOCS_REFORMATTED_BODY))

# Le service tourne mais n'est pas prêt à recevoir du trafic : readyz refuse,
# HTTPException(500). L'inférence n'est alors servie à personne.
BENTOML_NOT_READY = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=(500, "Internal Server Error"),
    docs=(200, BENTOML_DOCS_BODY))

# Un mandataire n'ouvre les sondes qu'à sa supervision et garde le reste : les
# deux premières réponses sont exactement celles de l'instance ouverte.
BENTOML_DOCS_GUARDED = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK,
    docs=(401, '{"detail":"Not authenticated"}'))

# Un cache placé devant relaie le document qu'il détient sous le statut du refus,
# alors que le serveur, lui, a refusé.
BENTOML_CACHED_UNDER_REFUSAL = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK,
    docs=(401, BENTOML_DOCS_BODY))

# Un cache indexé sur l'hôte et non sur le chemin sert la même réponse aux trois.
BENTOML_DOCS_ON_ALL_PATHS = bentoml_scenario(
    livez=(200, BENTOML_DOCS_BODY), readyz=(200, BENTOML_DOCS_BODY),
    docs=(200, BENTOML_DOCS_BODY))
BENTOML_PROBES_ON_ALL_PATHS = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK, docs=BENTOML_PROBE_OK)

# Une autre passerelle d'inférence, avec les mêmes sondes et son propre schéma.
OTHER_FASTAPI_SERVICE = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK,
    docs=(200, OTHER_FASTAPI_DOCS_BODY))

# La passerelle qui republie la description d'un service BentoML qu'elle
# proxifie.
OTHER_GATEWAY_QUOTING_BENTOML = bentoml_scenario(
    livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK,
    docs=(200, OTHER_GATEWAY_QUOTING_BENTOML_BODY))

# Un portail captif qui répond 200 et sa page à tout ce qu'on lui demande.
BENTOML_BEHIND_CAPTIVE_PORTAL = bentoml_scenario(
    livez=(200, "<html><body>Connexion requise</body></html>"),
    readyz=(200, "<html><body>Connexion requise</body></html>"),
    docs=(200, "<html><body>Connexion requise</body></html>"))

# Un serveur quelconque qui répond 200 à tout.
BENTOML_SERVER_ALWAYS_UP = bentoml_scenario(
    livez=(200, '{"status":"ok"}'), readyz=(200, '{"status":"ok"}'),
    docs=(200, '{"status":"ok"}'))


def bentoml_block():
    doc = load(BENTOML_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.replace("{{BaseURL}}", "") == BENTOML_DOCS
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {BENTOML_DOCS} — les sondes rendent "
        "« PlainTextResponse(\"\\n\") », donc rien qui désigne un produit, et "
        "c'est le document OpenAPI qui porte les deux libellés nommant BentoML"
    )
    return blocks[0]


def bentoml_responses(scenario):
    """
    Range les réponses d'un scénario dans l'ordre des chemins déclarés par le
    template : c'est cet ordre qui donne son numéro à chaque body_N.
    """
    ordered = []
    for path in bentoml_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        assert route in scenario, (
            f"le template interroge un chemin que BentoML ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def bentoml_fires(scenario):
    block = bentoml_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = bentoml_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les trois réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_bentoml_probe_reads_the_schema_and_touches_nothing_else():
    """
    Le document que le template lit est précisément celui qui dirait comment
    appeler le modèle : chemin, méthode et schéma du corps attendu. Le lire est
    le constat ; s'en servir serait la consommation qu'il signale.
    """
    doc = load(BENTOML_TEMPLATE)

    assert bentoml_block().get("req-condition") is True, (
        "le template ne lie pas les trois réponses : sans req-condition, ni "
        "body_N ni status_code_N n'existent, chaque réponse est jugée seule, et "
        "les sondes concluraient de leur côté — or elles ne rendent qu'un saut "
        "de ligne, qui ne désigne aucun produit"
    )

    for block in (doc.get("http") or []):
        assert block.get("method") == "GET", (
            "les trois routes se lisent en GET : un POST sur ce serveur est un "
            "appel d'inférence, donc du calcul déclenché sur les accélérateurs "
            "de l'exploitant"
        )
        assert block.get("body") is None, (
            "le template envoie un corps : sur un serveur BentoML, un corps est "
            "l'entrée d'une méthode d'API"
        )

        for path in (block.get("path") or []):
            route = path.replace("{{BaseURL}}", "")

            for forbidden, why in (
                ("/submit",
                 "le template inscrit une tâche dans la file du service : elle "
                 "serait exécutée aux frais de l'exploitant"),
                ("/retry",
                 "le template relance une tâche déjà soumise"),
                ("/cancel",
                 "le template annule une tâche que l'exploitant a soumise"),
            ):
                assert forbidden not in route, why


def test_bentoml_matcher_needs_the_schema_not_just_the_probes():
    assert bentoml_fires(BENTOML_OPEN), (
        "le template ne reconnaît pas une instance servie telle quelle, celle "
        "dont les sondes répondent et dont le document se lit"
    )
    assert bentoml_fires(BENTOML_OPEN_MINIMAL), (
        "le template exige des clés qu'__omit_if_default__ retire du document — "
        "info.description quand le service n'a pas de docstring, components "
        "quand aucune méthode ne déclare de modèle d'entrée"
    )
    assert bentoml_fires(BENTOML_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte de JSONResponse ou de "
        "la fin de ligne exacte des sondes : un intermédiaire qui réindente ce "
        "qu'il relaie le mettrait en défaut"
    )

    assert not bentoml_fires(OTHER_FASTAPI_SERVICE), (
        "le template déclenche sur une passerelle d'inférence qui n'est pas "
        "BentoML : « openapi », « paths », « /livez » et « /readyz » sont le "
        "vocabulaire de n'importe quelle application FastAPI munie de sondes "
        "Kubernetes, et ne désignent aucun produit"
    )
    assert not bentoml_fires(OTHER_GATEWAY_QUOTING_BENTOML), (
        "le template conclut d'un seul libellé : une passerelle qui republie la "
        "description d'un service BentoML qu'elle proxifie porte celui d'APP_TAG "
        "mot pour mot sans être BentoML — c'est l'exigence des deux ensemble qui "
        "demande le document lui-même plutôt qu'une mention"
    )
    assert not bentoml_fires(BENTOML_DOCS_GUARDED), (
        "le template conclut des sondes seules : elles sont greffées par "
        "get_system_routes et un mandataire peut ne les ouvrir qu'à sa "
        "supervision en gardant le reste — les deux premières réponses sont "
        "alors exactement celles de l'instance ouverte"
    )
    assert not bentoml_fires(BENTOML_CACHED_UNDER_REFUSAL), (
        "le template conclut du seul corps du document : un cache placé devant "
        "l'instance peut relayer celui qu'il détient sous le statut du refus, "
        "alors que le serveur, lui, a refusé"
    )
    assert not bentoml_fires(BENTOML_DOCS_ON_ALL_PATHS), (
        "le template accepte n'importe quoi en guise de réponse des sondes : un "
        "cache indexé sur l'hôte et non sur le chemin sert le document aux "
        "trois, et le constat porterait alors sur une seule route interrogée "
        "trois fois"
    )
    assert not bentoml_fires(BENTOML_PROBES_ON_ALL_PATHS), (
        "le template conclut de trois corps vides : le même cache sert la "
        "réponse des sondes à /docs.json, et rien n'a identifié le produit"
    )
    assert not bentoml_fires(BENTOML_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML là où les sondes rendent un corps "
        "vide : un portail captif qui répond 200 à tout suffirait à le faire "
        "remonter"
    )
    assert not bentoml_fires(BENTOML_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )

    # Collisions internes au pack : ces produits sont eux aussi des applications
    # FastAPI et publient un document OpenAPI de la même famille. Deux templates
    # ne doivent pas revendiquer la même instance.
    for other_body, produit in ((LANGSERVE_OPENAPI_BODY, "LangServe"),
                                (VLLM_OPENAPI_BODY, "vLLM")):
        assert not bentoml_fires(bentoml_scenario(
            livez=BENTOML_PROBE_OK, readyz=BENTOML_PROBE_OK,
            docs=(200, other_body))), (
            f"le template déclenche sur {produit}, déjà couvert par son propre "
            "template"
        )


def test_bentoml_stays_silent_when_the_service_is_not_ready():
    """
    La frontière que le template revendique, fixée dans le sens qui coûte.

    livez rend 200 dès que le processus tourne ; readyz ne le rend qu'une fois le
    service prêt à recevoir du trafic. C'est le serveur lui-même qui fait cette
    distinction, et l'exiger est ce qui sépare « un serveur BentoML est
    joignable » de « l'inférence est servie à qui la demande » — le constat que
    la sévérité retenue suppose.

    La contrepartie est assumée : une instance exposée mais pas encore prête ne
    remonte pas. Elle ne sert alors rien à personne, et elle se referme d'elle-
    même au passage suivant.
    """
    assert not bentoml_fires(BENTOML_NOT_READY), (
        "le template remonte une instance dont readyz refuse : le service n'est "
        "pas prêt à recevoir du trafic, donc l'inférence n'est servie à personne"
    )

    # La contrepartie de ce choix : ce scénario doit rester celui d'une instance
    # ouverte à tout le reste, sans quoi le silence ci-dessus ne prouve rien.
    assert BENTOML_NOT_READY[BENTOML_LIVEZ] == BENTOML_PROBE_OK, (
        "le scénario ne modélise plus un processus qui tourne"
    )
    assert BENTOML_NOT_READY[BENTOML_DOCS] == (200, BENTOML_DOCS_BODY), (
        "le scénario ne modélise plus un document lisible : le silence "
        "viendrait d'ailleurs que de readyz"
    )


def test_bentoml_extractor_stays_on_the_schema_response():
    block = bentoml_block()
    paths = [p.replace("{{BaseURL}}", "") for p in (block.get("path") or [])]
    extractors = block.get("extractors") or []

    assert extractors, (
        "le template ne remonte rien à l'exploitant : signaler que le port "
        "répond ne lui dit ni quel service est servi ni ce qui y est appelable"
    )
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le moteur "
        "émet un résultat par extracteur qui rend quelque chose, donc la même "
        "instance est signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "l'extracteur ne lit pas le JSON du document : une expression libre "
        "remonterait aussi bien des fragments de page"
    )
    assert extractor.get("part") == f"body_{paths.index(BENTOML_DOCS) + 1}", (
        "l'extracteur n'est pas borné à la réponse de /docs.json : sous "
        "req-condition il serait évalué contre les trois, et les deux sondes "
        "n'ont rien à en rendre"
    )

    expressions = extractor.get("json") or []
    assert any(e.startswith(".info.") for e in expressions), (
        "l'extracteur ne remonte pas le nom du service : c'est ce qui, dans le "
        "document, appartient à l'exploitant"
    )
    assert any(e.startswith(".paths") for e in expressions), (
        "l'extracteur ne remonte pas les routes du document : elles sont le "
        "fond du constat, puisqu'un tiers peut les appeler"
    )
    for expression in expressions:
        assert expression.startswith((".info.", ".paths")), (
            f"l'extracteur sort du document ({expression!r})"
        )

    # Et il doit rendre quelque chose sur la réponse qu'il vise. Les routes
    # d'inférence sont les entrées portant un POST : les quatre routes
    # d'infrastructure n'ayant qu'un GET, la sélection les écarte d'elle-même.
    document = json.loads(BENTOML_DOCS_BODY)
    assert document["info"]["title"], (
        "le document ne porte plus de titre : l'extracteur ne rendrait rien"
    )
    inference_routes = [route for route, item in document["paths"].items()
                        if "post" in item]
    assert inference_routes == ["/summarize"], (
        "la sélection des routes d'inférence ne rend plus les seules entrées "
        f"appelables du document : {inference_routes}"
    )


# --------------------------------------------------------------------------
# Triton pose une difficulté qu'aucun template précédent n'avait : ses trois
# routes n'ont pas la même méthode. La sonde est GET-seul, l'index est POST-seul,
# et les deux doivent pourtant être jugées ensemble — d'où `raw` plutôt que
# `path`, un bloc ne portant qu'une méthode. Le partage des rôles est en
# revanche le même que chez BentoML : la sonde dit l'état sans nommer personne,
# une seconde route identifie le produit, la troisième porte le constat. Ce qui
# identifie n'est ici ni le nom rendu par /v2 — « triton » par défaut, mais --id
# le change — ni la forme de la réponse, « name », « version » et
# « extensions » étant le vocabulaire du protocole KServe v2 que d'autres
# serveurs implémentent, mais le contenu de la liste d'extensions.

TRITON_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                               "triton-inference-server-exposed.yaml")

TRITON_READY = "/v2/health/ready"
TRITON_METADATA = "/v2"
TRITON_INDEX = "/v2/repository/index"

# Ce que rend HandleServerHealth : rien n'est écrit dans buffer_out, la réponse
# se réduit à « evhtp_send_reply(req, ready ? EVHTP_RES_OK : EVHTP_RES_BADREQ) ».
TRITON_READY_BODY = ""

# Les extensions poussées sans condition par le constructeur d'InferenceServer,
# avant celles qu'un drapeau de compilation subordonne.
TRITON_CORE_EXTENSIONS = [
    "classification", "sequence", "model_repository",
    "model_repository(unload_dependents)", "schedule_policy",
    "model_configuration", "system_shared_memory", "cuda_shared_memory",
    "binary_tensor_data", "parameters",
]

# Celles que TRITON_ENABLE_STATS, TRITON_ENABLE_TRACING et TRITON_ENABLE_LOGGING
# ajoutent : une compilation qui les retire ne doit pas faire taire le template.
TRITON_OPTIONAL_EXTENSIONS = ["statistics", "trace", "logging"]


def triton_metadata_body(name="triton", version="2.62.0", extensions=None):
    """
    Ce que /v2 rend : les trois clés que TRITONSERVER_ServerMetadata pose, dans
    la sérialisation compacte de rapidjson.

    `name` vaut lserver->Id(), donc « triton » par défaut et ce que --id dit
    sinon — le template ne doit pas en dépendre.
    """
    if extensions is None:
        extensions = TRITON_CORE_EXTENSIONS + TRITON_OPTIONAL_EXTENSIONS
    return json.dumps({"name": name, "version": version,
                       "extensions": extensions}, separators=(",", ":"))


def triton_index_body(models=(("densenet_onnx", "1", "READY"),
                              ("simple", "1", "READY"))):
    """
    Ce que rend TRITONSERVER_ServerModelIndex : un tableau dont chaque entrée
    porte toujours « name », et « version » / « state » seulement quand le
    modèle a un état — un modèle présent au dépôt mais jamais chargé est écrit
    sous son seul nom, name_only_ valant alors vrai.
    """
    entries = []
    for name, version, state in models:
        entry = {"name": name}
        if version is not None:
            entry["version"] = version
        if state is not None:
            entry["state"] = state
        entries.append(entry)
    return json.dumps(entries, separators=(",", ":"))


TRITON_METADATA_BODY = triton_metadata_body()
TRITON_INDEX_BODY = triton_index_body()

# Une instance dont l'exploitant a changé le nom rendu par /v2 : --id le pose, et
# il ne ferme rien. Le template doit toujours la reconnaître.
TRITON_METADATA_RENAMED_BODY = triton_metadata_body(name="prod-inference-01")

# Une compilation sans statistiques, sans traçage et sans journalisation : trois
# extensions en moins, et ce sont justement celles qui sont conditionnelles.
TRITON_METADATA_MINIMAL_BODY = triton_metadata_body(
    extensions=TRITON_CORE_EXTENSIONS)

# Un dépôt en mode EXPLICIT dont les modèles ne sont pas chargés : le
# sérialiseur n'écrit que « name ». C'est le cas qui interdit d'exiger « state ».
TRITON_INDEX_NAME_ONLY_BODY = triton_index_body(
    models=(("densenet_onnx", None, None), ("simple", None, None)))

# Les mêmes corps relayés par un intermédiaire qui réindente ce qu'il transporte.
TRITON_METADATA_REFORMATTED_BODY = json.dumps(json.loads(TRITON_METADATA_BODY),
                                              indent=2)
TRITON_INDEX_REFORMATTED_BODY = json.dumps(json.loads(TRITON_INDEX_BODY),
                                           indent=2)

# Un dépôt vide : le tableau est là, il ne nomme personne.
TRITON_INDEX_EMPTY_BODY = "[]"

# Un autre serveur d'inférence parlant le même protocole KServe v2 : mêmes
# routes, mêmes trois clés dans /v2, même forme de réponse. Tout le vocabulaire
# du protocole y est, aucune des deux extensions de Triton n'y est.
OTHER_KSERVE_METADATA_BODY = json.dumps(
    {"name": "mlserver", "version": "1.7.0",
     "extensions": ["kserve", "model_repository"]}, separators=(",", ":"))

# Une passerelle qui republie une extension du serveur qu'elle proxifie — cas
# ordinaire d'un agrégateur. La chaîne la plus distinctive de Triton figure donc
# mot pour mot dans sa réponse sans qu'il soit Triton, et la seconde n'y est
# pas : c'est ce corps qui rend nécessaire d'exiger les deux ensemble.
OTHER_GATEWAY_QUOTING_TRITON_BODY = json.dumps(
    {"name": "inference-gateway", "version": "2.3.0",
     "extensions": ["model_repository", "model_repository(unload_dependents)"]},
    separators=(",", ":"))


def triton_scenario(ready, metadata, index):
    return {TRITON_READY: ready, TRITON_METADATA: metadata, TRITON_INDEX: index}


TRITON_READY_OK = (200, TRITON_READY_BODY)

# Une instance servie telle quelle : la sonde répond, les métadonnées se lisent,
# l'index nomme les modèles.
TRITON_OPEN = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, TRITON_METADATA_BODY),
    index=(200, TRITON_INDEX_BODY))

# La même, renommée par --id et compilée sans les extensions conditionnelles.
TRITON_OPEN_RENAMED = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, TRITON_METADATA_RENAMED_BODY),
    index=(200, TRITON_INDEX_BODY))
TRITON_OPEN_MINIMAL_BUILD = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, TRITON_METADATA_MINIMAL_BODY),
    index=(200, TRITON_INDEX_BODY))

# La même, en mode EXPLICIT avec un dépôt dont rien n'est chargé : l'index ne
# porte que des noms.
TRITON_OPEN_NAME_ONLY_INDEX = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, TRITON_METADATA_BODY),
    index=(200, TRITON_INDEX_NAME_ONLY_BODY))

# La même, derrière un intermédiaire qui réindente et ajoute une fin de ligne.
TRITON_OPEN_REFORMATTED = triton_scenario(
    ready=(200, "\n"), metadata=(200, TRITON_METADATA_REFORMATTED_BODY),
    index=(200, TRITON_INDEX_REFORMATTED_BODY))

# Le serveur tourne mais ne se déclare pas prêt : HandleServerHealth rend 400, et
# sous --strict-readiness — vrai par défaut — cela veut dire qu'un modèle au
# moins n'est pas chargé.
TRITON_NOT_READY = triton_scenario(
    ready=(400, ""), metadata=(200, TRITON_METADATA_BODY),
    index=(200, TRITON_INDEX_BODY))

# --http-restricted-api ferme metadata sans fermer health : les catégories se
# restreignent une à une, et la sonde reste exactement celle de l'instance
# ouverte.
TRITON_METADATA_RESTRICTED = triton_scenario(
    ready=TRITON_READY_OK, metadata=(401, '{"error":"This API is restricted"}'),
    index=(200, TRITON_INDEX_BODY))

# La même restriction posée sur model-repository : c'est le constat lui-même qui
# est refusé, et les deux premières réponses ne le disent pas.
TRITON_INDEX_RESTRICTED = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, TRITON_METADATA_BODY),
    index=(401, '{"error":"This API is restricted"}'))

# Un cache placé devant relaie l'index qu'il détient sous le statut du refus,
# alors que le serveur, lui, a refusé.
TRITON_CACHED_UNDER_REFUSAL = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, TRITON_METADATA_BODY),
    index=(401, TRITON_INDEX_BODY))

# Un dépôt vide : le template ne doit pas conclure d'un tableau qui ne nomme
# personne.
TRITON_EMPTY_REPOSITORY = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, TRITON_METADATA_BODY),
    index=(200, TRITON_INDEX_EMPTY_BODY))

# Un cache indexé sur l'hôte et non sur le chemin sert la même réponse aux trois.
TRITON_METADATA_ON_ALL_PATHS = triton_scenario(
    ready=(200, TRITON_METADATA_BODY), metadata=(200, TRITON_METADATA_BODY),
    index=(200, TRITON_METADATA_BODY))
TRITON_INDEX_ON_ALL_PATHS = triton_scenario(
    ready=(200, TRITON_INDEX_BODY), metadata=(200, TRITON_INDEX_BODY),
    index=(200, TRITON_INDEX_BODY))
TRITON_PROBE_ON_ALL_PATHS = triton_scenario(
    ready=TRITON_READY_OK, metadata=TRITON_READY_OK, index=TRITON_READY_OK)

# Un autre serveur d'inférence parlant KServe v2.
OTHER_KSERVE_SERVER = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, OTHER_KSERVE_METADATA_BODY),
    index=(200, TRITON_INDEX_BODY))

# La passerelle qui republie l'extension la plus distinctive de Triton.
OTHER_GATEWAY_QUOTING_TRITON = triton_scenario(
    ready=TRITON_READY_OK, metadata=(200, OTHER_GATEWAY_QUOTING_TRITON_BODY),
    index=(200, TRITON_INDEX_BODY))

# Un portail captif qui répond 200 et sa page à tout ce qu'on lui demande.
TRITON_BEHIND_CAPTIVE_PORTAL = triton_scenario(
    ready=(200, "<html><body>Connexion requise</body></html>"),
    metadata=(200, "<html><body>Connexion requise</body></html>"),
    index=(200, "<html><body>Connexion requise</body></html>"))

# Un serveur quelconque qui répond 200 à tout.
TRITON_SERVER_ALWAYS_UP = triton_scenario(
    ready=(200, '{"status":"ok"}'), metadata=(200, '{"status":"ok"}'),
    index=(200, '{"status":"ok"}'))


def triton_block():
    doc = load(TRITON_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(TRITON_INDEX in raw for raw in (b.get("raw") or []))]
    assert blocks, (
        f"le template n'interroge pas {TRITON_INDEX} — c'est pourtant l'index "
        "que le constat revendique, la sonde ne rendant rien et /v2 ne disant "
        "que ce que le serveur sait de lui-même"
    )
    return blocks[0]


def triton_requests():
    """
    (méthode, chemin) de chaque requête brute, dans l'ordre déclaré : c'est cet
    ordre qui donne son numéro à chaque body_N.

    Le bloc emploie `raw` et non `path` parce que les méthodes diffèrent —
    HandleServerHealth rend 405 sur autre chose qu'un GET, HandleRepositoryIndex
    sur autre chose qu'un POST — et qu'un bloc `path` n'en porte qu'une.
    """
    out = []
    for raw in triton_block().get("raw") or []:
        start_line = raw.strip().splitlines()[0].split()
        assert len(start_line) >= 2, f"requête brute illisible : {raw!r}"
        out.append((start_line[0], start_line[1]))
    return out


def triton_responses(scenario):
    ordered = []
    for _, route in triton_requests():
        assert route in scenario, (
            f"le template interroge un chemin que Triton ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def triton_fires(scenario):
    block = triton_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = triton_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les trois réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_triton_probe_reads_the_index_and_touches_nothing_else():
    """
    L'index que le template lit est précisément ce qui dirait quel modèle
    appeler : chaque nom qu'il rend désigne une route /v2/models/{nom}/infer.
    Le lire est le constat ; s'en servir serait la consommation qu'il signale.
    """
    assert triton_block().get("req-condition") is True, (
        "le template ne lie pas les trois réponses : sans req-condition, ni "
        "body_N ni status_code_N n'existent, chaque réponse est jugée seule, et "
        "la sonde conclurait de son côté — or elle ne rend rien du tout, et un "
        "corps vide ne désigne aucun produit"
    )

    assert triton_requests() == [
        ("GET", TRITON_READY), ("GET", TRITON_METADATA), ("POST", TRITON_INDEX),
    ], (
        "les trois requêtes ne sont plus celles que Triton sert sous ces "
        "méthodes : HandleServerHealth et HandleServerMetadata rendent 405 sur "
        f"autre chose qu'un GET, HandleRepositoryIndex 405 sur autre chose "
        f"qu'un POST — {triton_requests()}"
    )

    for raw in triton_block().get("raw") or []:
        method, route = raw.strip().splitlines()[0].split()[:2]

        # Le POST de l'index n'envoie rien : HandleRepositoryIndex n'inspecte le
        # corps que sous « if (buffer_len > 0) », donc l'absence de corps prend
        # le défaut « ready: false » et demande tout le dépôt. Ne rien envoyer
        # est la garantie que le serveur ne dit que ce qu'il sait de lui-même.
        assert "\n\n" not in raw.strip(), (
            f"le template envoie un corps à {route} : la requête doit se "
            "réduire à sa ligne de départ et à son en-tête d'hôte"
        )

        for forbidden, why in (
            ("/infer",
             "le template appelle une route d'inférence : chaque appel ferait "
             "tourner le modèle sur les accélérateurs de l'exploitant"),
            ("/generate",
             "le template appelle /generate ou /generate_stream, donc fait "
             "produire du texte aux frais de l'exploitant"),
            ("/load",
             "le template charge un modèle que l'index vient de nommer"),
            ("/unload",
             "le template retire de la mémoire un modèle que l'exploitant "
             "sert : il interromprait le service qu'il audite"),
            ("register",
             "le template inscrit une région de mémoire partagée sur "
             "l'instance qu'il audite"),
            ("/v2/logging",
             "le template change la journalisation en cours, donc ce que les "
             "traces retiendront de sa propre visite"),
            ("/trace",
             "le template change le réglage de traçage de l'instance"),
        ):
            assert forbidden not in route, f"{why} ({method} {route})"


def test_triton_matcher_needs_the_extension_list_not_just_the_kserve_shape():
    assert triton_fires(TRITON_OPEN), (
        "le template ne reconnaît pas une instance servie telle quelle, celle "
        "dont la sonde répond et dont l'index nomme les modèles"
    )
    assert triton_fires(TRITON_OPEN_RENAMED), (
        "le template dépend du nom rendu par /v2 : lserver->Id() vaut « triton » "
        "par défaut, mais --id le change sans rien fermer — une instance "
        "renommée reste une instance ouverte"
    )
    assert triton_fires(TRITON_OPEN_MINIMAL_BUILD), (
        "le template exige une extension que TRITON_ENABLE_STATS, "
        "TRITON_ENABLE_TRACING ou TRITON_ENABLE_LOGGING subordonnent : une "
        "compilation qui les retire le mettrait en défaut"
    )
    assert triton_fires(TRITON_OPEN_NAME_ONLY_INDEX), (
        "le template exige « state » ou « version » dans l'index : le "
        "sérialiseur ne les écrit que lorsque le modèle a un état, et un dépôt "
        "en mode EXPLICIT dont rien n'est chargé n'est écrit que sous ses noms"
    )
    assert triton_fires(TRITON_OPEN_REFORMATTED), (
        "le template dépend de la sérialisation compacte de rapidjson ou de "
        "l'absence exacte de fin de ligne sur la sonde : un intermédiaire qui "
        "réindente ce qu'il relaie le mettrait en défaut"
    )

    assert not triton_fires(OTHER_KSERVE_SERVER), (
        "le template déclenche sur un autre serveur parlant KServe v2 : "
        "« name », « version » et « extensions » sont le vocabulaire du "
        "protocole, pas la signature de Triton — ce qui l'identifie est le "
        "contenu de la liste, écrit en dur dans le constructeur "
        "d'InferenceServer"
    )
    assert not triton_fires(OTHER_GATEWAY_QUOTING_TRITON), (
        "le template conclut d'une seule extension : une passerelle qui "
        "republie celle du serveur qu'elle proxifie porte "
        "« model_repository(unload_dependents) » mot pour mot sans être Triton "
        "— c'est l'exigence des deux ensemble qui demande la liste elle-même "
        "plutôt qu'une mention"
    )
    assert not triton_fires(TRITON_METADATA_RESTRICTED), (
        "le template conclut de la sonde et de l'index seuls : "
        "--http-restricted-api se pose catégorie par catégorie, donc metadata "
        "peut être fermée quand health ne l'est pas"
    )
    assert not triton_fires(TRITON_INDEX_RESTRICTED), (
        "le template conclut de la sonde et des métadonnées seules : "
        "model-repository est une catégorie restreignable à part, et les deux "
        "premières réponses sont alors exactement celles de l'instance ouverte"
    )
    assert not triton_fires(TRITON_CACHED_UNDER_REFUSAL), (
        "le template conclut du seul corps de l'index : un cache placé devant "
        "l'instance peut relayer celui qu'il détient sous le statut du refus, "
        "alors que le serveur, lui, a refusé"
    )
    assert not triton_fires(TRITON_METADATA_ON_ALL_PATHS), (
        "le template accepte n'importe quoi en guise d'index : un cache indexé "
        "sur l'hôte et non sur le chemin sert les métadonnées aux trois, et le "
        "constat porterait alors sur une seule route interrogée trois fois"
    )
    assert not triton_fires(TRITON_INDEX_ON_ALL_PATHS), (
        "le template accepte n'importe quoi en guise de sonde et de "
        "métadonnées : le même cache sert l'index aux trois, et rien n'a "
        "identifié le produit"
    )
    assert not triton_fires(TRITON_PROBE_ON_ALL_PATHS), (
        "le template conclut de trois corps vides : le même cache sert la "
        "réponse de la sonde aux trois, et rien n'a été divulgué"
    )
    assert not triton_fires(TRITON_BEHIND_CAPTIVE_PORTAL), (
        "le template accepte une page HTML là où la sonde ne rend rien : un "
        "portail captif qui répond 200 à tout suffirait à le faire remonter"
    )
    assert not triton_fires(TRITON_SERVER_ALWAYS_UP), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


def test_triton_stays_silent_when_nothing_is_served():
    """
    Les deux frontières que le template revendique, fixées dans le sens qui
    coûte.

    La première est l'état : /v2/health/ready rend 400 tant que le serveur ne se
    déclare pas prêt, et sous --strict-readiness — vrai par défaut — cela veut
    dire qu'un modèle au moins n'est pas chargé. L'exiger sépare « un serveur
    Triton est joignable » de « l'inférence est servie à qui la demande », qui
    est le constat que la sévérité retenue suppose.

    La seconde est le fond : un dépôt vide sérialise « [] », et un index qui ne
    nomme personne ne divulgue rien. Ce cas est rare à l'endroit qui compte — en
    mode NONE, qui est le mode par défaut, Triton charge au démarrage tous les
    modèles du dépôt.

    Les deux contreparties sont assumées : ces instances-là ne remontent pas, et
    elles se referment d'elles-mêmes au passage suivant.
    """
    assert not triton_fires(TRITON_NOT_READY), (
        "le template remonte une instance dont la sonde rend 400 : le serveur "
        "ne se déclare pas prêt, donc l'inférence n'est servie à personne"
    )
    assert not triton_fires(TRITON_EMPTY_REPOSITORY), (
        "le template remonte une instance dont l'index est vide : le tableau ne "
        "nomme aucun modèle, et il n'y a rien à divulguer"
    )

    # La contrepartie de ces deux choix : chaque scénario doit rester celui d'une
    # instance ouverte à tout le reste, sans quoi le silence ci-dessus ne prouve
    # rien.
    assert TRITON_NOT_READY[TRITON_INDEX] == (200, TRITON_INDEX_BODY), (
        "le scénario ne modélise plus un index lisible : le silence viendrait "
        "d'ailleurs que de la sonde"
    )
    assert TRITON_EMPTY_REPOSITORY[TRITON_READY] == TRITON_READY_OK, (
        "le scénario ne modélise plus un serveur prêt : le silence viendrait "
        "d'ailleurs que du dépôt vide"
    )
    assert TRITON_EMPTY_REPOSITORY[TRITON_METADATA] == (200,
                                                        TRITON_METADATA_BODY), (
        "le scénario ne modélise plus des métadonnées lisibles"
    )


def test_triton_extractor_stays_on_the_index_response():
    routes = [route for _, route in triton_requests()]
    block = triton_block()
    extractors = block.get("extractors") or []

    assert extractors, (
        "le template ne remonte rien à l'exploitant : signaler que le port "
        "répond ne lui dit pas quels modèles sont servis"
    )
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le moteur "
        "émet un résultat par extracteur qui rend quelque chose, donc la même "
        "instance est signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "l'extracteur ne lit pas le JSON de l'index : une expression libre "
        "remonterait aussi bien des fragments de page"
    )
    assert extractor.get("part") == f"body_{routes.index(TRITON_INDEX) + 1}", (
        "l'extracteur n'est pas borné à la réponse de l'index : sous "
        "req-condition il serait évalué contre les trois, et la sonde n'a rien "
        "à en rendre"
    )

    expressions = extractor.get("json") or []
    assert expressions, "l'extracteur ne porte aucune expression"
    for expression in expressions:
        assert "name" in expression, (
            f"l'extracteur ne remonte pas les noms des modèles ({expression!r}) "
            "— « name » est la seule clé que le sérialiseur écrive sans "
            "condition, et chaque nom désigne une route /v2/models/{nom}/infer "
            "appelable"
        )

    # Et il doit rendre quelque chose sur la réponse qu'il vise, y compris quand
    # l'index ne porte que des noms.
    for body, cas in ((TRITON_INDEX_BODY, "un dépôt chargé"),
                      (TRITON_INDEX_NAME_ONLY_BODY, "un dépôt non chargé")):
        names = [entry.get("name") for entry in json.loads(body)]
        assert names == ["densenet_onnx", "simple"], (
            f"l'index de {cas} ne nomme plus les modèles attendus : {names}"
        )


# --------------------------------------------------------------------------
# CVE-2026-0770. Le template ne constate pas une exposition, il constate qu'un
# sink d'exécution répond à un anonyme — et il doit l'établir en touchant ce
# sink, ce qu'aucun autre template du pack ne fait. Deux exigences en découlent,
# et elles tirent en sens contraire : la sonde doit atteindre exec() pour que le
# constat porte, et elle ne doit rien exécuter d'autre qu'une recherche de nom
# vouée à l'échec.
#
# Le voisin exposure/langflow-unauthenticated.yaml s'interdit explicitement
# cette route ; ici elle est le sujet. C'est la sonde qui doit porter la
# différence, pas l'intention.

CVE_2026_0770_TEMPLATE = os.path.join(TEMPLATES_DIR, "cves", "CVE-2026-0770.yaml")

LANGFLOW_VERSION = "/api/v1/version"
LANGFLOW_VALIDATE = "/api/v1/validate/code"

# Réponse de /api/v1/version, telle que _get_version_info() la construit.
LANGFLOW_VERSION_BODY = (
    '{"version":"1.7.3","main_version":"1.7.3","package":"Langflow"}'
)

# La même route sur une distribution nightly : le nom du paquet change, et la
# version publiée se sépare de sa forme sans segment de pré-publication.
LANGFLOW_VERSION_NIGHTLY_BODY = (
    '{"version":"1.8.0.dev41","main_version":"1.8.0","package":"Langflow Nightly"}'
)

# Le même corps réindenté par un intermédiaire qui relaie.
LANGFLOW_VERSION_REFORMATTED_BODY = json.dumps(
    json.loads(LANGFLOW_VERSION_BODY), indent=2)

# Refus de la dépendance depuis la 1.5 quand LANGFLOW_SKIP_AUTH_AUTO_LOGIN n'est
# pas posé : le corps de la route n'a jamais tourné.
LANGFLOW_AUTO_LOGIN_CLOSED_BODY = (
    '{"detail":"Since v1.5, LANGFLOW_AUTO_LOGIN requires a valid API key. '
    'Set LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true to skip this check. '
    'Please update your authentication method."}'
)

# Refus ordinaire de get_current_user quand AUTO_LOGIN est fermé.
LANGFLOW_API_KEY_REQUIRED_BODY = '{"detail":"Invalid or missing API key"}'

# Enveloppe de CodeValidationResponse quand aucune définition de fonction n'a été
# soumise : la route a désérialisé, mais exec() n'a pas tourné.
LANGFLOW_VALIDATE_INERT_BODY = (
    '{"imports":{"errors":[]},"function":{"errors":[]}}'
)

# Page d'un portail captif qui répond 200 à tout.
CAPTIVE_PORTAL_BODY = "<html><body>Connexion requise</body></html>"


def cve_2026_0770_block():
    doc = load(CVE_2026_0770_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(LANGFLOW_VALIDATE in raw for raw in (b.get("raw") or []))]
    assert blocks, (
        f"le template n'interroge pas POST {LANGFLOW_VALIDATE} — c'est pourtant "
        "la seule route qui mène au exec(code_obj, exec_globals) de "
        "validate_code(), et le constat porte sur ce sink, pas sur l'exposition "
        "de l'API que couvre déjà exposure/langflow-unauthenticated.yaml"
    )
    return blocks[0]


def cve_2026_0770_requests():
    """
    (méthode, chemin) de chaque requête brute, dans l'ordre déclaré : c'est cet
    ordre qui donne son numéro à chaque body_N.
    """
    out = []
    for raw in cve_2026_0770_block().get("raw") or []:
        start_line = raw.strip().splitlines()[0].split()
        assert len(start_line) >= 2, f"requête brute illisible : {raw!r}"
        out.append((start_line[0], start_line[1]))
    return out


def cve_2026_0770_posted_code():
    """
    Le code Python que le template poste, extrait de la requête brute : en-têtes
    puis ligne vide puis corps, et le corps est le modèle Code de Langflow.
    """
    raws = [raw for raw in cve_2026_0770_block().get("raw") or []
            if LANGFLOW_VALIDATE in raw]
    assert raws, "aucune requête brute vers la route de validation"

    head, sep, body = raws[0].partition("\n\n")
    assert sep, (
        "la requête brute n'a pas de corps : sans corps, la route rend une "
        "erreur de validation et le sink n'est pas atteint"
    )
    assert "Content-Type: application/json" in head, (
        "la requête ne déclare pas de corps JSON : FastAPI refuserait avant "
        "d'atteindre validate_code()"
    )

    sent = json.loads(body)
    assert isinstance(sent, dict), "le corps envoyé n'est pas un objet JSON"
    assert set(sent) == {"code"}, (
        f"le corps envoyé n'est pas le modèle Code de Langflow : {sorted(sent)}"
    )
    return sent["code"]


def assert_probe_is_inert(tree):
    """
    Ce que la sonde a le droit de contenir, et rien d'autre : une définition de
    fonction, un corps vide, une unique valeur par défaut qui soit un nom nu.

    Ce contrôle est la condition d'exécution de la transcription ci-dessous.
    L'ordre compte : la suite de tests fait tourner ce que le template poste,
    donc elle doit refuser d'exécuter avant de savoir ce qu'elle exécute. Un
    contrôle qui ne rejetterait que les nœuds `import` laisserait passer
    « __import__(...) », qui est un appel.
    """
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    assert len(tree.body) == 1 and len(functions) == 1, (
        "la sonde n'est pas une définition de fonction seule : tout ce qui "
        "l'entoure est du code que le template envoie sans nécessité"
    )

    function = functions[0]
    assert all(isinstance(stmt, ast.Pass) for stmt in function.body), (
        "le corps de la fonction n'est pas vide : il ne serait certes jamais "
        "exécuté, personne n'appelant la fonction, mais le template n'a aucune "
        "raison de poster du code qu'il ne maîtrise pas"
    )

    defaults = function.args.defaults + [d for d in function.args.kw_defaults if d]
    assert len(defaults) == 1, (
        "la sonde n'a pas exactement une valeur par défaut : c'est elle, et elle "
        "seule, que Python évalue à la définition"
    )
    assert isinstance(defaults[0], ast.Name), (
        "la valeur par défaut n'est pas un nom nu : toute autre expression est "
        "du code que le template ferait tourner sur l'hôte"
    )

    for node in ast.walk(tree):
        assert not isinstance(node, (ast.Import, ast.ImportFrom)), (
            "la sonde contient un import : validate_code() charge réellement "
            "les modules qu'il trouve"
        )
        assert not isinstance(node, (ast.Call, ast.Attribute, ast.Subscript)), (
            f"la sonde contient un {type(node).__name__} : un appel, un accès "
            "d'attribut ou une souscription dans une valeur par défaut est "
            "exactement la primitive de la faille"
        )

    return defaults[0]


def langflow_validate_code(code):
    """
    validate_code() de lfx/custom/validate.py, transcrit terme à terme, pour
    dériver la réponse attendue de l'algorithme lui-même plutôt que de la
    recopier. La branche `import` est délibérément laissée à un refus :
    assert_probe_is_inert établit d'abord que la sonde n'en contient aucun, et
    une transcription qui importerait ferait de la suite de tests le chargeur de
    modules qu'elle est censée interdire.
    """
    errors = {"imports": {"errors": []}, "function": {"errors": []}}
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        errors["function"]["errors"].append(str(e))
        return errors

    assert_probe_is_inert(tree)

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            code_obj = compile(ast.Module(body=[node], type_ignores=[]),
                               "<string>", "exec")
            try:
                # _create_langflow_execution_context() en rend davantage — Data,
                # Message, Component, Output — mais aucune version n'y met le nom
                # que la sonde cherche, et les instances antérieures à ce
                # contexte appellent exec(code_obj) tout court.
                exec(code_obj, {})  # noqa: S102
            except Exception as e:  # noqa: BLE001
                errors["function"]["errors"].append(str(e))

    return errors


def cve_2026_0770_scenario(version, validate):
    return {LANGFLOW_VERSION: version, LANGFLOW_VALIDATE: validate}


def cve_2026_0770_responses(scenario):
    ordered = []
    for _, route in cve_2026_0770_requests():
        assert route in scenario, (
            f"le template interroge un chemin que Langflow ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def cve_2026_0770_fires(scenario):
    block = cve_2026_0770_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = cve_2026_0770_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_cve_2026_0770_identifies_the_vulnerability_it_claims():
    doc = load(CVE_2026_0770_TEMPLATE)
    classification = (doc.get("info") or {}).get("classification") or {}

    assert classification.get("cve-id") == doc.get("id"), (
        "le template ne se réclame pas de la faille que son identifiant nomme : "
        f"cve-id={classification.get('cve-id')!r}, id={doc.get('id')!r}"
    )
    assert classification.get("cwe-id") == "CWE-829", (
        "l'avis retient CWE-829, inclusion de fonctionnalité depuis une sphère "
        "de contrôle non approuvée"
    )

    refs = [str(r) for r in ((doc.get("info") or {}).get("reference") or [])]
    assert any("CVE-2026-0770" in r for r in refs), (
        "aucune référence ne renvoie à l'avis lui-même"
    )

    tags = [t.strip() for t in str((doc.get("info") or {}).get("tags")).split(",")]
    assert "kev" in tags, (
        "la faille est au catalogue KEV de la CISA depuis le 21 juillet 2026 : "
        "le marqueur est ce qui permet de la trier avec les autres"
    )


def test_cve_2026_0770_dsl_expressions_can_be_compiled_by_the_engine():
    """
    Le message que la sonde fait remonter porte des apostrophes — CPython écrit
    « name 'x' is not defined » — et le moteur d'expressions de nuclei n'a qu'un
    seul type de littéral de chaîne : une apostrophe à l'intérieur d'un
    littéral coupe le jeton, et le template est rejeté au chargement avec
    « Cannot transition token types from STRING to VARIABLE ».

    Le piège est que la porte du dépôt ne le voit pas : `nuclei -validate` rend
    « All templates validated successfully » sur un template que le moteur
    refusera ensuite de charger, et `nuclei -tl` l'énumère encore puisqu'il
    liste avant de compiler. Le seul signe est un avertissement au chargement
    d'un vrai scan. Le contrôle porte donc ici, sur le texte des expressions, où
    il est déterministe et ne dépend d'aucun binaire.
    """
    for matcher in cve_2026_0770_block().get("matchers") or []:
        if matcher.get("type") != "dsl":
            continue
        for expression in matcher.get("dsl") or []:
            assert "'" not in expression, (
                "une apostrophe dans une expression dsl empêche le moteur de "
                f"charger le template, et -validate ne le dit pas : {expression}"
            )


def test_cve_2026_0770_probe_reaches_exec_and_does_nothing_else():
    """
    Les deux moitiés de la contrainte, dans l'ordre où elles se vérifient.

    Atteindre exec() : validate_code() n'exécute que les définitions de
    fonction, donc un corps sans `def` n'aurait pas touché le sink et le constat
    ne porterait plus que sur la désérialisation.

    Ne rien exécuter d'autre : aucun import, aucun appel, aucun accès
    d'attribut, aucune souscription — la valeur par défaut doit être un nom nu,
    et le corps de la fonction inatteignable. Ce qui reste est une recherche
    dans un dictionnaire, et elle échoue.
    """
    block = cve_2026_0770_block()

    assert block.get("req-condition") is True, (
        "le template ne lie pas les deux réponses : sans req-condition, la "
        "version conclurait seule — or elle répond sur toute instance, y "
        "compris fermée"
    )

    methods = dict((route, method) for method, route in cve_2026_0770_requests())
    assert methods.get(LANGFLOW_VALIDATE) == "POST", (
        "la route de validation n'est servie qu'en POST : autre chose ne prouve "
        "pas que le sink est atteignable"
    )
    assert methods.get(LANGFLOW_VERSION) == "GET", (
        "la version se lit en GET"
    )

    for _, route in cve_2026_0770_requests():
        assert "auto_login" not in route, (
            "le template appelle /api/v1/auto_login : la route délivre une "
            "session de superutilisateur à qui la demande, et elle écrit en "
            "base au passage"
        )
        assert "custom_component" not in route, (
            "le template appelle /api/v1/custom_component : cette route-là "
            "instancie le composant et exécute son corps, là où la validation "
            "s'arrête à la définition"
        )

    tree = ast.parse(cve_2026_0770_posted_code())

    assert [n for n in tree.body if isinstance(n, ast.FunctionDef)], (
        "la sonde ne définit aucune fonction : validate_code() n'exécute que "
        "les définitions, donc exec() ne tournerait pas et le sink ne serait "
        "pas atteint"
    )

    probe = assert_probe_is_inert(tree).id
    assert "0770" in probe, (
        f"le nom cherché ne porte pas l'identifiant de la faille ({probe!r}) : "
        "l'exploitant qui relit ses journaux doit pouvoir séparer la sonde "
        "d'une tentative"
    )


def test_cve_2026_0770_probe_response_is_derived_from_langflow_own_algorithm():
    """
    La réponse que le matcher attend n'est pas recopiée d'un avis : elle est
    produite en faisant passer la sonde du template dans la transcription de
    validate_code(). Si CPython changeait la formulation du NameError, ou si
    quelqu'un modifiait la sonde, ce test tomberait avant le matcher.
    """
    code = cve_2026_0770_posted_code()
    errors = langflow_validate_code(code)

    assert errors["imports"]["errors"] == [], (
        "la sonde a fait échouer un import : elle en contient donc un"
    )

    messages = errors["function"]["errors"]
    assert len(messages) == 1, (
        "exec() n'a pas rendu exactement une erreur : sans erreur, la réponse "
        "est indiscernable de celle d'un corps sans définition de fonction, et "
        f"le constat ne porterait plus sur le sink ({messages})"
    )
    assert "is not defined" in messages[0], (
        f"exec() a échoué autrement que sur une recherche de nom : {messages[0]!r}"
    )

    body = json.dumps(errors, separators=(",", ":"))
    block = cve_2026_0770_block()
    responses = cve_2026_0770_responses(
        cve_2026_0770_scenario(version=(200, LANGFLOW_VERSION_BODY),
                               validate=(200, body)))
    assert all(dsl_matcher_hits(m, responses)
               for m in (block.get("matchers") or []) if m.get("type") == "dsl"), (
        "le template ne reconnaît pas la réponse que sa propre sonde produit en "
        f"passant dans validate_code() : {body}"
    )


# Les scénarios. La réponse de la route de validation est dérivée de
# l'algorithme, pas recopiée — c'est le même corps que le test précédent
# vérifie.
LANGFLOW_VALIDATE_EXECUTED_BODY = json.dumps(
    langflow_validate_code(cve_2026_0770_posted_code()), separators=(",", ":"))

# Un mandataire qui renverrait la requête en écho : le nom de la sonde y est,
# l'enveloppe non.
LANGFLOW_VALIDATE_ECHO_BODY = json.dumps(
    {"code": cve_2026_0770_posted_code()}, separators=(",", ":"))

# L'instance atteinte : la version se lit, et la validation a exécuté.
CVE_2026_0770_OPEN = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_BODY),
    validate=(200, LANGFLOW_VALIDATE_EXECUTED_BODY))

# La même sur une distribution nightly, et derrière un intermédiaire qui
# réindente ce qu'il relaie.
CVE_2026_0770_OPEN_NIGHTLY = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_NIGHTLY_BODY),
    validate=(200, LANGFLOW_VALIDATE_EXECUTED_BODY))
CVE_2026_0770_OPEN_REFORMATTED = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_REFORMATTED_BODY),
    validate=(200, json.dumps(json.loads(LANGFLOW_VALIDATE_EXECUTED_BODY),
                              indent=2)))

# Instance dont la dépendance refuse : depuis la 1.5 sans
# LANGFLOW_SKIP_AUTH_AUTO_LOGIN, puis AUTO_LOGIN fermé. Dans les deux cas le
# corps de la route n'a pas tourné.
CVE_2026_0770_AUTO_LOGIN_GUARDED = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_BODY),
    validate=(403, LANGFLOW_AUTO_LOGIN_CLOSED_BODY))
CVE_2026_0770_API_KEY_REQUIRED = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_BODY),
    validate=(403, LANGFLOW_API_KEY_REQUIRED_BODY))

# Instance atteinte, mais dont la réponse ne porte pas la trace du exec() : ce
# que rendrait la route si la sonde n'avait pas défini de fonction. Le template
# ne doit pas conclure de la seule enveloppe.
CVE_2026_0770_NO_EXEC_TRACE = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_BODY),
    validate=(200, LANGFLOW_VALIDATE_INERT_BODY))

# Mandataire qui renvoie la requête en écho sous un 200.
CVE_2026_0770_ECHOED = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_BODY),
    validate=(200, LANGFLOW_VALIDATE_ECHO_BODY))

# Cache indexé sur l'hôte et non sur le chemin : il sert la même réponse aux
# deux, dans un sens puis dans l'autre.
CVE_2026_0770_VERSION_ON_BOTH_PATHS = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_BODY),
    validate=(200, LANGFLOW_VERSION_BODY))
CVE_2026_0770_VALIDATE_ON_BOTH_PATHS = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VALIDATE_EXECUTED_BODY),
    validate=(200, LANGFLOW_VALIDATE_EXECUTED_BODY))

# Cache qui relaie le corps d'une instance atteinte sous le statut du refus que
# le serveur, lui, a émis.
CVE_2026_0770_CACHED_UNDER_REFUSAL = cve_2026_0770_scenario(
    version=(200, LANGFLOW_VERSION_BODY),
    validate=(403, LANGFLOW_VALIDATE_EXECUTED_BODY))

# Portail captif qui répond 200 et sa page à n'importe quel chemin.
CVE_2026_0770_CAPTIVE_PORTAL = cve_2026_0770_scenario(
    version=(200, CAPTIVE_PORTAL_BODY), validate=(200, CAPTIVE_PORTAL_BODY))

# Serveur quelconque répondant 200 à tout.
CVE_2026_0770_SERVER_ALWAYS_OK = cve_2026_0770_scenario(
    version=(200, '{"status":"ok"}'), validate=(200, '{"status":"ok"}'))


def test_cve_2026_0770_fires_on_a_reachable_sink_across_distributions():
    assert cve_2026_0770_fires(CVE_2026_0770_OPEN), (
        "le template ne reconnaît pas une instance dont /api/v1/validate/code "
        "a exécuté le code d'un appelant sans identifiant"
    )
    assert cve_2026_0770_fires(CVE_2026_0770_OPEN_NIGHTLY), (
        "le template exige le nom de paquet « Langflow » exact : il raterait "
        "les distributions nightly et langflow-base, que _get_version_info() "
        "nomme « Langflow Nightly » et « Langflow Base »"
    )
    assert cve_2026_0770_fires(CVE_2026_0770_OPEN_REFORMATTED), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindente ce qu'il relaie suffirait à le faire taire"
    )


def test_cve_2026_0770_stays_silent_when_the_sink_did_not_run():
    assert not cve_2026_0770_fires(CVE_2026_0770_AUTO_LOGIN_GUARDED), (
        "le template remonte une instance dont la dépendance a refusé : depuis "
        "la 1.5, AUTO_LOGIN sans LANGFLOW_SKIP_AUTH_AUTO_LOGIN rend 403 et le "
        "corps de la route n'a jamais tourné"
    )
    assert not cve_2026_0770_fires(CVE_2026_0770_API_KEY_REQUIRED), (
        "le template remonte une instance qui réclame une clé d'API"
    )
    assert not cve_2026_0770_fires(CVE_2026_0770_NO_EXEC_TRACE), (
        "le template conclut de la seule enveloppe de CodeValidationResponse : "
        "elle est rendue même quand aucune définition de fonction n'a été "
        "soumise, donc sans que exec() ait tourné — ce serait constater que la "
        "route désérialise, pas que le sink est atteignable"
    )
    assert not cve_2026_0770_fires(CVE_2026_0770_CACHED_UNDER_REFUSAL), (
        "le template conclut du seul corps : un cache placé devant l'instance "
        "peut relayer celui qu'il détient sous le statut du refus, alors que le "
        "serveur, lui, a refusé"
    )


def test_cve_2026_0770_stays_silent_on_what_only_looks_like_the_proof():
    assert not cve_2026_0770_fires(CVE_2026_0770_ECHOED), (
        "le template déclenche sur un écho de sa propre requête : le nom de la "
        "sonde y figure puisque c'est lui qui l'a envoyé, mais rien ne l'a "
        "exécuté — c'est l'enveloppe de la réponse qui sépare les deux"
    )
    assert not cve_2026_0770_fires(CVE_2026_0770_VERSION_ON_BOTH_PATHS), (
        "le template accepte n'importe quoi en guise de réponse de validation : "
        "un cache indexé sur l'hôte et non sur le chemin sert la version aux "
        "deux, et le sink n'a été ni atteint ni même interrogé"
    )
    assert not cve_2026_0770_fires(CVE_2026_0770_VALIDATE_ON_BOTH_PATHS), (
        "le template accepte n'importe quoi en guise de version : le même cache "
        "sert la réponse de validation aux deux, et rien n'a nommé le produit"
    )
    assert not cve_2026_0770_fires(CVE_2026_0770_CAPTIVE_PORTAL), (
        "le template déclenche sur un portail captif qui répond 200 et sa page "
        "à tout ce qu'on lui demande"
    )
    assert not cve_2026_0770_fires(CVE_2026_0770_SERVER_ALWAYS_OK), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


def test_cve_2026_0770_assumes_the_version_route_answers():
    """
    La contrepartie du choix, fixée dans le sens qui coûte : le template exige
    un 200 sur /api/v1/version, donc une instance dont un mandataire fermerait
    cette route-là tout en laissant passer la validation ne remonte pas.

    Le cas est assumé et il est ténu — la route n'a aucune dépendance
    d'authentification et un montage qui refuserait la lecture de la version en
    servant l'exécution de code prendrait les choses à l'envers. Ce qu'il achète
    en retour est la version elle-même, que l'avis ne permet pas de déduire :
    aucune version corrigée n'y est nommée.
    """
    version_closed = cve_2026_0770_scenario(
        version=(403, LANGFLOW_API_KEY_REQUIRED_BODY),
        validate=(200, LANGFLOW_VALIDATE_EXECUTED_BODY))

    assert not cve_2026_0770_fires(version_closed)

    # La contrepartie n'a de sens que si le scénario modélise bien une instance
    # atteinte par ailleurs, sans quoi le silence viendrait d'autre chose.
    assert cve_2026_0770_fires(cve_2026_0770_scenario(
        version=(200, LANGFLOW_VERSION_BODY),
        validate=version_closed[LANGFLOW_VALIDATE])), (
        "le scénario ne modélise plus un sink atteint : le silence viendrait "
        "d'ailleurs que de la route de version"
    )


def test_cve_2026_0770_extractor_stays_on_the_version_response():
    routes = [route for _, route in cve_2026_0770_requests()]
    block = cve_2026_0770_block()
    extractors = block.get("extractors") or []

    assert len(extractors) == 1, (
        "le template ne remonte pas exactement un renseignement : sous "
        "req-condition le moteur émet un résultat par extracteur qui rend "
        "quelque chose, donc la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "l'extracteur ne lit pas le JSON de la version"
    )
    assert extractor.get("part") == f"body_{routes.index(LANGFLOW_VERSION) + 1}", (
        "l'extracteur n'est pas borné à la réponse de la version : sous "
        "req-condition il serait évalué contre les deux, et la réponse de la "
        "sonde ne contient que l'écho de ce que le template a envoyé"
    )

    expressions = extractor.get("json") or []
    assert expressions, "l'extracteur ne porte aucune expression"
    for expression in expressions:
        assert "version" in expression, (
            f"l'extracteur ne remonte pas la version ({expression!r}) — c'est "
            "le renseignement qui manque au rapport, l'avis ne nommant aucune "
            "version corrigée"
        )

    # Et il doit rendre quelque chose sur la réponse qu'il vise.
    assert json.loads(LANGFLOW_VERSION_BODY)["version"] == "1.7.3", (
        "le corps de référence ne porte plus la version attendue"
    )


# --------------------------------------------------------------------------
# CVE-2026-55255. Deux choses séparent ce template de son voisin CVE-2026-0770,
# et les deux tirent la suite de tests.
#
# La première : le correctif ne change rien de ce que le serveur donne à lire.
# La 1.9.1 pose un filtre à l'intérieur de get_flow_by_id_or_endpoint_name() ;
# vue du dehors, elle répond à la sonde exactement comme la 1.9.0. La version
# est donc le seul discriminant, et un template qui ne la bornerait pas
# signalerait toutes les instances corrigées. C'est ce que teste la table des
# versions ci-dessous, et c'est la raison d'être de ce bloc.
#
# La seconde : le sink est ici une exécution de flux, pas une compilation. La
# sonde doit atteindre la recherche non filtrée sans que rien ne tourne — donc
# un UUID qui ne peut désigner aucun flux, et aucun autre champ qui ferait
# dévier le handler.

CVE_2026_55255_TEMPLATE = os.path.join(TEMPLATES_DIR, "cves", "CVE-2026-55255.yaml")

LANGFLOW_RESPONSES = "/api/v1/responses"

# La version corrigée, telle que l'avis GHSA-qrpv-q767-xqq2 la nomme. Tout ce
# qui est en dessous est atteint, tout ce qui est au-dessus ne l'est plus.
LANGFLOW_IDOR_FIXED_IN = (1, 9, 1)


def langflow_version_body(version, package="Langflow", indent=None):
    """
    Réponse de /api/v1/version, telle que _get_version_info() la construit :
    la version publiée, la même privée de son segment de pré-publication, et le
    nom d'affichage du paquet installé.
    """
    main = version
    for keyword in ("a", "b", "rc", "dev", "post"):
        if keyword in main:
            main = main.split(keyword)[0][:-1]
            break
    payload = {"version": version, "main_version": main, "package": package}
    if indent is None:
        return json.dumps(payload, separators=(",", ":"))
    return json.dumps(payload, indent=indent)


def langflow_flow_not_found_body(model, indent=None):
    """
    Ce que rend POST /api/v1/responses sur un identifiant qui ne désigne aucun
    flux, transcrit du handler plutôt que recopié d'un avis.

    Le chemin est celui-ci : get_flow_by_id_or_endpoint_name() lève un 404, le
    handler le rattrape et met flow à None, puis rend OpenAIErrorResponse
    construit par create_openai_error(). Le tout sous un 200 — l'erreur est une
    valeur de retour, pas une exception, donc FastAPI ne change pas le statut.
    """
    error = {
        "message": f"Flow with id '{model}' not found",
        "type": "invalid_request_error",
        "code": "flow_not_found",
    }
    payload = {"error": error}
    if indent is None:
        return json.dumps(payload, separators=(",", ":"))
    return json.dumps(payload, indent=indent)


# Refus de api_key_security quand AUTO_LOGIN est posé sans
# LANGFLOW_SKIP_AUTH_AUTO_LOGIN : le corps de la route n'a jamais tourné.
LANGFLOW_AUTO_LOGIN_ERROR_BODY = json.dumps(
    {"detail": "Since v1.5, LANGFLOW_AUTO_LOGIN requires a valid API key. "
               "Set LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true to skip this check. "
               "Please update your authentication method."},
    separators=(",", ":"))

# Refus de la même dépendance quand AUTO_LOGIN est fermé et qu'aucune clé n'est
# présentée.
LANGFLOW_API_KEY_MISSING_BODY = json.dumps(
    {"detail": "An API key must be passed as query or header"},
    separators=(",", ":"))


def cve_2026_55255_block():
    doc = load(CVE_2026_55255_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(LANGFLOW_RESPONSES in raw for raw in (b.get("raw") or []))]
    assert blocks, (
        f"le template n'interroge pas POST {LANGFLOW_RESPONSES} — c'est "
        "pourtant la seule route qui remet l'identifiant du flux à l'appelant, "
        "donc la seule qui expose la branche UUID non filtrée de "
        "get_flow_by_id_or_endpoint_name()"
    )
    return blocks[0]


def cve_2026_55255_requests():
    out = []
    for raw in cve_2026_55255_block().get("raw") or []:
        start_line = raw.strip().splitlines()[0].split()
        assert len(start_line) >= 2, f"requête brute illisible : {raw!r}"
        out.append((start_line[0], start_line[1]))
    return out


def cve_2026_55255_posted_request():
    """
    Le corps JSON que le template poste, extrait de la requête brute : c'est le
    modèle OpenAIResponsesRequest.
    """
    raws = [raw for raw in cve_2026_55255_block().get("raw") or []
            if LANGFLOW_RESPONSES in raw]
    assert raws, "aucune requête brute vers la route des réponses"

    head, sep, body = raws[0].partition("\n\n")
    assert sep, (
        "la requête brute n'a pas de corps : sans corps, FastAPI rend une "
        "erreur de validation et le helper n'est jamais interrogé"
    )
    assert "Content-Type: application/json" in head, (
        "la requête ne déclare pas de corps JSON : FastAPI refuserait avant "
        "d'atteindre le handler"
    )

    sent = json.loads(body)
    assert isinstance(sent, dict), "le corps envoyé n'est pas un objet JSON"
    return sent


def cve_2026_55255_scenario(version, responses):
    return {LANGFLOW_VERSION: version, LANGFLOW_RESPONSES: responses}


def cve_2026_55255_responses(scenario):
    ordered = []
    for _, route in cve_2026_55255_requests():
        assert route in scenario, (
            f"le template interroge un chemin que Langflow ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def cve_2026_55255_fires(scenario):
    block = cve_2026_55255_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = cve_2026_55255_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def cve_2026_55255_open_on(version, package="Langflow"):
    """
    Instance atteinte tournant `version` : la version se lit, et la route des
    réponses a servi l'anonyme. La réponse de la sonde est dérivée du handler,
    pas recopiée.
    """
    return cve_2026_55255_scenario(
        version=(200, langflow_version_body(version, package)),
        responses=(200, langflow_flow_not_found_body(
            cve_2026_55255_posted_request()["model"])))


def test_cve_2026_55255_identifies_the_vulnerability_it_claims():
    doc = load(CVE_2026_55255_TEMPLATE)
    classification = (doc.get("info") or {}).get("classification") or {}

    assert classification.get("cve-id") == doc.get("id"), (
        "le template ne se réclame pas de la faille que son identifiant nomme : "
        f"cve-id={classification.get('cve-id')!r}, id={doc.get('id')!r}"
    )
    assert classification.get("cwe-id") == "CWE-639", (
        "l'avis retient CWE-639, contournement d'autorisation par clé contrôlée "
        "par l'utilisateur — ce n'est pas une exécution de code, et confondre "
        "les deux ferait sur-noter le rapport"
    )

    refs = [str(r) for r in ((doc.get("info") or {}).get("reference") or [])]
    assert any("CVE-2026-55255" in r for r in refs), (
        "aucune référence ne renvoie à l'avis lui-même"
    )

    tags = [t.strip() for t in str((doc.get("info") or {}).get("tags")).split(",")]
    assert "kev" in tags, (
        "la faille est au catalogue KEV de la CISA depuis le 7 juillet 2026 : "
        "le marqueur est ce qui permet de la trier avec les autres"
    )


def test_cve_2026_55255_dsl_expressions_can_be_compiled_by_the_engine():
    """
    Le message que la sonde fait remonter porte des apostrophes — le handler
    écrit « Flow with id 'x' not found » — et le moteur d'expressions de nuclei
    n'a qu'un seul type de littéral de chaîne : une apostrophe à l'intérieur
    d'un littéral coupe le jeton, et le template est rejeté au chargement avec
    « Cannot transition token types from STRING to VARIABLE ».

    `nuclei -validate` ne le voit pas. Le contrôle porte donc sur le texte des
    expressions, où il est déterministe et ne dépend d'aucun binaire.
    """
    for matcher in cve_2026_55255_block().get("matchers") or []:
        if matcher.get("type") != "dsl":
            continue
        for expression in matcher.get("dsl") or []:
            assert "'" not in expression, (
                "une apostrophe dans une expression dsl empêche le moteur de "
                f"charger le template, et -validate ne le dit pas : {expression}"
            )


def test_cve_2026_55255_probe_reaches_the_lookup_and_runs_no_flow():
    """
    Les deux moitiés de la contrainte.

    Atteindre la recherche non filtrée : seule la branche UUID de
    get_flow_by_id_or_endpoint_name() est celle que la faille ouvre — la branche
    endpoint_name, elle, reçoit bien le user_id que openai_responses.py lui
    passe. Un identifiant qui ne se parse pas en UUID prendrait donc la branche
    filtrée, et le constat porterait à côté.

    Ne rien exécuter : l'UUID ne doit désigner aucun flux, sans quoi le template
    ferait tourner celui d'autrui — c'est-à-dire commettrait la faille qu'il
    signale, appellerait les fournisseurs de modèles et lirait les secrets. Et
    rien d'autre dans le corps ne doit détourner le handler.
    """
    block = cve_2026_55255_block()

    assert block.get("req-condition") is True, (
        "le template ne lie pas les deux réponses : sans req-condition, la "
        "borne de version et le constat ne se jugent plus ensemble, et chacun "
        "seul est insuffisant"
    )

    methods = dict((route, method) for method, route in cve_2026_55255_requests())
    assert methods.get(LANGFLOW_RESPONSES) == "POST", (
        "la route des réponses n'est servie qu'en POST"
    )
    assert methods.get(LANGFLOW_VERSION) == "GET", (
        "la version se lit en GET"
    )

    for _, route in cve_2026_55255_requests():
        for forbidden, why in (
            ("auto_login", "le template appelle /api/v1/auto_login : la route "
                           "délivre une session de superutilisateur à qui la "
                           "demande, et elle écrit en base au passage"),
            ("/run", "le template appelle une route d'exécution de flux : elle "
                     "fait tourner le flux désigné, ce que ce template a "
                     "précisément pour objet de ne pas faire"),
            ("/webhook", "le template déclenche un flux par son webhook"),
            ("/build", "le template fait construire un flux sur l'instance"),
            ("validate/code", "le template poste du code à exécuter : c'est "
                              "l'objet de CVE-2026-0770.yaml, pas de celui-ci"),
            ("custom_component", "le template instancie un composant, donc "
                                 "exécute son corps"),
        ):
            assert forbidden not in route, why

    sent = cve_2026_55255_posted_request()

    assert set(sent) >= {"model", "input"}, (
        "le corps ne porte pas les deux champs obligatoires de "
        f"OpenAIResponsesRequest : {sorted(sent)} — FastAPI rendrait un 422 et "
        "le handler ne tournerait pas"
    )
    assert "tools" not in sent, (
        "le corps porte « tools » : le handler y répond avant tout le reste par "
        "« Tools are not supported yet » et la recherche du flux n'a pas lieu"
    )
    assert sent.get("stream") in (None, False), (
        "le corps demande un flux SSE : la réponse cesse d'être une enveloppe "
        "lisible d'un bloc"
    )
    assert not sent.get("background"), (
        "le corps demande un traitement en arrière-plan"
    )

    model = sent["model"]
    assert isinstance(model, str), "« model » n'est pas une chaîne"

    parsed = uuid.UUID(model)
    assert str(parsed) == model.lower(), (
        f"« model » n'est pas un UUID canonique ({model!r}) : la branche "
        "vulnérable est celle qui se parse en UUID, tout le reste part dans la "
        "branche endpoint_name, qui est filtrée par user_id"
    )

    # Un UUID que Langflow ne peut pas avoir tiré. uuid4() remplit 122 bits ;
    # celui-ci les laisse tous à zéro sauf le dernier groupe, qui porte le
    # marqueur en clair. Ce qui reste — le numéro de version et la variante —
    # est la forme sous laquelle UUID() l'accepte, rien de plus.
    assert parsed.version == 4, (
        f"l'UUID de la sonde n'a pas la forme d'un uuid4 ({model!r}) : Langflow "
        "tire les siens ainsi, et une forme exotique risque d'être rejetée avant "
        "d'atteindre le helper"
    )
    random_bits = parsed.int & ~((0xF << 76) | (0x3 << 62))
    assert random_bits < (1 << 48), (
        f"l'UUID de la sonde porte des bits aléatoires ({model!r}) : rien "
        "n'exclut alors qu'il désigne un flux réel, et le template exécuterait "
        "le flux d'autrui"
    )
    assert "55255" in model, (
        f"l'UUID de la sonde ne porte pas l'identifiant de la faille ({model!r}) "
        ": l'exploitant qui relit ses journaux doit pouvoir séparer la sonde "
        "d'une tentative — celles observées dans la nature portent des UUID "
        "récoltés sur l'instance"
    )


def test_cve_2026_55255_matcher_recognises_what_the_handler_itself_returns():
    """
    La réponse que le matcher attend n'est pas recopiée d'un avis : elle est
    produite en faisant passer l'identifiant de la sonde dans la transcription du
    chemin d'échec du handler. Si quelqu'un changeait la sonde sans changer le
    matcher, ou l'inverse, ce test tomberait avant eux.
    """
    model = cve_2026_55255_posted_request()["model"]
    body = langflow_flow_not_found_body(model)

    assert model in body, (
        "le message ne renvoie pas l'identifiant demandé : le handler "
        "l'interpole pourtant, et c'est ce qui prouve que cette valeur-là est "
        "descendue dans le helper"
    )
    assert cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, langflow_version_body("1.9.0")),
        responses=(200, body))), (
        f"le template ne reconnaît pas la réponse que sa propre sonde produit "
        f"en passant dans le handler : {body}"
    )


# La table des versions, dérivée de la seule chose que l'avis affirme : le
# correctif est la 1.9.1. Ce qui est en dessous est atteint, ce qui est au-dessus
# ne l'est plus — y compris 1.10 et 1.11, que toute borne écrite à la main
# risque de ranger du mauvais côté en comparant « 1.10 » à « 1.9 » caractère par
# caractère.
LANGFLOW_RELEASED_VERSIONS = [
    "0.6.19", "1.0.19", "1.1.4", "1.2.0", "1.3.0", "1.4.2", "1.5.0", "1.6.9",
    "1.7.0", "1.7.3", "1.8.0", "1.8.4", "1.9.0",
    "1.9.1", "1.9.2", "1.9.3", "1.9.6", "1.10.0", "1.10.3", "1.11.0", "1.11.1",
]


def version_tuple(version):
    return tuple(int(part) for part in version.split("."))


@pytest.mark.parametrize("version", LANGFLOW_RELEASED_VERSIONS)
def test_cve_2026_55255_fires_only_below_the_fixed_version(version):
    """
    Le test qui porte ce template.

    Le correctif de la 1.9.1 pose un filtre user_id à l'intérieur de
    get_flow_by_id_or_endpoint_name(). Rien de ce filtre ne traverse la réponse
    HTTP : sur une 1.9.1 comme sur une 1.9.0, un UUID inconnu rend la même
    enveloppe d'erreur, sous le même 200. La version lue sur /api/v1/version est
    donc le seul discriminant, et un template qui ne la bornerait pas
    signalerait toutes les instances déjà corrigées.

    Le piège est dans la forme de la borne : une comparaison lexicale range
    « 1.10.0 » en dessous de « 1.9.0 ». Les versions au-dessus du correctif sont
    ici gardées en table pour que ce cas-là soit couvert.
    """
    vulnerable = version_tuple(version) < LANGFLOW_IDOR_FIXED_IN

    assert cve_2026_55255_fires(cve_2026_55255_open_on(version)) is vulnerable, (
        f"la version {version} est {'atteinte' if vulnerable else 'corrigée'} "
        f"selon l'avis, et le template dit le contraire — le correctif étant "
        f"invisible du dehors, c'est la borne de version qui décide seule"
    )


def test_cve_2026_55255_fires_across_distributions_and_intermediaries():
    assert cve_2026_55255_fires(cve_2026_55255_open_on("1.9.0.dev41",
                                                      "Langflow Nightly")), (
        "le template rate les distributions nightly : _get_version_info() les "
        "nomme « Langflow Nightly » et sépare la version publiée "
        "« 1.9.0.dev41 » de sa forme normalisée « 1.9.0 », qui est celle sur "
        "laquelle la borne doit se lire"
    )
    assert cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, langflow_version_body("1.8.4", "Langflow Base")),
        responses=(200, langflow_flow_not_found_body(
            cve_2026_55255_posted_request()["model"])))), (
        "le template exige le nom de paquet « Langflow » exact : il raterait "
        "langflow-base, que _get_version_info() nomme « Langflow Base »"
    )
    assert cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, langflow_version_body("1.9.0", indent=2)),
        responses=(200, langflow_flow_not_found_body(
            cve_2026_55255_posted_request()["model"], indent=2)))), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindente ce qu'il relaie suffirait à le faire taire, "
        "or la borne de version se lit sur un couple clé/valeur, donc sur "
        "l'espace qui les sépare"
    )


def test_cve_2026_55255_stays_silent_when_the_route_refused():
    model = cve_2026_55255_posted_request()["model"]

    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, langflow_version_body("1.9.0")),
        responses=(403, LANGFLOW_AUTO_LOGIN_ERROR_BODY))), (
        "le template remonte une instance dont la dépendance a refusé : depuis "
        "la 1.5, AUTO_LOGIN sans LANGFLOW_SKIP_AUTH_AUTO_LOGIN rend 403 et le "
        "corps de la route n'a jamais tourné"
    )
    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, langflow_version_body("1.9.0")),
        responses=(403, LANGFLOW_API_KEY_MISSING_BODY))), (
        "le template remonte une instance qui réclame une clé d'API"
    )
    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, langflow_version_body("1.9.0")),
        responses=(403, langflow_flow_not_found_body(model)))), (
        "le template conclut du seul corps : un cache placé devant l'instance "
        "peut relayer celui qu'il détient sous le statut du refus, alors que le "
        "serveur, lui, a refusé"
    )


def test_cve_2026_55255_stays_silent_on_what_only_looks_like_the_proof():
    model = cve_2026_55255_posted_request()["model"]
    version_body = langflow_version_body("1.9.0")

    # Un mandataire qui renvoie la requête en écho : l'UUID de la sonde y est,
    # puisque c'est lui qui l'a envoyé, mais rien ne l'a cherché.
    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, version_body),
        responses=(200, json.dumps(cve_2026_55255_posted_request(),
                                   separators=(",", ":"))))), (
        "le template déclenche sur un écho de sa propre requête : c'est "
        "l'enveloppe d'erreur OpenAI qui sépare les deux"
    )

    # L'enveloppe est là, mais le message nomme un autre identifiant : ce que
    # rendrait un cache servant l'erreur produite pour un autre appelant. Rien
    # ne dit alors que la valeur du template soit descendue dans le helper.
    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, version_body),
        responses=(200, langflow_flow_not_found_body(
            "3f2a1c88-1d0e-4b7a-9c31-6ee2b0d4a915")))), (
        "le template se contente de l'enveloppe sans vérifier qu'elle renvoie "
        "l'identifiant qu'il a demandé : une erreur mise en cache pour un autre "
        "appelant suffirait à le faire conclure"
    )

    # Cache indexé sur l'hôte et non sur le chemin : il sert la même réponse aux
    # deux, dans un sens puis dans l'autre.
    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, version_body), responses=(200, version_body))), (
        "le template accepte n'importe quoi en guise de réponse de la route : "
        "un cache indexé sur l'hôte sert la version aux deux, et la route n'a "
        "été ni servie ni même interrogée"
    )
    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, langflow_flow_not_found_body(model)),
        responses=(200, langflow_flow_not_found_body(model)))), (
        "le template accepte n'importe quoi en guise de version : le même cache "
        "sert l'erreur aux deux, et rien n'a nommé le produit ni sa version"
    )

    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, CAPTIVE_PORTAL_BODY),
        responses=(200, CAPTIVE_PORTAL_BODY))), (
        "le template déclenche sur un portail captif qui répond 200 et sa page "
        "à tout ce qu'on lui demande"
    )
    assert not cve_2026_55255_fires(cve_2026_55255_scenario(
        version=(200, '{"status":"ok"}'),
        responses=(200, '{"status":"ok"}'))), (
        "le template déclenche sur un serveur quelconque répondant 200 à tout"
    )


def test_cve_2026_55255_extractor_stays_on_the_version_response():
    routes = [route for _, route in cve_2026_55255_requests()]
    extractors = cve_2026_55255_block().get("extractors") or []

    assert len(extractors) == 1, (
        "le template ne remonte pas exactement un renseignement : sous "
        "req-condition le moteur émet un résultat par extracteur qui rend "
        "quelque chose, donc la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "l'extracteur ne lit pas le JSON de la version"
    )
    assert extractor.get("part") == f"body_{routes.index(LANGFLOW_VERSION) + 1}", (
        "l'extracteur n'est pas borné à la réponse de la version : sous "
        "req-condition il serait évalué contre les deux, et la réponse de la "
        "sonde ne contient que l'écho de l'identifiant envoyé"
    )

    expressions = extractor.get("json") or []
    assert expressions, "l'extracteur ne porte aucune expression"
    for expression in expressions:
        assert "version" in expression, (
            f"l'extracteur ne remonte pas la version ({expression!r}) — c'est "
            "elle qui dit la distance à la 1.9.1, donc s'il s'agit d'une mise à "
            "jour de retard ou de neuf"
        )


def test_cve_2026_55255_does_not_duplicate_its_neighbour():
    """
    Deux templates Langflow dans templates/cves/, et le pack n'a de valeur que
    s'ils constatent deux choses différentes. CVE-2026-0770 poste du code à
    /api/v1/validate/code ; celui-ci cherche un flux via /api/v1/responses. Ni
    l'un ni l'autre ne doit se mettre à interroger la route de l'autre.
    """
    ours = {route for _, route in cve_2026_55255_requests()}
    theirs = {route for _, route in cve_2026_0770_requests()}

    assert LANGFLOW_RESPONSES in ours and LANGFLOW_RESPONSES not in theirs
    assert LANGFLOW_VALIDATE in theirs and LANGFLOW_VALIDATE not in ours, (
        "le template poste du code à la route de validation : c'est le constat "
        "de CVE-2026-0770.yaml, et deux templates qui déclenchent sur la même "
        "réponse ne font qu'un doublon de plus"
    )

    assert (load(CVE_2026_55255_TEMPLATE).get("info") or {}).get("severity") \
        in VALID_SEVERITY


# --------------------------------------------------------------------------
# Label Studio pose une difficulté que le pack n'avait pas encore rencontrée :
# la page qui porte le constat est servie identique des deux côtés de la
# frontière. Le contrôle de user_signup est posé sur la seule branche POST —
# « if settings.DISABLE_SIGNUP_WITHOUT_LINK is True: ... raise PermissionDenied() » —
# donc l'instance fermée rend le formulaire et refuse l'envoi. Trouver
# « signup-form » ne prouve donc rien, et c'est la première chose que cette
# section refuse.
#
# Ce qui sépare les deux états est dans le gabarit dont la page hérite :
# users/user_base.html enferme le sélecteur « Sign up / Log in » dans
# « {% if not settings.DISABLE_SIGNUP_WITHOUT_LINK %} ». Les corps ci-dessous
# transcrivent ce gabarit plutôt qu'ils ne recopient une capture, pour que la
# différence testée soit celle de la condition et rien d'autre.

LABEL_STUDIO_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                     "label-studio-signup-open.yaml")

LABEL_STUDIO_VERSION = "/version/"
LABEL_STUDIO_SIGNUP = "/user/signup/"


def label_studio_version_body(release="1.23.0", components=True):
    """
    Ce que rend version_page sur /version/ : collect_versions() sérialisé par
    json.dumps(indent=2) et enveloppé de <pre> — la route choisit cette sortie
    sur « request.path == '/version/' », JsonResponse étant réservé à
    /api/version/.

    « release », « label-studio-os-package » et « label-studio-os-backend » sont
    posés sans condition dans le littéral de tête ; les trois suivants sont
    chacun sous un try, d'où `components` : une installation dont les fichiers
    version.json ne sont pas là ne doit pas faire taire le template.
    """
    short = ".".join(release.split(".")[:2])
    payload = {
        "release": release,
        "label-studio-os-package": {
            "version": release,
            "short_version": short,
            "latest_version_from_pypi": release,
            "latest_version_upload_time": "2026-03-13T08:15:04",
            "current_version_is_outdated": False,
        },
        "label-studio-os-backend": {
            "message": "chore: release " + release,
            "commit": "4b8f2c1d9a7e3f56c0b1d2e3f4a5b6c7d8e9f0a1",
            "date": "2026/03/13 08:15:04",
            "branch": "master",
            "version": release,
        },
    }
    if components:
        payload["label-studio-frontend"] = {"version": "1.20.0"}
        payload["dm2"] = {"version": "1.10.0"}
        payload["label-studio-converter"] = {"version": "1.0.1"}
    payload["edition"] = "Community"
    return "<pre>" + json.dumps(payload, indent=2, ensure_ascii=False) + "</pre>"


def label_studio_toggle(path, signup_open, hostname=""):
    """
    La div « toggle » de users/user_base.html, transcrite du gabarit.

    Les deux liens sont enfermés dans « {% if not settings.DISABLE_SIGNUP_WITHOUT_LINK %} » :
    quand la condition est fausse, Django retire le texte compris entre les
    balises et laisse le reste, donc la div ne contient plus que du blanc. La
    classe « active » est calculée sur request.path, et HOSTNAME — vide par
    défaut — préfixe les deux href.
    """
    inner = ""
    if signup_open:
        inner = (
            '\n        <a href="%s/user/signup" class="%s">Sign up</a>'
            '\n        <a href="%s/user/login" class="%s">Log in</a>\n    '
            % (hostname, "active" if "signup" in path else "",
               hostname, "active" if "login" in path else "")
        )
    return '  <div class="toggle">\n    %s\n  </div>\n' % inner


SIGNUP_FORM = (
    '  <form id="signup-form"\n'
    '        action="/user/signup/?next=%2F"\n'
    '        method="post"\n'
    '  >\n'
    '    <input type="text" class="lsf-input-ls" name="email" id="email">\n'
    '    <input type="password" class="lsf-input-ls" name="password" id="password">\n'
    '    <button type="submit" aria-label="Create Account">Create Account</button>\n'
    '  </form>\n'
)

LOGIN_FORM = (
    '  <form id="login-form" action="/user/login/?next=%2F" method="post">\n'
    '    <input type="text" class="lsf-input-ls" name="email" id="email">\n'
    '    <input type="password" class="lsf-input-ls" name="password" id="password">\n'
    '    <button type="submit" aria-label="Log In">Log in</button>\n'
    '  </form>\n'
)


def label_studio_page(path, signup_open, form=SIGNUP_FORM, hostname=""):
    """
    users/user_base.html rendu autour de son bloc user_content, lui-même rempli
    par user_signup.html ou user_login.html — les deux pages héritent du même
    gabarit, donc du même titre et du même sélecteur.

    Le <title> vient de simple.html, qu'aucune des deux ne redéfinit.
    """
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        '  <meta charset="utf-8">\n'
        '  <title>Label Studio</title>\n'
        '</head>\n<body>\n'
        '<div class="login_page">\n'
        '  <h1>Welcome to Label Studio Community Edition </h1>\n'
        '  <h2>A full-fledged open source solution for data labeling</h2>\n'
        '  <img src="/static/images/opossum_hanging.svg" height="128px" />\n'
        + label_studio_toggle(path, signup_open, hostname)
        + form
        + '</div>\n</body>\n</html>\n'
    )


# La page servie sous le drapeau fflag_feat_front_lsdv_e_297_..._short : le
# gabarit users/new-ui/ ne rend aucun sélecteur, donc l'état de l'inscription
# n'y est plus lisible du dehors. Faux sur une installation par défaut.
LABEL_STUDIO_NEW_UI_PAGE = (
    '<!doctype html>\n<html lang="en">\n<head>\n'
    '  <title>Label Studio</title>\n'
    '</head>\n<body>\n'
    '<div class="login_page_new_ui">\n'
    '  <h3>A full-fledged open source solution for data labeling</h3>\n'
    '  <div class="form-wrapper">\n'
    '    <h2>Sign Up</h2>\n'
    + SIGNUP_FORM +
    '  </div>\n'
    '  <div class="text-wrapper">\n'
    '    <p class="">Already have an account?</p>\n'
    '    <a href="/user/login/">Log in</a>\n'
    '  </div>\n'
    '</div>\n</body>\n</html>\n'
)


def label_studio_scenario(version, signup):
    return {LABEL_STUDIO_VERSION: version, LABEL_STUDIO_SIGNUP: signup}


LABEL_STUDIO_VERSION_OK = (200, label_studio_version_body())

LABEL_STUDIO_SIGNUP_OPEN_PAGE = label_studio_page(LABEL_STUDIO_SIGNUP, True)
LABEL_STUDIO_SIGNUP_CLOSED_PAGE = label_studio_page(LABEL_STUDIO_SIGNUP, False)
LABEL_STUDIO_LOGIN_OPEN_PAGE = label_studio_page("/user/login/", True,
                                                 form=LOGIN_FORM)

# Une instance servie telle quelle : les versions se lisent, et le sélecteur est
# là parce que DISABLE_SIGNUP_WITHOUT_LINK est faux par défaut.
LABEL_STUDIO_OPEN = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK,
    signup=(200, LABEL_STUDIO_SIGNUP_OPEN_PAGE))

# La même, derrière un HOSTNAME posé : les href deviennent absolus.
LABEL_STUDIO_OPEN_BEHIND_HOSTNAME = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK,
    signup=(200, label_studio_page(LABEL_STUDIO_SIGNUP, True,
                                   hostname="https://labelling.interne")))

# La même, dont les fichiers version.json ne sont pas là : les trois clés sous
# try manquent, les deux du littéral de tête restent.
LABEL_STUDIO_OPEN_WITHOUT_COMPONENTS = label_studio_scenario(
    version=(200, label_studio_version_body(components=False)),
    signup=(200, LABEL_STUDIO_SIGNUP_OPEN_PAGE))

# Le cas que tout le template sert à distinguer : l'inscription est fermée, et
# la page est pourtant servie — formulaire compris, le contrôle étant sur POST.
LABEL_STUDIO_SIGNUP_CLOSED = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK,
    signup=(200, LABEL_STUDIO_SIGNUP_CLOSED_PAGE))

# L'interface neuve, qui ne rend aucun sélecteur : rien n'y est lisible, donc
# rien n'y est affirmé.
LABEL_STUDIO_NEW_UI = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK,
    signup=(200, LABEL_STUDIO_NEW_UI_PAGE))

# Un mandataire n'ouvre /version/ qu'à sa supervision et garde le reste.
LABEL_STUDIO_SIGNUP_REFUSED = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK,
    signup=(403, "<html><body>Forbidden</body></html>"))

# L'inverse : la page d'inscription est ouverte, /version/ est fermé. Le produit
# n'est plus identifié, et le template ne conclut pas.
LABEL_STUDIO_VERSION_REFUSED = label_studio_scenario(
    version=(403, "<html><body>Forbidden</body></html>"),
    signup=(200, LABEL_STUDIO_SIGNUP_OPEN_PAGE))

# Un cache relaie la page qu'il détient sous le statut du refus, alors que le
# serveur, lui, a refusé.
LABEL_STUDIO_CACHED_UNDER_REFUSAL = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK,
    signup=(403, LABEL_STUDIO_SIGNUP_OPEN_PAGE))

# Un cache indexé sur l'hôte et non sur le chemin sert la même réponse aux deux.
LABEL_STUDIO_VERSION_ON_ALL_PATHS = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK, signup=LABEL_STUDIO_VERSION_OK)
LABEL_STUDIO_SIGNUP_ON_ALL_PATHS = label_studio_scenario(
    version=(200, LABEL_STUDIO_SIGNUP_OPEN_PAGE),
    signup=(200, LABEL_STUDIO_SIGNUP_OPEN_PAGE))

# Le même cache, servant cette fois la page de connexion sous le chemin de
# l'inscription : elle porte le même titre et le même sélecteur, et seul le
# formulaire les sépare.
LABEL_STUDIO_LOGIN_UNDER_SIGNUP = label_studio_scenario(
    version=LABEL_STUDIO_VERSION_OK,
    signup=(200, LABEL_STUDIO_LOGIN_OPEN_PAGE))

# Un portail captif qui répond 200 et sa page à tout ce qu'on lui demande.
LABEL_STUDIO_BEHIND_CAPTIVE_PORTAL = label_studio_scenario(
    version=(200, "<html><body>Connexion requise</body></html>"),
    signup=(200, "<html><body>Connexion requise</body></html>"))

# Un serveur quelconque qui répond 200 à tout.
LABEL_STUDIO_SERVER_ALWAYS_UP = label_studio_scenario(
    version=(200, '{"status":"ok"}'), signup=(200, '{"status":"ok"}'))


def label_studio_block():
    doc = load(LABEL_STUDIO_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(LABEL_STUDIO_SIGNUP) for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {LABEL_STUDIO_SIGNUP} — c'est pourtant la "
        "page dont le constat parle, /version/ ne disant que ce que le serveur "
        "sait de lui-même"
    )
    return blocks[0]


def label_studio_requests():
    """
    Chemin de chaque requête, dans l'ordre déclaré : c'est cet ordre qui donne
    son numéro à chaque body_N.
    """
    out = []
    for path in label_studio_block().get("path") or []:
        assert path.startswith("{{BaseURL}}"), f"chemin inattendu : {path!r}"
        out.append(path[len("{{BaseURL}}"):])
    return out


def label_studio_responses(scenario):
    ordered = []
    for route in label_studio_requests():
        assert route in scenario, (
            f"le template interroge un chemin que Label Studio ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def label_studio_fires(scenario):
    block = label_studio_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = label_studio_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_label_studio_probe_reads_two_pages_and_never_creates_an_account():
    """
    POST /user/signup/ serait la preuve définitive — on tient le compte ou on ne
    le tient pas — mais save_user inscrit l'utilisateur dans l'organisation
    existante et ouvre sa session : le template créerait le compte qu'il est
    censé signaler, à l'intérieur du périmètre qu'il audite.
    """
    block = label_studio_block()

    assert block.get("method", "GET") == "GET", (
        "le bloc n'est pas en GET : la branche POST de user_signup est la "
        "création de compte elle-même"
    )
    for forbidden in ("body", "raw"):
        assert forbidden not in block, (
            f"le bloc porte « {forbidden} » : la page se lit sans rien envoyer, "
            "et tout corps posté partirait sur la route d'inscription"
        )

    assert set(label_studio_requests()) == {LABEL_STUDIO_VERSION, LABEL_STUDIO_SIGNUP}, (
        "le template touche autre chose que les deux pages en lecture — "
        f"{label_studio_requests()}"
    )

    assert block.get("req-condition") is True, (
        "sans req-condition les deux réponses sont jugées séparément, et "
        "/version/ conclurait seul alors qu'il ne dit rien de l'inscription"
    )


def test_label_studio_matcher_proves_signup_is_open_not_merely_that_it_is_label_studio():
    """
    Le cœur du template. L'instance fermée sert la même page — même titre, même
    formulaire, même route d'action — et seule la div « toggle » les sépare.
    """
    assert label_studio_fires(LABEL_STUDIO_OPEN), (
        "le template ne reconnaît pas une instance Label Studio dont "
        "l'inscription est ouverte"
    )

    assert not label_studio_fires(LABEL_STUDIO_SIGNUP_CLOSED), (
        "le template déclenche sur une instance dont l'inscription est fermée : "
        "le formulaire est servi des deux côtés de la frontière, seul le "
        "sélecteur de users/user_base.html transcrit le réglage"
    )

    # Ce qui ne doit pas faire taire le template : les variantes légitimes d'une
    # instance ouverte.
    for scenario, cas in (
        (LABEL_STUDIO_OPEN_BEHIND_HOSTNAME, "HOSTNAME posé, href absolus"),
        (LABEL_STUDIO_OPEN_WITHOUT_COMPONENTS, "sans les version.json du front"),
    ):
        assert label_studio_fires(scenario), (
            f"le template rate une instance ouverte : {cas}"
        )

    # Ce sur quoi il ne doit pas conclure.
    for scenario, cas in (
        (LABEL_STUDIO_SIGNUP_REFUSED, "la page d'inscription est refusée"),
        (LABEL_STUDIO_VERSION_REFUSED, "le produit n'est pas identifié"),
        (LABEL_STUDIO_CACHED_UNDER_REFUSAL, "la page est relayée sous un refus"),
        (LABEL_STUDIO_VERSION_ON_ALL_PATHS, "/version/ servi sur les deux chemins"),
        (LABEL_STUDIO_SIGNUP_ON_ALL_PATHS, "la page servie sur les deux chemins"),
        (LABEL_STUDIO_LOGIN_UNDER_SIGNUP,
         "la page de connexion servie sous le chemin de l'inscription"),
        (LABEL_STUDIO_BEHIND_CAPTIVE_PORTAL, "un portail captif"),
        (LABEL_STUDIO_SERVER_ALWAYS_UP, "un serveur qui répond 200 à tout"),
    ):
        assert not label_studio_fires(scenario), (
            f"le template conclut alors que {cas}"
        )


def test_label_studio_stays_silent_on_the_ui_that_says_nothing():
    """
    La frontière que le template tient plutôt qu'il ne la masque : le gabarit
    users/new-ui/ ne rend aucun sélecteur, donc l'inscription y est ouverte ou
    fermée sans que rien ne le dise du dehors. Se taire est le seul constat
    honnête — déclencher sur la seule présence du formulaire signalerait aussi
    les instances fermées.
    """
    assert "signup-form" in LABEL_STUDIO_NEW_UI_PAGE, (
        "le cas de test ne dit pas ce qu'il croit dire : c'est bien la page "
        "d'inscription qui doit être servie ici"
    )
    assert not label_studio_fires(LABEL_STUDIO_NEW_UI)


def test_label_studio_extractor_reports_the_release_of_the_version_page():
    routes = label_studio_requests()
    extractors = label_studio_block().get("extractors") or []

    assert extractors, (
        "le template ne remonte rien à l'exploitant : signaler que "
        "l'inscription est ouverte ne lui dit pas quelle version répond"
    )
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le moteur "
        "émet un résultat par extracteur qui rend quelque chose, donc la même "
        "instance est signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("part") == f"body_{routes.index(LABEL_STUDIO_VERSION) + 1}", (
        "l'extracteur n'est pas borné à la réponse de /version/ : sous "
        "req-condition il serait évalué contre les deux, et la page "
        "d'inscription n'a pas de version à rendre"
    )
    assert extractor.get("type") == "regex", (
        "le corps de /version/ est du HTML autour du JSON — « <pre> » puis "
        "json.dumps — donc un extracteur json ne rendrait rien"
    )

    patterns = extractor.get("regex") or []
    assert patterns, "l'extracteur ne porte aucun motif"
    group = extractor.get("group", 0)
    for pattern in patterns:
        found = re.search(pattern, label_studio_version_body(release="1.23.0"))
        assert found, f"le motif ne rend rien sur la page de version : {pattern!r}"
        assert found.group(group) == "1.23.0", (
            "l'extracteur remonte autre chose que la version publiée : "
            f"{found.group(group)!r}"
        )


# --------------------------------------------------------------------------
# llama.cpp expose son état sous /props, un nom aussi banal que /info : la
# signature doit tenir aux clés propres au serveur llama-server, pas au seul
# nom de l'endpoint. "default_generation_settings" et "total_slots" ont été
# ajoutés en février 2024 (llama.cpp#5307, #5373) — les exiger ne rate donc
# que des versions antérieures de plus de deux ans, pas celles qui traînent
# exposées aujourd'hui. "model_path", "chat_template" et "build_info" sont
# sérialisés depuis l'introduction de l'endpoint.

LLAMACPP_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "llamacpp-server-exposed.yaml")

# Réponse de /props sur une build récente de llama-server (tools/server/server-context.cpp).
LLAMACPP_PROPS_BODY = (
    '{"default_generation_settings":{"id":0,"id_task":-1,"n_ctx":4096,'
    '"speculative":false,"is_processing":false,"params":{"n_predict":-1,'
    '"temperature":0.800000011920929,"top_k":40,"top_p":0.949999988079071}},'
    '"total_slots":4,"model_alias":"unknown","model_ftype":"unknown",'
    '"model_path":"/srv/models/llama-3.1-8b-instruct.Q4_K_M.gguf",'
    '"modalities":{"vision":false,"video":false,"audio":false},'
    '"media_marker":"<__media__>","endpoint_slots":false,'
    '"endpoint_props":false,"endpoint_metrics":false,"ui":true,'
    '"chat_template":"{% for message in messages %}...{% endfor %}",'
    '"chat_template_caps":{},"bos_token":"<|begin_of_text|>",'
    '"eos_token":"<|eot_id|>","build_info":"b4327-8a4bad5",'
    '"is_sleeping":false,"cors_proxy_enabled":false}'
)

# Même endpoint juste après l'ajout de total_slots (février 2024) : ni
# modalities, ni model_ftype, ni is_sleeping n'existaient encore. Le template
# doit continuer à reconnaître cette forme plus pauvre.
LLAMACPP_PROPS_BODY_OLDER = (
    '{"default_generation_settings":{"id":0,"n_ctx":2048,"n_predict":-1,'
    '"params":{"temperature":0.8}},"total_slots":1,'
    '"model_path":"/models/llama-2-7b-chat.Q4_K_M.gguf",'
    '"chat_template":"{% if messages[0][\'role\'] == \'system\' %}...{% endif %}",'
    '"build_info":"b2107-abc1234"}'
)

# Une passerelle d'inférence maison nomme aussi son modèle model_path et
# publie un build_info, mais ne sert ni chat_template ni total_slots ni
# default_generation_settings : ces deux clés seules ne prouvent donc rien.
OTHER_PROPS_BODY = (
    '{"model_path":"/models/llama-3.1-8b","build_info":"custom-gateway-1.0",'
    '"backend":"triton","version":"1.2.0","max_batch_size":8}'
)


def test_llamacpp_matcher_holds_across_versions_without_becoming_generic():
    doc = load(LLAMACPP_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/props" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /props"

    block = blocks[0]
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, LLAMACPP_PROPS_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /props de llama-server"
    )
    assert all(word_matcher_hits(m, LLAMACPP_PROPS_BODY_OLDER)
               for m in body_matchers), (
        "le template exige des clés absentes des versions plus anciennes de "
        "llama-server — il raterait les instances qui traînent exposées"
    )
    assert not all(word_matcher_hits(m, OTHER_PROPS_BODY) for m in body_matchers), (
        "le template déclenche sur une passerelle d'inférence qui n'est pas "
        "llama.cpp : model_path et build_info seuls sont des clés banales"
    )
    # Collisions internes au pack : les autres templates de disclosure du
    # modèle servi ne doivent pas être revendiqués par celui-ci.
    for other_body, other_name in (
        (SGLANG_MODEL_INFO_BODY, "sglang"),
        (TGI_INFO_BODY, "text-generation-inference"),
        (LMSTUDIO_MODELS_BODY, "lmstudio"),
        (VLLM_MODELS_BODY, "vllm"),
    ):
        assert not all(word_matcher_hits(m, other_body) for m in body_matchers), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


# --------------------------------------------------------------------------
# AUTOMATIC1111 rend, sous /sdapi/v1/sd-models, un tableau d'objets
# SDModelItem (modules/api/models.py) : title, model_name, hash, sha256,
# filename, config. Aucune de ces clés n'est propre au produit prise seule
# ("hash" et "filename" sont des mots de vocabulaire courant), mais les six
# ensemble, sur le même objet, ne le sont que de ce schéma.

AUTOMATIC1111_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                       "automatic1111-api-exposed.yaml")

# Réponse de GET /sdapi/v1/sd-models telle que get_sd_models() la sérialise
# (modules/api/api.py) à partir de sd_models.checkpoints_list.
AUTOMATIC1111_SD_MODELS_BODY = (
    '[{"title":"v1-5-pruned-emaonly.safetensors [6ce0161689]",'
    '"model_name":"v1-5-pruned-emaonly",'
    '"hash":"81761151",'
    '"sha256":"6ce0161689b3853acaa03779ec93eafe75a02f4ced659bee03f50797806fa2f",'
    '"filename":"/home/user/stable-diffusion-webui/models/Stable-diffusion/'
    'v1-5-pruned-emaonly.safetensors",'
    '"config":null}]'
)

# sha256 pas encore mis en cache (hashes.sha256_from_cache peut rendre None) :
# le template ne doit pas dépendre d'une valeur non nulle.
AUTOMATIC1111_SD_MODELS_BODY_UNHASHED = (
    '[{"title":"sd_xl_base_1.0.safetensors",'
    '"model_name":"sd_xl_base_1.0",'
    '"hash":"31e35c80",'
    '"sha256":null,'
    '"filename":"/models/Stable-diffusion/sd_xl_base_1.0.safetensors",'
    '"config":null}]'
)

# Une passerelle maison qui nomme aussi ses modèles "model_name" et sert un
# "filename" et un "hash", mais pas les trois clés propres à SDModelItem
# (title, sha256, config) : la combinaison des six ne doit pas se réduire à
# un sous-ensemble générique.
AUTOMATIC1111_OTHER_REGISTRY_BODY = (
    '[{"model_name":"llama-3.1-8b","filename":"/models/llama-3.1-8b.gguf",'
    '"hash":"abc12345","backend":"custom-gateway","version":"1.2.0"}]'
)


def test_automatic1111_matcher_holds_across_versions_without_becoming_generic():
    doc = load(AUTOMATIC1111_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/sdapi/v1/sd-models" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /sdapi/v1/sd-models"

    block = blocks[0]
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, AUTOMATIC1111_SD_MODELS_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /sdapi/v1/sd-models "
        "d'AUTOMATIC1111"
    )
    assert all(word_matcher_hits(m, AUTOMATIC1111_SD_MODELS_BODY_UNHASHED)
               for m in body_matchers), (
        "le template exige une valeur pour sha256, qui peut être null tant "
        "que le hash n'a pas été calculé"
    )
    assert not all(word_matcher_hits(m, AUTOMATIC1111_OTHER_REGISTRY_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une passerelle qui n'est pas "
        "AUTOMATIC1111 : model_name, filename et hash seuls sont un "
        "sous-ensemble banal du schéma SDModelItem"
    )
    # Collisions internes au pack : les autres templates de disclosure du
    # modèle servi ne doivent pas être revendiqués par celui-ci.
    for other_body, other_name in (
        (LLAMACPP_PROPS_BODY, "llama.cpp"),
        (SGLANG_MODEL_INFO_BODY, "sglang"),
        (TGI_INFO_BODY, "text-generation-inference"),
        (LMSTUDIO_MODELS_BODY, "lmstudio"),
        (VLLM_MODELS_BODY, "vllm"),
        (XINFERENCE_REGISTRATIONS_BODY, "xinference"),
    ):
        assert not all(word_matcher_hits(m, other_body) for m in body_matchers), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


# --------------------------------------------------------------------------
# Letta expose /v1/health/ sans jamais le garder — check_password.py l'exempte
# nommément du mot de passe, sécurisée ou non — et /v1/agents/ sans dépendance
# d'authentification déclarée. Le premier ne prouve donc que le produit et sa
# version ; c'est le second qui porte le constat, et seulement s'il rend au
# moins un agent : une liste vide ne distingue Letta d'aucune autre API.

LETTA_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "letta-server-unauthenticated.yaml")

# Réponse de GET /v1/health/ telle que check_health() la sérialise
# (routers/v1/health.py) : Health(version=__version__, status="ok").
LETTA_HEALTH_BODY = '{"version":"0.16.8","status":"ok"}'


def letta_agent_state(agent_type="memgpt_agent", name="customer-support-bot"):
    """
    Une AgentState telle que list_agents() la sérialise (schemas/agent.py),
    réduite aux champs requis que le template vérifie plus un minimum de
    contexte réaliste.
    """
    return {
        "id": "agent-3f9b2a1c-5e21-4e60-9c2e-1a2b3c4d5e6f",
        "name": name,
        "system": "You are Letta, the latest version of Limnal Corporation's...",
        "agent_type": agent_type,
        "llm_config": {
            "model": "gpt-4o-mini",
            "model_endpoint_type": "openai",
            "model_endpoint": "https://api.openai.com/v1",
            "context_window": 128000,
        },
        "memory": {
            "agent_type": agent_type,
            "blocks": [
                {"label": "persona", "value": "I am a helpful assistant.", "limit": 5000},
                {"label": "human", "value": "The user's name is Jane Doe.", "limit": 5000},
            ],
        },
        "blocks": [],
        "tools": [],
        "sources": [],
        "tags": [],
    }


def letta_agents_body(*agents):
    return json.dumps(list(agents), separators=(",", ":"))


LETTA_AGENTS_BODY = letta_agents_body(letta_agent_state())

# Instance neuve : aucun agent n'a encore été créé, list_agents() rend "[]",
# et le corps ne porte donc plus aucune des neuf valeurs de l'enum AgentType.
LETTA_EMPTY_AGENTS_BODY = "[]"

# Une passerelle maison qui emprunte le même vocabulaire ("agent_type",
# "llm_config", "memory") sans être Letta : les trois clés seules, sans une
# valeur de l'enum AgentType, ne doivent pas suffire.
LETTA_OTHER_AGENT_FRAMEWORK_BODY = json.dumps([
    {"id": "wf-1", "name": "generic-agent", "agent_type": "custom_agent",
     "llm_config": {"model": "llama-3.1-8b"}, "memory": {"blocks": []}},
], separators=(",", ":"))


def letta_block():
    doc = load(LETTA_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v1/agents/" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /v1/agents/"
    return blocks[0]


def letta_responses(health_status=200, health_body=LETTA_HEALTH_BODY,
                     agents_status=200, agents_body=LETTA_AGENTS_BODY):
    """
    Range les réponses dans l'ordre des chemins déclarés par le template :
    c'est cet ordre qui donne son numéro à chaque body_N sous req-condition.
    """
    ordered = []
    for path in letta_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        if route == "/v1/health/":
            ordered.append((health_status, health_body))
        elif route == "/v1/agents/":
            ordered.append((agents_status, agents_body))
        else:
            raise AssertionError(f"le template interroge un chemin inattendu : {route}")
    return ordered


def letta_fires(**kwargs):
    block = letta_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = letta_responses(**kwargs)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_letta_reads_health_then_agents_and_touches_nothing_else():
    doc = load(LETTA_TEMPLATE)
    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "la liste des agents se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/tools/", "POST .../tools/{tool_name}/run exécuterait un "
                            "outil déjà attaché à l'agent avec ses secrets "
                            "déchiffrés"),
                ("/core-memory", "PATCH .../core-memory/blocks/{label} "
                                 "réécrirait la mémoire centrale de l'agent"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    assert letta_block().get("req-condition") is True, (
        "sans req-condition, /v1/health/ conclurait seul — or check_password.py "
        "l'exempte nommément du mot de passe dans les deux branches, "
        "sécurisée ou non, donc il ne dit rien de l'autorisation"
    )


def test_letta_matcher_needs_a_real_agent_not_just_a_reachable_route():
    assert letta_fires(), (
        "le template ne reconnaît pas une instance Letta ouverte avec un "
        "agent memgpt_agent"
    )
    for other_type in ("memgpt_v2_agent", "letta_v1_agent", "react_agent",
                       "workflow_agent", "split_thread_agent", "sleeptime_agent",
                       "voice_convo_agent", "voice_sleeptime_agent"):
        body = letta_agents_body(letta_agent_state(agent_type=other_type))
        assert letta_fires(agents_body=body), (
            f"le template dépend d'un type d'agent précis alors que "
            f"{other_type} est l'une des neuf valeurs valides de l'enum "
            "AgentType"
        )
    assert not letta_fires(agents_body=LETTA_EMPTY_AGENTS_BODY), (
        "une instance neuve sans agent rend \"[]\" : rien n'y distingue "
        "Letta d'une autre API, le template a raison de rester silencieux"
    )
    assert not letta_fires(agents_body=LETTA_OTHER_AGENT_FRAMEWORK_BODY), (
        "le template déclenche sur une passerelle qui emprunte le même "
        "vocabulaire (agent_type, llm_config, memory) sans être Letta : les "
        "clés seules, sans une valeur de l'enum AgentType, ne prouvent rien"
    )


def test_letta_health_alone_does_not_prove_the_absence_of_auth():
    """
    check_password.py exempte /v1/health/ du mot de passe même en mode
    --secure : un 200 dessus ne dit donc jamais si le reste de l'API est
    gardé. Une instance sécurisée répond 200 sur la sonde et 401 sur
    /v1/agents/, et le template doit rester silencieux dans ce cas.
    """
    assert not letta_fires(agents_status=401,
                            agents_body='{"detail":"Unauthorized"}'), (
        "le template conclut sur la seule sonde /v1/health/, qui répond "
        "200 que le serveur soit sécurisé ou non"
    )


def test_letta_extractor_stays_on_the_agent_list_response():
    block = letta_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "un second extracteur ferait remonter deux fois la même instance "
        "sous req-condition, qui évalue chaque extracteur contre les deux "
        "réponses"
    )

    extractor = extractors[0]
    assert extractor.get("part") == "body_2", (
        "l'extracteur doit être borné à la réponse de /v1/agents/ — la "
        "seconde requête déclarée — puisque c'est la seule à porter des "
        "noms d'agent"
    )
    assert extractor.get("type") == "json", (
        "/v1/agents/ rend un tableau JSON : un extracteur regex n'a pas à "
        "s'en charger"
    )


# --------------------------------------------------------------------------
# Aim rend, sous GET /api/projects/, le schéma ProjectApiOut
# (aim/web/api/projects/pydantic_models.py) : name, path, description,
# telemetry_enabled, warn_index, warn_runs. Le trio telemetry_enabled /
# warn_index / warn_runs n'appartient qu'à ce schéma — name/path/description
# sont un vocabulaire trop banal pour signer le produit seuls.

AIM_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "aim-tracking-server-exposed.yaml")

# Réponse de GET /api/projects/ telle que project_api() la rend
# (aim/web/api/projects/views.py) sur un dépôt .aim sain.
AIM_PROJECTS_BODY = (
    '{"name":"My awesome project","path":"/home/ubuntu/experiments",'
    '"description":"","telemetry_enabled":0,"warn_index":false,'
    '"warn_runs":false}'
)

# Même route quand l'index ou des runs sont corrompus : warn_index/warn_runs
# passent à true, le reste du schéma ne bouge pas.
AIM_PROJECTS_BODY_CORRUPTED = (
    '{"name":"My awesome project","path":"/srv/aim-repo",'
    '"description":"team tracking","telemetry_enabled":0,'
    '"warn_index":true,"warn_runs":true}'
)

# Une passerelle maison qui nomme aussi ses ressources name/path/description
# sans être Aim : ce triplet seul, sans telemetry_enabled/warn_index/warn_runs,
# ne doit pas suffire.
AIM_OTHER_PROJECT_BODY = (
    '{"name":"demo","path":"/data/demo","description":"generic project",'
    '"owner":"alice","version":"2.0.0"}'
)


def test_aim_matcher_holds_across_states_without_becoming_generic():
    doc = load(AIM_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/projects/" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /api/projects/"

    block = blocks[0]
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(word_matcher_hits(m, AIM_PROJECTS_BODY) for m in body_matchers), (
        "le template ne reconnaît pas une réponse /api/projects/ d'Aim"
    )
    assert all(word_matcher_hits(m, AIM_PROJECTS_BODY_CORRUPTED)
               for m in body_matchers), (
        "le template dépend de warn_index/warn_runs à false alors que "
        "project_api() les rend à true sur un dépôt corrompu"
    )
    assert not all(word_matcher_hits(m, AIM_OTHER_PROJECT_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une passerelle qui n'est pas Aim : "
        "name, path et description seuls sont un vocabulaire trop banal "
        "pour signer ProjectApiOut"
    )


def test_aim_extractor_reports_the_leaked_repo_path():
    doc = load(AIM_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/projects/" in (b.get("path") or [])]
    extractors = blocks[0].get("extractors") or []
    assert extractors, "aucun extracteur : la fuite de chemin n'est pas remontée"

    paths = [e for e in extractors if e.get("json") == [".path"]]
    assert paths, (
        "aucun extracteur ne lit .path — c'est le chemin absolu du dépôt "
        ".aim sur le système de fichiers du serveur, la fuite que le "
        "roadmap vise au-delà du seul constat produit"
    )
    assert all(e.get("type") == "json" for e in extractors), (
        "/api/projects/ rend un objet JSON : un extracteur regex n'a pas à "
        "s'en charger"
    )


# --------------------------------------------------------------------------
# Phoenix sert /arize_phoenix_version depuis le router nu de app.py, hors du
# préfixe /v1 et sans dépendance : la route répond pareil que
# PHOENIX_ENABLE_AUTH soit posé ou non, elle nomme donc le produit sans rien
# dire de l'autorisation. C'est GET /v1/projects qui porte le constat —
# create_v1_router() n'y accroche Depends(is_authenticated) que si
# authentication_enabled, et is_authenticated répond 401 sitôt le drapeau posé.

PHOENIX_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "arize-phoenix-exposed.yaml")

# Corps de GET /arize_phoenix_version : version() rend
# PlainTextResponse(f"{phoenix_version}"), donc la version seule, sans
# enveloppe. Le serveur ASGI la sert telle quelle, avec un saut de ligne ou non.
PHOENIX_VERSION_BODY = "20.2.0"

# Le catch-all du SPA rend l'index React sur un chemin inconnu : c'est ce
# qu'un hôte qui n'est pas Phoenix — ou un proxy qui avale la route — renvoie
# sous ce même chemin, avec un 200.
PHOENIX_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Phoenix</title>'
    '<script type="module" src="/index.js"></script></head><body></body></html>'
)


def phoenix_projects_body(*projects):
    """
    Réponse de GET /v1/projects telle que get_projects() la sérialise :
    GetProjectsResponseBody, un PaginatedResponseBody[Project] dont les champs
    déclarés sont data puis next_cursor (routers/v1/utils.py). Chaque Project
    vient de _to_project_response() : id (GlobalID relay), name, description —
    l'ordre pydantic met les champs hérités de ProjectData en premier.
    """
    return json.dumps({"data": list(projects), "next_cursor": None},
                      separators=(",", ":"))


PHOENIX_PROJECTS_BODY = phoenix_projects_body(
    # Le projet que la migration initiale insère sur toute instance :
    # {"name": "default", "description": "Default project"}.
    {"name": "default", "description": "Default project", "id": "UHJvamVjdDox"},
    {"name": "support-copilot", "description": None, "id": "UHJvamVjdDoy"},
)

# Instance dont la liste serait vide : l'enveloppe reste, les champs de
# ProjectData disparaissent.
PHOENIX_EMPTY_PROJECTS_BODY = '{"data":[],"next_cursor":null}'


def phoenix_block():
    doc = load(PHOENIX_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v1/projects" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /v1/projects"
    return blocks[0]


def phoenix_responses(version_status=200, version_body=PHOENIX_VERSION_BODY,
                      projects_status=200, projects_body=PHOENIX_PROJECTS_BODY):
    """
    Range les réponses dans l'ordre des chemins déclarés par le template :
    c'est cet ordre qui donne son numéro à chaque body_N sous req-condition.
    """
    ordered = []
    for path in phoenix_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        if route == "/arize_phoenix_version":
            ordered.append((version_status, version_body))
        elif route == "/v1/projects":
            ordered.append((projects_status, projects_body))
        else:
            raise AssertionError(f"le template interroge un chemin inattendu : {route}")
    return ordered


def phoenix_fires(**kwargs):
    block = phoenix_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = phoenix_responses(**kwargs)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_phoenix_reads_version_then_projects_and_touches_nothing_else():
    doc = load(PHOENIX_TEMPLATE)
    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "la liste des projets se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/spans", "POST /v1/spans injecterait des traces dans un "
                           "projet et DELETE /v1/spans/{span_identifier} en "
                           "effacerait"),
                ("/v1/projects/", "DELETE /v1/projects/{project_identifier} "
                                  "supprimerait tout projet autre que "
                                  "\"default\""),
            ):
                assert forbidden not in path, f"{path} : {why}"

    assert phoenix_block().get("req-condition") is True, (
        "sans req-condition, /arize_phoenix_version conclurait seul — or la "
        "route est déclarée hors du préfixe /v1 sur un router sans "
        "dépendance, donc elle répond 200 que PHOENIX_ENABLE_AUTH soit posé "
        "ou non"
    )


def test_phoenix_matcher_needs_a_real_project_not_just_a_reachable_route():
    assert phoenix_fires(), (
        "le template ne reconnaît pas une instance Phoenix ouverte qui rend "
        "ses projets"
    )
    for version in ("4.0.0", "11.28.3", "20.2.0", "20.3.0.dev0"):
        assert phoenix_fires(version_body=version), (
            f"le template dépend d'une version précise alors que "
            f"version() rend {version} en texte brut sur cette route"
        )
    assert phoenix_fires(version_body=PHOENIX_VERSION_BODY + "\n"), (
        "le corps est détouré avant l'ancrage : un saut de ligne final ne "
        "doit pas faire manquer la sonde"
    )
    assert not phoenix_fires(projects_body=PHOENIX_EMPTY_PROJECTS_BODY), (
        "une liste vide ne porte ni name ni description : l'enveloppe "
        "data/next_cursor seule est un vocabulaire trop banal pour signer "
        "le produit"
    )
    assert not phoenix_fires(version_body=PHOENIX_SPA_BODY), (
        "le template déclenche sur l'index du SPA que le catch-all rend sur "
        "un chemin inconnu : le corps de /arize_phoenix_version est la "
        "version seule, un jeton sans espace"
    )
    assert not phoenix_fires(version_body='{"version":"20.2.0"}'), (
        "le template accepte une enveloppe JSON alors que version() rend une "
        "PlainTextResponse : n'importe quelle API qui nomme sa version "
        "passerait la sonde"
    )


def test_phoenix_version_alone_does_not_prove_the_absence_of_auth():
    """
    /arize_phoenix_version est déclarée sur le router nu de app.py, inclus
    inconditionnellement : elle répond 200 même une fois PHOENIX_ENABLE_AUTH
    posé. Une instance authentifiée rend donc la version puis un 401 sur
    /v1/projects, et le template doit rester silencieux dans ce cas.
    """
    assert not phoenix_fires(projects_status=401,
                             projects_body='{"detail":"Unauthorized"}'), (
        "le template conclut sur la seule sonde de version, qui répond 200 "
        "que l'authentification soit active ou non"
    )
    assert not phoenix_fires(projects_status=403,
                             projects_body='{"detail":"The Phoenix REST API '
                                           'is disabled in read-only mode."}'), (
        "prevent_access_in_read_only_mode refuse tout le préfixe /v1 par un "
        "403 : rien n'y est exposé, le template n'a pas à le signaler"
    )


def test_phoenix_extractor_stays_on_the_project_list_response():
    block = phoenix_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "un second extracteur ferait remonter deux fois la même instance "
        "sous req-condition, qui évalue chaque extracteur contre les deux "
        "réponses"
    )

    extractor = extractors[0]
    assert extractor.get("part") == "body_2", (
        "l'extracteur doit être borné à la réponse de /v1/projects — la "
        "seconde requête déclarée — puisque c'est la seule à porter des noms "
        "de projet ; /arize_phoenix_version ne rend que du texte brut"
    )
    assert extractor.get("type") == "json", (
        "/v1/projects rend un objet JSON : un extracteur regex n'a pas à "
        "s'en charger"
    )
    assert extractor.get("json") == [".data[].name"], (
        "les noms de projet sont sous data[] : ils nomment les applications "
        "instrumentées et servent tels quels de project_identifier pour "
        "atteindre les spans"
    )


# --------------------------------------------------------------------------
# Même piège que chez Open WebUI, et le code de LibreChat le documente lui-même :
# index.js monte /api/config derrière optionalJwtAuth et non requireJwtAuth, et
# le commentaire de buildPreLoginPayload() prévient que « Any field added here is
# readable by anonymous callers of GET /api/config ». Reconnaître le produit,
# c'est donc reconnaître une instance correctement fermée aussi bien qu'une
# instance ouverte : le constat tient à la valeur de registrationEnabled seule.
# La signature produit doit par ailleurs traverser les versions — la charge utile
# a gagné appleLoginEnabled et samlLoginEnabled, perdu checkBalance et
# instanceProjectId depuis la 0.7.5 — et les configurations, JSON.stringify
# effaçant toute clé qui vaut directement une variable d'environnement non posée.

LIBRECHAT_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                  "librechat-open-registration.yaml")

# Instance récente, ALLOW_REGISTRATION laissé à la valeur que porte le .env.example
# que la documentation fait recopier. Ni OpenID, ni SAML, ni turnstile configurés :
# openidImageUrl, samlLabel, samlImageUrl et turnstile valent undefined et
# JSON.stringify les efface.
LIBRECHAT_CONFIG_REGISTRATION_OPEN_BODY = (
    '{"appTitle":"LibreChat","discordLoginEnabled":false,'
    '"facebookLoginEnabled":false,"githubLoginEnabled":false,'
    '"googleLoginEnabled":true,"appleLoginEnabled":false,'
    '"openidLoginEnabled":false,"openidLabel":"Continue with OpenID",'
    '"openidAutoRedirect":false,"samlLoginEnabled":false,'
    '"serverDomain":"https://chat.interne.lan","emailLoginEnabled":true,'
    '"registrationEnabled":true,"socialLoginEnabled":false,'
    '"emailEnabled":false,"passwordResetEnabled":false,"ldap":{"enabled":false},'
    '"socialLogins":["google","facebook","openid","github","discord","saml"]}'
)

# Même route sur une 0.7.5, avant que buildPreLoginPayload() n'isole les champs
# pré-connexion : ni appleLoginEnabled, ni samlLoginEnabled, ni ldap, mais
# checkBalance et instanceProjectId, qui ont depuis quitté la charge utile
# anonyme. Le template doit toujours la reconnaître — ce sont ces instances-là
# qui traînent exposées.
LIBRECHAT_OLD_CONFIG_REGISTRATION_OPEN_BODY = (
    '{"appTitle":"LibreChat",'
    '"socialLogins":["google","facebook","openid","github","discord"],'
    '"discordLoginEnabled":false,"facebookLoginEnabled":false,'
    '"githubLoginEnabled":false,"googleLoginEnabled":false,'
    '"openidLoginEnabled":false,"openidLabel":"Continue with OpenID",'
    '"serverDomain":"http://localhost:3080","emailLoginEnabled":true,'
    '"registrationEnabled":true,"socialLoginEnabled":false,'
    '"emailEnabled":false,"passwordResetEnabled":false,"checkBalance":false,'
    '"showBirthdayIcon":false,"helpAndFaqURL":"https://librechat.ai",'
    '"sharedLinksEnabled":true,"publicSharedLinksEnabled":false,'
    '"instanceProjectId":"6672b7d0e1e0a2c3d4e5f601"}'
)

# Instance à laquelle l'exploitant a tout branché : OpenID avec son image, SAML
# avec son libellé, turnstile, une longueur de mot de passe imposée. Les clés
# conditionnelles apparaissent, la signature ne doit pas s'en trouver changée.
LIBRECHAT_FULLY_CONFIGURED_OPEN_BODY = (
    '{"appTitle":"Assistant interne","discordLoginEnabled":true,'
    '"facebookLoginEnabled":false,"githubLoginEnabled":true,'
    '"googleLoginEnabled":true,"appleLoginEnabled":true,'
    '"openidLoginEnabled":true,"openidLabel":"Connexion SSO",'
    '"openidImageUrl":"https://sso.interne.lan/logo.png",'
    '"openidAutoRedirect":false,"samlLoginEnabled":false,'
    '"samlLabel":"SAML","samlImageUrl":"https://sso.interne.lan/saml.png",'
    '"serverDomain":"https://chat.interne.lan","emailLoginEnabled":true,'
    '"registrationEnabled":true,"socialLoginEnabled":true,'
    '"emailEnabled":true,"passwordResetEnabled":true,"minPasswordLength":12,'
    '"ldap":{"enabled":false},'
    '"socialLogins":["google","github","discord"],'
    '"turnstile":{"siteKey":"0x4AAAAAAA"}}'
)

# Même produit, même route, inscription fermée comme il se doit. Le template ne
# doit pas déclencher : sinon il remonte toute instance LibreChat vivante.
LIBRECHAT_CONFIG_REGISTRATION_CLOSED_BODY = (
    LIBRECHAT_CONFIG_REGISTRATION_OPEN_BODY
    .replace('"registrationEnabled":true', '"registrationEnabled":false')
)

# La frontière que le template tient plutôt qu'il ne la masque : registrationEnabled
# vaut « !ldap?.enabled && isEnabled(ALLOW_REGISTRATION) », donc il passe à false
# dès que LDAP est configuré — alors que validateRegistration, seul contrôle de
# POST /api/auth/register, ne lit qu'ALLOW_REGISTRATION. Le template ne rapporte
# que ce que la réponse établit, et cette réponse-là n'établit rien.
LIBRECHAT_LDAP_CONFIG_BODY = (
    LIBRECHAT_CONFIG_REGISTRATION_CLOSED_BODY
    .replace('"ldap":{"enabled":false}', '"ldap":{"enabled":true,"username":true}')
)

# Le serveur sérialise compact, mais un intermédiaire peut reformater le corps
# qu'il relaie. La même instance ouverte, réindentée : le template doit encore la
# reconnaître.
LIBRECHAT_REFORMATTED_REGISTRATION_OPEN_BODY = json.dumps(
    json.loads(LIBRECHAT_CONFIG_REGISTRATION_OPEN_BODY), indent=2,
)

# Une application quelconque publie elle aussi son état d'inscription sous
# /api/config : « registrationEnabled » ne désigne aucun produit.
LIBRECHAT_OTHER_APP_CONFIG_BODY = (
    '{"appTitle":"portail interne","version":"3.4.1",'
    '"registrationEnabled":true,"emailLoginEnabled":true,'
    '"passwordResetEnabled":false}'
)


def librechat_config_block():
    doc = load(LIBRECHAT_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/config" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /api/config"
    return blocks[0]


def test_librechat_probe_never_creates_an_account():
    doc = load(LIBRECHAT_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'état de l'inscription se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            assert "/register" not in path, (
                "le template appelle POST /api/auth/register : il créerait le "
                "compte qu'il est censé signaler, et sur une instance dont la "
                "base est vide registerUser() accorderait ADMIN à ce compte — "
                "le scanner prendrait la main sur ce qu'il audite"
            )


def test_librechat_matcher_proves_registration_is_open_not_merely_that_it_is_librechat():
    block = librechat_config_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "suffirait à faire remonter une instance correctement fermée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"

    assert all(body_matcher_hits(m, LIBRECHAT_CONFIG_REGISTRATION_OPEN_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une réponse /api/config de LibreChat dont "
        "l'inscription est ouverte"
    )
    assert all(body_matcher_hits(m, LIBRECHAT_OLD_CONFIG_REGISTRATION_OPEN_BODY)
               for m in body_matchers), (
        "le template exige des clés absentes de la charge utile de la 0.7.5 — "
        "appleLoginEnabled, samlLoginEnabled ou ldap — il raterait les "
        "instances qui traînent exposées"
    )
    assert all(body_matcher_hits(m, LIBRECHAT_FULLY_CONFIGURED_OPEN_BODY)
               for m in body_matchers), (
        "le template rate une instance dont les fournisseurs sont tous câblés : "
        "les clés conditionnelles ne changent pas ce que la signature exige"
    )
    assert all(body_matcher_hits(m, LIBRECHAT_REFORMATTED_REGISTRATION_OPEN_BODY)
               for m in body_matchers), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    assert not all(body_matcher_hits(m, LIBRECHAT_CONFIG_REGISTRATION_CLOSED_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une instance dont l'inscription est fermée : "
        "/api/config est servi à l'anonyme par dessein, reconnaître LibreChat ne "
        "prouve rien"
    )
    assert not all(body_matcher_hits(m, LIBRECHAT_LDAP_CONFIG_BODY)
                   for m in body_matchers), (
        "le template conclut sur une instance LDAP, dont registrationEnabled "
        "vaut false : la réponse n'établit pas que POST /api/auth/register "
        "accepterait, et le constat ne porte que sur ce qu'elle établit"
    )
    assert not all(body_matcher_hits(m, LIBRECHAT_OTHER_APP_CONFIG_BODY)
                   for m in body_matchers), (
        "le template déclenche sur une application quelconque servant "
        "/api/config : registrationEnabled et emailLoginEnabled sont des clés "
        "banales"
    )


def test_librechat_extractors_report_what_the_anonymous_payload_gives_away():
    extractors = librechat_config_block().get("extractors") or []
    assert extractors, "aucun extracteur : la réponse n'est pas exploitée"
    assert all(e.get("type") == "json" for e in extractors), (
        "/api/config rend un objet JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )

    paths = {p for e in extractors for p in (e.get("json") or [])}
    assert ".emailEnabled" in paths, (
        "aucun extracteur ne lit .emailEnabled — c'est checkEmailConfig() tel "
        "que la réponse le publie, et à false registerUser() pose emailVerified "
        "à true : il n'y a rien entre le formulaire et la session"
    )
    assert ".appTitle" in paths, (
        "aucun extracteur ne lit .appTitle — APP_TITLE nomme l'instance, et "
        "c'est le renseignement qu'un exploitant veut lire à côté du constat"
    )


# --------------------------------------------------------------------------
# Prefect a changé la forme de sa réponse sans changer la route : un serveur 3.x
# rend l'objet Settings imbriqué, dont les clés sont les champs du modèle, là où
# un 2.x rend un dictionnaire plat de cent soixante clés PREFECT_*. Les deux
# lignes traînent exposées, et un template qui n'aurait vu que la seconde raterait
# tout le parc récent — ou l'inverse. Ces corps sont ceux que deux serveurs
# réellement lancés ont rendus, réduits aux sections que le template regarde et
# aux valeurs qu'un déploiement conteneurisé porte.
#
# L'autre moitié du travail est la frontière : chez Prefect, à la différence de
# Phoenix, la sonde de version tombe sous la même garde que le constat. Une
# instance dont PREFECT_SERVER_API_AUTH_STRING est posé répond 401 sur les deux
# routes, donc le template doit se taire — reconnaître le produit n'est pas le
# constat, et une instance correctement fermée ne se reconnaît même pas.

PREFECT_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "prefect-server-admin-exposed.yaml")

# read_version() est annotée « -> str » : FastAPI rend la version en chaîne JSON,
# donc le corps entier est le numéro entre guillemets.
PREFECT_VERSION_BODY = '"3.8.3"'
PREFECT_V2_VERSION_BODY = '"2.20.16"'

# Serveur 3.x en conteneur derrière un proxy, base PostgreSQL configurée par
# parties plutôt que par URL — le cas où l'obfuscation ne protège plus rien :
# connection_url et password sont masqués, driver, host, port, user et name ne le
# sont pas. server.api.host à 0.0.0.0 est la condition même de l'exposition, et
# server.api.auth_string à null la confirme dans la réponse.
PREFECT_SETTINGS_BODY = (
    '{"home":"/root/.prefect","profiles_path":"/root/.prefect/profiles.toml",'
    '"debug_mode":false,'
    '"api":{"url":"https://prefect.interne.lan/api","auth_string":null,'
    '"key":null,"tls_insecure_skip_verify":false,"ssl_cert_file":null,'
    '"enable_http2":false,"request_timeout":60.0},'
    '"ui_url":null,"silence_api_url_misconfiguration":false,'
    '"server":{"logging_level":"WARNING","analytics_enabled":true,'
    '"register_blocks_on_start":true,"memoize_block_auto_registration":true,'
    '"memo_store_path":"/root/.prefect/memo_store.toml",'
    '"api":{"auth_string":null,"host":"0.0.0.0","port":4200,"base_path":null,'
    '"default_limit":200,"keepalive_timeout":5,'
    '"csrf_protection_enabled":false,"csrf_token_expiration":"PT1H",'
    '"cors_allowed_origins":"*","cors_allowed_methods":"*",'
    '"cors_allowed_headers":"*","websocket_ping_interval":20.0,'
    '"websocket_ping_timeout":20.0,"max_parameter_size":524288},'
    '"database":{"connection_url":"**********",'
    '"driver":"postgresql+asyncpg","host":"prefect-db.interne.lan",'
    '"port":5432,"user":"prefect","name":"prefect","password":"**********",'
    '"echo":false,"migrate_on_start":true,"timeout":10.0,'
    '"connection_timeout":5.0,"migration_timeout":null},'
    '"ui":{"enabled":true,"v2_enabled":true,'
    '"api_url":"https://prefect.interne.lan/api","serve_base":"/",'
    '"static_directory":null,"show_promotional_content":true}}}'
)

# Même route sur un 2.x, avant que la 3.0 ne restructure les réglages en modèles
# imbriqués : un dictionnaire plat, dont les clés portent le préfixe PREFECT_.
# Cette ligne n'a aucun réglage d'authentification à publier — elle n'en a pas —
# et sa configuration de base tient dans une seule URL, obfusquée.
PREFECT_V2_SETTINGS_BODY = (
    '{"PREFECT_HOME":"/root/.prefect","PREFECT_DEBUG_MODE":false,'
    '"PREFECT_PROFILES_PATH":"${PREFECT_HOME}/profiles.toml",'
    '"PREFECT_API_URL":null,"PREFECT_API_KEY":"********",'
    '"PREFECT_API_DATABASE_CONNECTION_URL":"********",'
    '"PREFECT_API_DATABASE_PASSWORD":"********",'
    '"PREFECT_API_BLOCKS_REGISTER_ON_START":true,'
    '"PREFECT_MEMOIZE_BLOCK_AUTO_REGISTRATION":true,'
    '"PREFECT_MEMO_STORE_PATH":"${PREFECT_HOME}/memo_store.toml",'
    '"PREFECT_SERVER_API_HOST":"0.0.0.0","PREFECT_SERVER_API_PORT":4200,'
    '"PREFECT_UI_API_URL":null,"PREFECT_LOGGING_LEVEL":"INFO"}'
)

# Le serveur sérialise compact, mais un intermédiaire peut reformater le corps
# qu'il relaie : le deux-points se retrouve alors séparé de la clé par un espace.
PREFECT_REFORMATTED_SETTINGS_BODY = json.dumps(
    json.loads(PREFECT_SETTINGS_BODY), indent=2,
)

# Ce que rend une instance dont PREFECT_SERVER_API_AUTH_STRING est posé :
# token_validation intercepte avant le routage, n'exempte que GET /health et GET
# /ready, et rend ce corps en 401 sur les deux routes du routeur /admin.
PREFECT_UNAUTHORIZED_BODY = '{"exception_message":"Unauthorized"}'

# Le catch-all du SPA : sur un chemin qu'il ne sert pas, le serveur rend l'index
# de l'interface en 200 plutôt qu'un 404.
PREFECT_SPA_BODY = (
    '<!DOCTYPE html><html lang="en"><head><title>Prefect Server</title>'
    '</head><body><div id="app"></div></body></html>'
)

# Ce qui justifie d'exiger deux noms plutôt qu'un. Les champs que Settings porte
# à sa racine sont génériques — "home", "profiles_path" et "debug_mode" ne sont
# pas des mots de Prefect —, et un outil de la même famille les publie à
# l'identique : dbt tient sa configuration dans un profiles.yml et nomme lui
# aussi son répertoire. Seul "memoize_block_auto_registration", qui désigne la
# mémoïsation de l'enregistrement automatique des blocs, appartient à Prefect et
# à lui seul.
PREFECT_OTHER_TOOL_WITH_PROFILES_PATH_BODY = (
    '{"home":"/opt/dbt","profiles_path":"/opt/dbt/profiles.yml",'
    '"debug_mode":false,"target":"prod","threads":8,'
    '"logging_level":"INFO","partial_parse":true}'
)

# Une application quelconque expose elle aussi une console d'administration sous
# /api/admin : le chemin ne désigne aucun produit, et la version qu'elle rend a
# la même forme.
PREFECT_OTHER_ADMIN_BODY = (
    '{"instance_name":"portail interne","debug_mode":false,'
    '"registration_enabled":true,"database":{"host":"db.interne.lan",'
    '"port":5432,"user":"portail"},"logging_level":"INFO"}'
)

# Les deux pièges que le deux-points écarte, et qui séparent « publier un
# réglage » de « nommer un réglage ». En prose d'abord : un service qui
# documente les variables d'environnement de Prefect les cite dans une valeur de
# chaîne. Puis, plus près du template, un catalogue de configuration qui les
# porte en éléments de tableau — là les noms sont bien entre guillemets, et seul
# le deux-points qui suit distingue une clé d'une valeur.
PREFECT_MENTIONS_THE_NAMES_IN_A_STRING_BODY = (
    '{"doc":"poser PREFECT_PROFILES_PATH et '
    'PREFECT_MEMOIZE_BLOCK_AUTO_REGISTRATION avant de lancer le serveur",'
    '"service":"catalogue"}'
)
PREFECT_LISTS_THE_NAMES_AS_VALUES_BODY = (
    '{"service":"catalogue de configuration","scope":"orchestration",'
    '"documented_settings":["PREFECT_PROFILES_PATH",'
    '"PREFECT_MEMOIZE_BLOCK_AUTO_REGISTRATION","PREFECT_API_URL"]}'
)


def prefect_block():
    doc = load(PREFECT_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/admin/settings" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /api/admin/settings"
    return blocks[0]


def prefect_responses(settings_status=200, settings_body=PREFECT_SETTINGS_BODY,
                      version_status=200, version_body=PREFECT_VERSION_BODY):
    """
    Range les réponses dans l'ordre des chemins déclarés par le template : c'est
    cet ordre qui donne son numéro à chaque body_N sous req-condition.
    """
    ordered = []
    for path in prefect_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        if route == "/api/admin/settings":
            ordered.append((settings_status, settings_body))
        elif route == "/api/admin/version":
            ordered.append((version_status, version_body))
        else:
            raise AssertionError(f"le template interroge un chemin inattendu : {route}")
    return ordered


def prefect_fires(**kwargs):
    block = prefect_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = prefect_responses(**kwargs)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_prefect_reads_the_admin_router_and_never_writes_to_it():
    doc = load(PREFECT_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "la configuration se lit en GET : le template ne doit rien envoyer "
            "à une instance qu'il découvre, alors que le routeur qu'il "
            "interroge porte des écritures juste à côté"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/admin/database", "le template appelle POST "
                                    "/admin/database/drop ou /clear : sur un "
                                    "serveur resté en 2.x, un confirm=True dans "
                                    "le corps détruit ou vide la base de "
                                    "l'ordonnanceur — le template effacerait "
                                    "l'historique d'exécution qu'il est censé "
                                    "protéger"),
                ("/admin/storage", "le template touche à PUT ou DELETE "
                                   "/api/admin/storage : il remplacerait ou "
                                   "effacerait le bloc de stockage de résultats "
                                   "par défaut du serveur, donc l'endroit où "
                                   "toutes les exécutions écrivent"),
                ("create_flow_run", "le template appelle "
                                    "/api/deployments/{id}/create_flow_run : "
                                    "le premier worker qui interroge la file "
                                    "exécuterait le code du déploiement — le "
                                    "scanner ferait tourner du code sur ce "
                                    "qu'il audite"),
            ):
                assert forbidden not in path, why


def test_prefect_matcher_proves_the_admin_router_answers_anonymously():
    block = prefect_block()

    assert block.get("req-condition") is True, (
        "sans req-condition les deux réponses ne partagent pas d'espace de "
        "noms : chaque sonde conclurait seule, et /settings sans la version "
        "tiendrait à deux noms de réglages"
    )

    # Les deux 200 sont vérifiés ici sur la forme, et non par un corps de plus.
    # C'est délibéré : les ancrages de corps rejettent déjà tout ce qu'une
    # instance réelle rend en erreur — le 401 de token_validation vaut
    # {"exception_message":"Unauthorized"}, un 404 rend l'index du SPA — donc
    # aucun scénario plausible ne sépare la condition de statut de ces
    # ancrages, et un corps inventé pour y arriver ne prouverait rien qu'une
    # instance ferait. Reste que le constat est que les deux routes ont
    # *répondu* à l'anonyme : cela doit être écrit dans le matcher, pas déduit
    # de la forme d'un corps.
    dsl_exprs = [expr for m in (block.get("matchers") or [])
                 if m.get("type") == "dsl" for expr in (m.get("dsl") or [])]
    for index, route in ((1, "/api/admin/settings"), (2, "/api/admin/version")):
        assert any(f"status_code_{index} == 200" in expr for expr in dsl_exprs), (
            f"aucune expression n'exige status_code_{index} == 200 : le "
            f"template ne dit pas que {route} a répondu à l'anonyme, alors que "
            "c'est tout le constat — la configuration lue n'est un défaut que "
            "parce que le serveur l'a rendue sans rien demander"
        )

    assert prefect_fires(), (
        "le template ne reconnaît pas un serveur Prefect 3.x dont le routeur "
        "/admin répond sans authentification"
    )
    assert prefect_fires(settings_body=PREFECT_V2_SETTINGS_BODY,
                         version_body=PREFECT_V2_VERSION_BODY), (
        "le template rate un serveur 2.x : sa réponse est un dictionnaire plat "
        "de clés PREFECT_*, pas l'objet imbriqué de la 3.0, et c'est cette "
        "ligne-là qui traîne exposée sans même avoir de réglage "
        "d'authentification à poser"
    )
    assert prefect_fires(settings_body=PREFECT_REFORMATTED_SETTINGS_BODY), (
        "le template dépend de la sérialisation compacte du serveur : un "
        "intermédiaire qui reformate le corps le mettrait en défaut"
    )

    # La frontière du constat : l'authentification posée, les deux routes
    # tombent, et le template n'a plus rien à dire.
    assert not prefect_fires(settings_status=401,
                             settings_body=PREFECT_UNAUTHORIZED_BODY,
                             version_status=401,
                             version_body=PREFECT_UNAUTHORIZED_BODY), (
        "le template déclenche sur une instance dont "
        "PREFECT_SERVER_API_AUTH_STRING est posé : token_validation rend 401 "
        "sur les deux routes du routeur /admin, et le constat porte sur le 200 "
        "anonyme, pas sur la reconnaissance du produit"
    )
    assert not prefect_fires(settings_status=403,
                             settings_body="Forbidden"), (
        "le template conclut alors qu'un proxy filtre /api/admin/settings : la "
        "seule route qui porte la configuration n'a rien rendu"
    )
    assert not prefect_fires(version_status=401,
                             version_body=PREFECT_UNAUTHORIZED_BODY), (
        "le template conclut sur la seule réponse de /settings, sans que la "
        "seconde route du même routeur ait corroboré"
    )

    assert not prefect_fires(settings_body=PREFECT_OTHER_ADMIN_BODY,
                             version_body='"1.4.2"'), (
        "le template déclenche sur une application quelconque servant une "
        "console sous /api/admin : le chemin ne désigne aucun produit"
    )
    assert not prefect_fires(
        settings_body=PREFECT_OTHER_TOOL_WITH_PROFILES_PATH_BODY,
        version_body='"1.10.6"'), (
        "le template tient à « profiles_path » seul, un nom que Prefect ne "
        "possède pas : un outil qui range sa configuration dans un fichier de "
        "profils publie les mêmes champs de racine — home, profiles_path, "
        "debug_mode — et suffirait à le faire conclure. Le second nom exigé "
        "doit être un mot du produit"
    )
    assert not prefect_fires(
        settings_body=PREFECT_MENTIONS_THE_NAMES_IN_A_STRING_BODY), (
        "le template se contente de trouver les noms de réglages n'importe où "
        "dans le corps : il déclencherait sur un service qui documente les "
        "variables d'environnement de Prefect au lieu d'en publier"
    )
    assert not prefect_fires(
        settings_body=PREFECT_LISTS_THE_NAMES_AS_VALUES_BODY), (
        "le template accepte les noms de réglages en valeurs : un catalogue de "
        "configuration qui les liste entre guillemets suffirait à le faire "
        "conclure, alors que le constat est qu'une instance publie ces "
        "réglages — donc que les noms sont des clés, deux-points compris"
    )
    assert not prefect_fires(version_body=PREFECT_SPA_BODY), (
        "le template accepte l'index du SPA en guise de version : le "
        "catch-all rend cette page en 200 sur tout chemin qu'il ne sert pas"
    )
    assert not prefect_fires(version_body='{"version":"3.8.3"}'), (
        "le template accepte une version sous enveloppe JSON : read_version() "
        "est annotée « -> str » et rend le numéro nu entre guillemets, donc "
        "une enveloppe désigne un autre produit"
    )


def test_prefect_extractor_reports_the_database_left_in_clear():
    extractors = prefect_block().get("extractors") or []
    assert len(extractors) == 1, (
        "un seul extracteur, sinon la même instance remonte autant de fois "
        "sous req-condition, qui évalue chaque extracteur contre les deux "
        "réponses"
    )

    extractor = extractors[0]
    assert extractor.get("part") == "body_1", (
        "l'extracteur doit être borné à la réponse de /api/admin/settings — la "
        "première requête déclarée — puisque c'est la seule à porter la "
        "configuration ; /api/admin/version ne rend que le numéro"
    )
    assert extractor.get("type") == "json", (
        "/api/admin/settings rend un objet JSON : un extracteur regex n'a pas "
        "à s'en charger"
    )

    paths = extractor.get("json") or []
    for field in ("host", "user", "name", "port", "driver"):
        assert any(p.startswith(f".server.database.{field}") for p in paths), (
            f"aucun chemin ne lit .server.database.{field} — connection_url et "
            "password sont les seuls champs obfusqués de la section, donc "
            "l'exploitant qui configure sa base par parties publie tout ce qui "
            "la désigne, et c'est le renseignement à lire à côté du constat"
        )
    assert all(p.endswith(" // empty") for p in paths), (
        "sans « // empty », ces chemins rendent null sur un serveur 2.x — dont "
        "la réponse est plate et n'a pas de .server — et le moteur remonterait "
        "des chaînes vides à côté du constat"
    )


# --------------------------------------------------------------------------
# Chez TorchServe le constat ne tient pas au corps seul : il tient aussi à la
# question posée. ApiUtils.getModelList() ne pose nextPageToken que dans la
# branche « else » de « if (pageToken + limit > keys.size()) », donc au limit par
# défaut de cent une instance qui sert trois modèles rend {"models":[…]} sans
# jeton de pagination. Le template qui interrogerait /models nu ne lirait jamais
# la clé sur laquelle il conclut ; limit=1 est la seule borne qui tienne pour
# toute instance portant au moins un modèle.
#
# L'autre moitié est la frontière. Depuis la 0.11.1, l'autorisation par jeton est
# imposée par défaut : ce template ne signale pas un défaut du produit mais une
# instance dont le jeton a été retiré. Et l'instance qui refuse ne rend pas 401 —
# InvalidKeyException hérite de ModelException, que channelRead0() attrape en
# BAD_REQUEST — donc le refus est un 400 servi en application/json sur la bonne
# route, que seul le statut sépare d'une réponse.

TORCHSERVE_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                   "torchserve-management-api-open.yaml")

# Ce que rend GET /models?limit=1 sur une instance dont le jeton est retiré.
# NettyUtils sérialise par JsonUtils.GSON_PRETTY : indentation de deux espaces,
# deux-points suivi d'une espace. Le jeton vaut String.valueOf(pageToken + limit),
# donc « "1" » après la première page.
TORCHSERVE_MODELS_BODY = (
    '{\n'
    '  "nextPageToken": "1",\n'
    '  "models": [\n'
    '    {\n'
    '      "modelName": "densenet161",\n'
    '      "modelUrl": "densenet161.mar"\n'
    '    }\n'
    '  ]\n'
    '}'
)

# Même route sur une instance dont allowed_urls est resté à la valeur livrée :
# le modèle a été tiré d'une URL, et modelUrl la garde. C'est la ligne que le
# template doit signaler en premier, pas celle qu'il doit rater.
TORCHSERVE_REMOTE_MODEL_BODY = TORCHSERVE_MODELS_BODY.replace(
    '"densenet161.mar"', '"https://modeles.interne.lan/densenet161.mar"',
)

# Le serveur sérialise en pretty-print, mais un intermédiaire peut recompacter le
# corps qu'il relaie : le deux-points se retrouve alors collé à la clé.
TORCHSERVE_COMPACT_MODELS_BODY = json.dumps(
    json.loads(TORCHSERVE_MODELS_BODY), separators=(",", ":"),
)

# Instance vivante et tout aussi ouverte, mais qui ne sert encore aucun modèle :
# last vaut 0, la branche « else » pose quand même nextPageToken, et models reste
# vide. Il n'y a alors rien à nommer — ni modèle servi, ni origine d'archive — et
# le template n'a pas de constat à porter.
TORCHSERVE_EMPTY_INDEX_BODY = (
    '{\n'
    '  "nextPageToken": "0",\n'
    '  "models": []\n'
    '}'
)

# La même instance, interrogée sans borne : au limit par défaut de cent,
# « 100 > 1 » est vrai, last retombe à la taille de l'index et nextPageToken
# n'est jamais posé. C'est la réponse que lirait un template qui viserait /models
# nu — et elle ne porte pas la clé sur laquelle celui-ci conclut.
TORCHSERVE_DEFAULT_LIMIT_BODY = (
    '{\n'
    '  "models": [\n'
    '    {\n'
    '      "modelName": "densenet161",\n'
    '      "modelUrl": "densenet161.mar"\n'
    '    }\n'
    '  ]\n'
    '}'
)

# Ce que rend une instance dont le jeton est en place : checkTokenAuthorization()
# lève InvalidKeyException, sendError() en fait un ErrorResponse, et le statut est
# 400 — pas 401. Même route, même content-type, même forme de corps JSON.
TORCHSERVE_TOKEN_REFUSED_BODY = (
    '{\n'
    '  "code": 400,\n'
    '  "type": "InvalidKeyException",\n'
    '  "message": "Token Authorization failed. Token either incorrect, '
    'expired, or not provided correctly"\n'
    '}'
)

# Une autre passerelle de modèles pagine sous le même nom et nomme ses entrées
# de la même façon, mais son jeton est un curseur opaque là où
# setNextPageToken() reçoit String.valueOf(int) : le rang de la page suivante,
# en chiffres.
TORCHSERVE_OTHER_REGISTRY_BODY = (
    '{\n'
    '  "nextPageToken": "Q2c9PWFiYw",\n'
    '  "models": [\n'
    '    {\n'
    '      "modelName": "resnet50",\n'
    '      "modelUrl": "s3://modeles/resnet50"\n'
    '    }\n'
    '  ]\n'
    '}'
)

# Le piège que le deux-points écarte : un catalogue qui documente les champs de
# l'API de TorchServe les porte entre guillemets, en valeurs. Les noms y sont
# tous, et aucun ne désigne une clé.
TORCHSERVE_CATALOGUE_BODY = (
    '{\n'
    '  "service": "catalogue interne",\n'
    '  "documented_fields": ["nextPageToken", "modelName", "modelUrl"],\n'
    '  "upstream": "torchserve"\n'
    '}'
)


def torchserve_models_block():
    doc = load(TORCHSERVE_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.startswith("{{BaseURL}}/models")
                     for p in (b.get("path") or []))]
    assert blocks, "le template ne vise pas GET /models"
    return blocks[0]


def torchserve_fires(status=200, body=TORCHSERVE_MODELS_BODY,
                     content_type="application/json"):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint.
    """
    block = torchserve_models_block()
    header = "HTTP/1.1 %d\r\nContent-Type: %s\r\n" % (status, content_type)

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        elif matcher.get("part") == "header":
            verdicts.append(body_matcher_hits(matcher, header))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_torchserve_probe_bounds_the_page_and_never_registers_a_model():
    doc = load(TORCHSERVE_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'inventaire se lit en GET : le template ne doit rien envoyer à "
            "une instance qu'il découvre, alors que le routeur qu'il interroge "
            "porte l'enregistrement de modèle juste à côté"
        )
        for path in (block.get("path") or []):
            assert "url=" not in path, (
                "le template appelle POST /models?url= : TorchServe tirerait "
                "l'archive .mar de l'URL demandée et en importerait le handler "
                "Python — le scanner exécuterait du code sur ce qu'il audite, "
                "et c'est exactement la chaîne ShellTorch"
            )
            assert "min_worker" not in path and "set-default" not in path, (
                "le template touche à PUT /models/{nom} : il remettrait à zéro "
                "les workers d'un modèle servi, ou changerait la version par "
                "défaut — arrêter le service qu'on audite n'est pas le signaler"
            )

    paths = torchserve_models_block().get("path") or []
    assert all("limit=1" in path for path in paths), (
        "la sonde n'impose pas limit=1, et sans cette borne il n'y a rien à "
        "reconnaître : getModelList() ne pose nextPageToken que si "
        "pageToken + limit ne dépasse pas le nombre de modèles, donc au limit "
        "par défaut de cent une instance qui en sert moins ne l'émet jamais. "
        "Toute valeur plus haute retombe sur les instances qui servent moins "
        "de modèles qu'elle"
    )


def test_torchserve_matcher_needs_a_served_model_not_a_reachable_route():
    block = torchserve_models_block()

    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon le statut ou la "
        "signature suffirait seul, et le refus par jeton — 400 en "
        "application/json sur la même route — remonterait comme une réponse"
    )

    # Le 200 est exigé ici sur la forme, et non par un corps de plus. C'est
    # délibéré : le refus par jeton ne porte aucune des clés que le corps doit
    # nommer, donc les ancrages l'écartent déjà, et un corps inventé pour
    # séparer la condition de statut de ces ancrages ne prouverait rien qu'une
    # instance ferait. Reste que le constat est que la route a *répondu* à
    # l'anonyme : cela doit être écrit dans le template, pas déduit de la forme
    # d'un corps — la route existe sur toute instance, et c'est le statut qui
    # dit si elle a servi ou refusé.
    assert any(200 in (m.get("status") or [])
               for m in (block.get("matchers") or [])
               if m.get("type") == "status"), (
        "aucun matcher n'exige un 200 : le template ne dit pas que "
        "GET /models?limit=1 a répondu à l'anonyme, alors que c'est tout le "
        "constat — l'inventaire lu n'est un défaut que parce que le serveur "
        "l'a rendu sans jeton"
    )

    assert torchserve_fires(), (
        "le template ne reconnaît pas la réponse que rend GET /models?limit=1 "
        "sur une instance dont l'autorisation par jeton a été retirée"
    )
    assert torchserve_fires(body=TORCHSERVE_REMOTE_MODEL_BODY), (
        "le template rate l'instance dont le modèle a été tiré d'une URL — "
        "allowed_urls y admet donc un domaine tiers, et c'est la ligne la plus "
        "exposée du parc"
    )
    assert torchserve_fires(body=TORCHSERVE_COMPACT_MODELS_BODY), (
        "le template dépend du pretty-print de GSON_PRETTY : un intermédiaire "
        "qui recompacte le corps le mettrait en défaut"
    )

    # La frontière du constat : le jeton en place, la route répond, mais elle
    # refuse — et un 400 n'est pas un 401, donc rien ne le distingue d'une
    # réponse hors du statut et du corps.
    assert not torchserve_fires(status=400,
                                body=TORCHSERVE_TOKEN_REFUSED_BODY), (
        "le template déclenche sur une instance dont l'autorisation par jeton "
        "est en place : TokenAuthorizationHandler rend InvalidKeyException, que "
        "channelRead0() sert en 400 — le constat porte sur la réponse anonyme, "
        "pas sur la reconnaissance du produit"
    )
    assert not torchserve_fires(body=TORCHSERVE_EMPTY_INDEX_BODY), (
        "le template conclut sur un index vide : nextPageToken y est posé — "
        "last vaut 0 — mais aucun modèle n'est nommé, donc la réponse ne dit "
        "ni ce qui est servi ni d'où l'archive vient"
    )
    assert not torchserve_fires(body=TORCHSERVE_DEFAULT_LIMIT_BODY), (
        "le template se passe de nextPageToken et tiendrait aux seules clés de "
        "ModelItem : il conclurait sur ce que rend /models nu, où la clé de "
        "pagination est absente, et perdrait l'enveloppe qui signe "
        "ListModelsResponse"
    )
    assert not torchserve_fires(body=TORCHSERVE_OTHER_REGISTRY_BODY), (
        "le template accepte un curseur de pagination opaque : "
        "setNextPageToken() reçoit String.valueOf(int), donc le jeton de "
        "TorchServe est le rang de la page suivante, écrit en chiffres — une "
        "autre passerelle de modèles pagine sous le même nom"
    )
    assert not torchserve_fires(body=TORCHSERVE_CATALOGUE_BODY), (
        "le template accepte ces noms en valeurs : un catalogue qui documente "
        "les champs de l'API de TorchServe suffirait à le faire conclure, "
        "alors que le constat est qu'une instance les rend comme clés"
    )
    assert not torchserve_fires(content_type="text/html"), (
        "le template se passe du content-type : une page servie en 200 par un "
        "portail captif qui cite ces noms passerait pour un inventaire"
    )


def test_torchserve_extractors_report_the_served_model_and_its_origin():
    extractors = torchserve_models_block().get("extractors") or []
    assert extractors, "aucun extracteur : la réponse n'est pas exploitée"
    assert all(e.get("type") == "json" for e in extractors), (
        "/models rend un objet JSON : un extracteur regex n'a pas à s'en charger"
    )

    paths = {p for e in extractors for p in (e.get("json") or [])}
    assert ".models[].modelName" in paths, (
        "aucun extracteur ne lit le nom du modèle servi — c'est ce que "
        "l'exploitant expose, et le premier renseignement que la réponse donne"
    )
    assert ".models[].modelUrl" in paths, (
        "aucun extracteur ne lit modelUrl — il dit si l'archive vient du model "
        "store ou d'une URL tierce, donc si allowed_urls a laissé passer un "
        "domaine, et c'est la moitié de la chaîne ShellTorch qui se lit sans "
        "rien envoyer"
    )


# --------------------------------------------------------------------------
# Chez Feast la garde existe mais ne garde rien. GET /v1/vector_stores est
# déclarée avec dependencies=[Depends(inject_user_details)], et
# inject_user_details() met tout son travail — extraction du jeton, appel au
# parser, les deux HTTPException(401) — sous « if sm is not None ». Or
# start_server() appelle init_security_manager(), qui pour AuthManagerType.NONE
# exécute no_security_manager() et pose _sm à None ; et le type vaut NONE par
# défaut, RepoConfig écrivant lui-même « self.auth["type"] =
# AuthType.NONE.value » quand feature_store.yaml ne porte pas de section auth.
#
# D'où la difficulté propre à ce template : l'enveloppe que rend la route est
# délibérément compatible OpenAI — {"object": "list", "data": [...]} — et
# plusieurs passerelles LLM servent des magasins vectoriels sous exactement ce
# chemin. C'est la seconde lecture qui nomme Feast : un identifiant que
# feature_view_to_vs_id() ne peut pas avoir émis fait lever
# FeatureViewNotFoundException à vs_registry.resolve(), et get_vector_store()
# l'attrape pour rendre un 404 dont le message renvoie l'identifiant demandé.

FEAST_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                              "feast-vector-stores-exposed.yaml")

# feature_view_to_vs_id(project, feature_view_name) rend « vs_ » suivi des
# vingt-quatre premiers caractères hexadécimaux du sha256 de « projet:nom ».
FEAST_VS_ID = re.compile(r"^vs_[0-9a-f]{24}$")


def feast_vs_id(project, feature_view_name):
    digest = hashlib.sha256(
        f"{project}:{feature_view_name}".encode()).hexdigest()[:24]
    return f"vs_{digest}"


def feast_store_list_body(*names, project="rag_demo"):
    """
    Réponse de GET /v1/vector_stores telle que list_vector_stores() la
    sérialise : JSONResponse({"object": "list", "data": permitted}), chaque
    entrée venant de build_vector_store_object() — id, object, name, status
    (« completed », posé en dur) et created_at. Starlette rend le JSON compact.
    """
    data = [{
        "id": feast_vs_id(project, name),
        "object": "vector_store",
        "name": name,
        "status": "completed",
        "created_at": 1755500000,
    } for name in names]
    return json.dumps({"object": "list", "data": data}, separators=(",", ":"))


FEAST_STORE_LIST_BODY = feast_store_list_body("document_embeddings",
                                              "support_kb_chunks")

# VectorStoreRegistry.refresh() ne retient que les feature views dont un champ
# porte vector_index : un déploiement Feast sans RAG rend l'enveloppe et rien
# dedans. Le constat porte sur la route qui a répondu à l'anonyme, pas sur le
# nombre de magasins, et cette instance est tout aussi ouverte — la même
# dépendance sans effet garde /push et /get-online-features.
FEAST_EMPTY_STORE_LIST_BODY = '{"object":"list","data":[]}'


def feast_not_found_body(vector_store_id):
    """
    Réponse de GET /v1/vector_stores/{id} sur un identifiant inconnu :
    vs_registry.resolve() lève FeatureViewNotFoundException, que le handler
    attrape pour rendre ce 404 — le message renvoie l'identifiant demandé.
    """
    return json.dumps({"error": {
        "message": f"No vector store found with id '{vector_store_id}'",
        "type": "not_found_error",
    }}, separators=(",", ":"))


# Une passerelle LLM qui sert des magasins vectoriels compatibles OpenAI sous
# le même chemin : l'enveloppe est la même, les clés d'une entrée aussi. Rien
# dans cette réponse ne dit Feast.
FEAST_OPENAI_PROXY_LIST_BODY = json.dumps({
    "object": "list",
    "data": [{
        "id": "vs_68ab1f2c9d3e4a5b6c7d8e9f",
        "object": "vector_store",
        "name": "knowledge-base",
        "status": "completed",
        "usage_bytes": 918273,
        "file_counts": {"completed": 12, "total": 12},
        "created_at": 1755500000,
    }],
}, separators=(",", ":"))

# Ce que rend cette même passerelle sur un identifiant inconnu : un 404, sur la
# bonne route, en JSON — mais pas la phrase du handler de Feast.
FEAST_OPENAI_PROXY_NOT_FOUND_BODY = json.dumps({"error": {
    "message": "Vector store not found",
    "type": "invalid_request_error",
}}, separators=(",", ":"))

# Le 404 d'un routeur quelconque, qui renvoie lui aussi le chemin demandé :
# l'identifiant de la sonde s'y retrouve mot pour mot, et lui seul ne prouve
# rien.
FEAST_GENERIC_NOT_FOUND_BODY = (
    "<!doctype html><html><head><title>404</title></head><body>"
    "<pre>Cannot GET /v1/vector_stores/feast-exposure-probe</pre>"
    "</body></html>"
)

# L'index d'une application servie sur le même hôte, que le catch-all d'un
# proxy rend sur un chemin inconnu.
FEAST_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Feature platform</title>'
    '</head><body><div id="root"></div></body></html>'
)

# Ce que rend une instance dont feature_store.yaml porte « auth: type: oidc »
# ou « type: kubernetes » : _sm existe, inject_user_details() lève
# HTTPException(401) avant le handler, et FastAPI sert le détail.
FEAST_UNAUTHORIZED_BODY = '{"detail":"Missing authentication token"}'


def feast_block():
    doc = load(FEAST_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v1/vector_stores" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /v1/vector_stores"
    return blocks[0]


def feast_probe_id():
    """
    L'identifiant que la sonde demande, lu dans le template plutôt que réécrit
    ici : c'est lui que le handler renvoie dans son message, donc la fixture
    doit suivre le chemin déclaré et non l'inverse.
    """
    probes = [p.split("/v1/vector_stores/", 1)[1]
              for p in (feast_block().get("path") or [])
              if "/v1/vector_stores/" in p]
    assert len(probes) == 1, (
        "le template doit interroger exactement une route "
        "/v1/vector_stores/{id} : c'est elle qui nomme le produit, et deux "
        f"sondes en feraient deux constats — {probes}"
    )
    return probes[0]


def feast_responses(list_status=200, list_body=FEAST_STORE_LIST_BODY,
                    probe_status=404, probe_body=None):
    """
    Range les réponses dans l'ordre des chemins déclarés par le template :
    c'est cet ordre qui donne son numéro à chaque body_N sous req-condition.
    """
    if probe_body is None:
        probe_body = feast_not_found_body(feast_probe_id())
    ordered = []
    for path in feast_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        if route == "/v1/vector_stores":
            ordered.append((list_status, list_body))
        elif route.startswith("/v1/vector_stores/"):
            ordered.append((probe_status, probe_body))
        else:
            raise AssertionError(f"le template interroge un chemin inattendu : {route}")
    return ordered


def feast_fires(**kwargs):
    block = feast_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = feast_responses(**kwargs)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_feast_reads_the_store_index_and_touches_nothing_else():
    doc = load(FEAST_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'index des magasins se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre, alors que le même serveur "
            "porte l'écriture dans le magasin juste à côté"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/search", "POST /v1/vector_stores/{id}/search interrogerait "
                            "le corpus et en rendrait les documents — lire le "
                            "contenu n'est pas signaler l'exposition"),
                ("/push", "POST /push écrirait dans le magasin en ligne ou "
                          "hors ligne, donc dans ce que liront les modèles "
                          "servis par cette instance"),
                ("write-to-online-store", "POST /write-to-online-store "
                                          "écrirait dans le magasin en ligne"),
                ("/materialize", "POST /materialize lancerait un travail de "
                                 "calcul sur le magasin hors ligne de ce "
                                 "qu'on audite"),
                ("/get-online-features", "POST /get-online-features lirait "
                                         "les valeurs de features, ce que le "
                                         "constat n'exige pas"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    assert feast_block().get("req-condition") is True, (
        "sans req-condition, l'index conclurait seul — or son enveloppe "
        "{\"object\": \"list\", \"data\": [...]} est celle d'une API de "
        "magasins vectoriels compatible OpenAI, que Feast n'est pas seul à "
        "servir sous ce chemin"
    )


def test_feast_probe_asks_for_an_id_feast_could_never_have_minted():
    """
    La sonde ne vaut que si l'identifiant demandé est introuvable par
    construction : feature_view_to_vs_id() rend « vs_ » suivi de vingt-quatre
    caractères hexadécimaux, donc tout libellé hors de cette forme fait lever
    FeatureViewNotFoundException quel que soit le contenu du registre. Un
    identifiant qui aurait cette forme pourrait, lui, désigner un magasin réel :
    le handler rendrait 200 et le template ne conclurait jamais.
    """
    probe = feast_probe_id()
    assert not FEAST_VS_ID.match(probe), (
        f"la sonde demande {probe!r}, qui a la forme d'un identifiant que "
        "feature_view_to_vs_id() peut émettre : sur l'instance où il désigne "
        "un magasin, get_vector_store() rend 200 et le constat est perdu"
    )

    dsl = [expr for m in (feast_block().get("matchers") or [])
           for expr in (m.get("dsl") or [])]
    assert any(f'"{probe}"' in expr for expr in dsl), (
        f"le chemin demande {probe!r} mais aucune expression ne l'exige dans "
        "le corps : le message du handler renvoie l'identifiant demandé, et "
        "sans cet ancrage le chemin peut dériver du matcher sans que rien ne "
        "le signale — le template resterait muet sur toute instance"
    )


def test_feast_matcher_needs_the_product_not_an_openai_shaped_store_list():
    assert feast_fires(), (
        "le template ne reconnaît pas une instance Feast ouverte qui rend ses "
        "magasins vectoriels"
    )
    assert feast_fires(list_body=FEAST_EMPTY_STORE_LIST_BODY), (
        "le template exige un magasin dans l'index : VectorStoreRegistry ne "
        "retient que les feature views portant un champ vector_index, donc un "
        "déploiement Feast sans RAG rend data vide — et il est tout aussi "
        "ouvert, la même dépendance sans effet gardant /push et "
        "/get-online-features"
    )

    assert not feast_fires(list_body=FEAST_OPENAI_PROXY_LIST_BODY,
                           probe_body=FEAST_OPENAI_PROXY_NOT_FOUND_BODY), (
        "le template conclut sur l'enveloppe compatible OpenAI : une "
        "passerelle LLM qui sert des magasins vectoriels sous ce même chemin "
        "remonterait comme une instance Feast"
    )
    assert not feast_fires(probe_body=FEAST_GENERIC_NOT_FOUND_BODY), (
        "le template se contente de retrouver l'identifiant de la sonde dans "
        "le corps : tout routeur qui renvoie le chemin demandé dans son 404 "
        "passerait, alors que la phrase « No vector store found with id » est "
        "écrite dans get_vector_store() et nulle part ailleurs"
    )
    assert not feast_fires(probe_status=200,
                           probe_body=feast_not_found_body(feast_probe_id())), (
        "le template se passe du statut de la sonde : un document qui cite le "
        "message d'erreur de Feast — une page d'aide, un catalogue d'API — "
        "suffirait à le faire conclure"
    )
    assert not feast_fires(list_body=FEAST_SPA_BODY,
                           probe_status=200, probe_body=FEAST_SPA_BODY), (
        "le template déclenche sur l'index d'une application quelconque servie "
        "en 200 sur ces chemins"
    )


def test_feast_instance_with_an_auth_manager_is_not_reported():
    """
    Une section auth dans feature_store.yaml fait exister le SecurityManager
    global, et inject_user_details() lève alors HTTPException(401) avant le
    handler. Les deux lectures rendent 401 : rien n'est exposé, et le template
    doit rester muet.
    """
    assert not feast_fires(list_status=401, list_body=FEAST_UNAUTHORIZED_BODY,
                           probe_status=401,
                           probe_body=FEAST_UNAUTHORIZED_BODY), (
        "le template signale une instance dont auth.type vaut oidc ou "
        "kubernetes : inject_user_details() y refuse toute requête sans jeton"
    )
    assert not feast_fires(list_status=401,
                           list_body=FEAST_UNAUTHORIZED_BODY), (
        "le template conclut sur la seule sonde de reconnaissance : elle nomme "
        "le produit, mais le constat est que l'index des magasins a répondu à "
        "l'anonyme"
    )


def test_feast_extractor_stays_on_the_store_index_response():
    block = feast_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "sous req-condition le moteur évalue les extracteurs contre chaque "
        "réponse et émet un résultat par extracteur qui rend quelque chose : "
        f"{len(extractors)} extracteurs feraient remonter autant de fois la "
        "même instance"
    )
    extractor = extractors[0]
    assert extractor.get("part") == "body_1", (
        "l'extracteur n'est pas borné à body_1 : seul l'index des magasins "
        f"porte des noms à lire — part={extractor.get('part')!r}"
    )
    assert extractor.get("json") == [".data[].name"], (
        "l'extracteur ne lit pas .data[].name — build_vector_store_object() y "
        "recopie le nom de la feature view indexée, donc celui du corpus RAG "
        "de l'exploitant, et c'est le renseignement que la réponse donne"
    )


# --------------------------------------------------------------------------
# Chez Langfuse, l'authentification du préfixe /api/public/ est écrite handler par
# handler — projects/index.ts pose « CHECK AUTH »,
# ApiAuthService.verifyAuthHeaderAndReturnScope() puis un 401 — et health.ts est
# celui qui n'a pas ce bloc : il n'applique que le middleware CORS avant de rendre
# {status, version}. La difficulté du template n'est donc pas de trouver la route,
# elle est de ne pas confondre cette charge utile avec la sonde de santé de
# n'importe quel autre service. Trois faits du code la séparent, et il faut les
# trois : status ne peut valoir que « OK » sur un 200, version est le triplet privé
# de son v par VERSION.replace("v", ""), et le corps n'a que ces champs scalaires.

LANGFUSE_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "langfuse-health-exposed.yaml")


def langfuse_health_body(version="4.12.0", status="OK"):
    """
    Réponse de GET /api/public/health telle que le handler la sérialise :
    res.status(...).json({status: result.status, version: result.version}),
    donc un objet à deux champs, écrit compact et dans cet ordre.
    """
    return json.dumps({"status": status, "version": version},
                      separators=(",", ":"))


LANGFUSE_HEALTH_BODY = langfuse_health_body()

# Ce que rend la même route quand runHealthCheck() pose isHealthy: false. Les
# deux clés y sont, la version aussi : seul le statut HTTP les sépare de
# l'instance saine, et ces corps-là ne sont pas des expositions à signaler
# différemment — c'est la même route, déjà couverte par le cas sain.
LANGFUSE_UNHEALTHY_BODIES = (
    langfuse_health_body(status="Database not available"),
    langfuse_health_body(status="No traces within the last 3 minutes"),
    langfuse_health_body(status="Couldn't fetch recent events"),
    langfuse_health_body(status="Health check failed"),
)

# La sonde de santé d'un service quelconque : même forme, même semver, mais
# aucune de ces valeurs n'est celle que health-service.ts écrit.
LANGFUSE_OTHER_HEALTH_BODY = '{"status":"ok","version":"1.4.2"}'
LANGFUSE_OTHER_UP_BODY = '{"status":"UP","version":"4.12.0"}'

# Une API qui nomme sa version avec le v que VERSION.replace("v", "") retire.
LANGFUSE_V_PREFIXED_BODY = '{"status":"OK","version":"v4.12.0"}'

# Un document plus riche qui porte les deux clés dans une sous-structure : c'est
# la forme qu'ont les sondes de santé composites (Spring Actuator et consorts),
# et rien n'y désigne Langfuse.
LANGFUSE_COMPOSITE_HEALTH_BODY = (
    '{"status":"OK","components":{"db":{"status":"OK","version":"16.4.0"}}}'
)

# L'index d'une application servie sur le même hôte, que le catch-all d'un proxy
# rend en 200 sur un chemin qu'il ne connaît pas.
LANGFUSE_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Langfuse</title></head>'
    '<body><div id="__next"></div></body></html>'
)

# Refus d'un proxy placé devant l'instance pour fermer ce que le produit ne ferme
# pas : la route ne répond plus à l'anonyme, il n'y a rien à signaler.
LANGFUSE_PROXY_DENIED_BODY = '{"message":"Unauthorized"}'


def langfuse_health_block():
    doc = load(LANGFUSE_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.startswith("{{BaseURL}}/api/public/health")
                     for p in (b.get("path") or []))]
    assert blocks, "le template ne vise pas GET /api/public/health"
    return blocks[0]


def langfuse_fires(status=200, body=LANGFUSE_HEALTH_BODY):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint.
    """
    block = langfuse_health_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_langfuse_probe_reads_the_bare_route_and_never_makes_the_instance_work():
    doc = load(LANGFUSE_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "la sonde de santé se lit en GET : le template ne doit rien "
            "envoyer à une instance qu'il découvre, alors que le même préfixe "
            "porte POST /api/public/ingestion, qui écrirait des traces dans le "
            "projet"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("failIfDatabaseUnavailable", "le handler exécuterait "
                                              "« SELECT 1 » sur le Postgres de "
                                              "l'instance auditée"),
                ("failIfNoRecentEvents", "le handler interrogerait ClickHouse "
                                         "sur les trois dernières minutes — "
                                         "deux requêtes sur les tables de "
                                         "traces de l'exploitant"),
                ("/ingestion", "POST /api/public/ingestion écrirait des "
                               "événements dans le projet"),
                ("/traces", "GET /api/public/traces rendrait les invites "
                            "envoyées aux modèles et leurs réponses — lire le "
                            "contenu n'est pas signaler l'exposition"),
                ("/sessions", "GET /api/public/sessions rendrait les "
                              "conversations des utilisateurs finaux"),
                ("/observations", "GET /api/public/observations rendrait le "
                                  "détail des appels aux modèles"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = langfuse_health_block().get("path") or []
    assert paths == ["{{BaseURL}}/api/public/health"], (
        "le constat tient à une seule lecture, sur le chemin nu : les deux "
        "paramètres que la route accepte font travailler l'instance sans rien "
        f"apprendre de plus au template — {paths}"
    )


def test_langfuse_matcher_needs_the_health_payload_not_any_health_endpoint():
    assert langfuse_fires(), (
        "le template ne reconnaît pas une instance Langfuse dont la sonde de "
        "santé répond à l'anonyme"
    )
    for version in ("2.95.11", "3.124.1", "4.12.0", "4.13.0-rc.1"):
        assert langfuse_fires(body=langfuse_health_body(version=version)), (
            f"le template dépend d'une version précise alors que le handler "
            f"rend VERSION.replace(\"v\", \"\") — ici {version} — et que la "
            "forme de la réponse n'a pas bougé depuis la 2.95.0"
        )
    assert langfuse_fires(body='{\n  "status": "OK",\n  "version": "4.12.0"\n}'), (
        "le template exige la sérialisation compacte de res.json() : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer la sonde"
    )
    assert langfuse_fires(
        body='{"status":"OK","version":"4.12.0","commit":"a1b2c3d"}'), (
        "le template compte les champs : une version ultérieure qui ajouterait "
        "un scalaire à la charge utile le rendrait muet, alors que la route "
        "resterait exactement aussi ouverte"
    )

    assert not langfuse_fires(body=LANGFUSE_OTHER_HEALTH_BODY), (
        "le template déclenche sur la sonde de santé de n'importe quel "
        "service : health-service.ts écrit « OK » et cette casse-là, or "
        "« ok » est ce qu'écrivent la plupart des autres"
    )
    assert not langfuse_fires(body=LANGFUSE_OTHER_UP_BODY), (
        "le template se passe de la valeur de status : « UP » n'est pas un "
        "statut que runHealthCheck() puisse rendre, sur aucun de ses chemins"
    )
    assert not langfuse_fires(body=LANGFUSE_V_PREFIXED_BODY), (
        "le template accepte une version préfixée d'un v, que "
        "VERSION.replace(\"v\", \"\") retire précisément : la valeur rendue "
        "est le triplet nu"
    )
    assert not langfuse_fires(body=LANGFUSE_COMPOSITE_HEALTH_BODY), (
        "le template retrouve ses deux clés au fond d'un document composite : "
        "la charge utile de health.ts n'a que deux champs scalaires, donc "
        "aucune accolade intérieure"
    )
    assert not langfuse_fires(body=LANGFUSE_SPA_BODY), (
        "le template déclenche sur l'index d'une application rendu en 200 par "
        "le catch-all d'un proxy sur un chemin qu'il ne connaît pas"
    )


def test_langfuse_instance_that_does_not_answer_the_anonymous_is_not_reported():
    """
    Deux façons de ne rien avoir à signaler, et le template doit rester muet sur
    les deux. Le 503 d'abord : runHealthCheck() rend le même couple de clés,
    version comprise, sur chacun de ses chemins d'échec — seul le statut sépare
    l'instance saine, et un template qui s'en passerait remonterait quatre fois
    la même route. Le refus d'un proxy ensuite : c'est la seule fermeture que le
    produit permette, puisqu'il ne prévoit aucun réglage pour cette route.
    """
    for body in LANGFUSE_UNHEALTHY_BODIES:
        assert not langfuse_fires(status=503, body=body), (
            "le template conclut sur le seul corps : le handler rend "
            f"« {body} » en 503, avec la version, et le 200 est ce qui "
            "distingue le dernier return de runHealthCheck() de tous les autres"
        )

    assert not langfuse_fires(status=401, body=LANGFUSE_PROXY_DENIED_BODY), (
        "le template signale une instance dont un proxy refuse déjà la route à "
        "l'anonyme"
    )
    assert not langfuse_fires(status=404, body=LANGFUSE_HEALTH_BODY), (
        "le template se passe du statut : un intermédiaire qui rend la charge "
        "utile d'une autre instance sous un 404 le ferait conclure"
    )


def test_langfuse_extractor_reports_the_version_the_anonymous_caller_obtains():
    block = langfuse_health_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement — le numéro de version — et "
        f"{len(extractors)} extracteurs feraient remonter autant de fois la "
        "même instance"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("json") == [".version"], (
        "l'extracteur ne lit pas .version — c'est pourtant le seul contenu du "
        "constat, et ce qui se compare aux intervalles des avis du dépôt : "
        "« >=2.70.0, <2.95.11 » pour GHSA-94hf-6gqq-pj69, « >= 3.68.0, "
        "< 3.167.0 » pour GHSA-2524-j966-gfgh"
    )


# --------------------------------------------------------------------------
# Chez Hayhooks il n'y a pas de garde à contourner : create_app() monte
# RequestIdMiddleware puis CORSMiddleware, et inclut ensuite status_router,
# draw_router, deploy_router, undeploy_router et openai_router sans passer de
# dependencies= — aucune route ne déclare de Depends(), et settings.py ne porte
# aucun réglage de clé ni de jeton sous son préfixe hayhooks_. La difficulté du
# template est donc entièrement de reconnaissance : status_all() rend
# « StatusResponse(status="Up!", pipelines=registry.get_names()) », et cette
# charge utile ressemble à la sonde de santé de n'importe quel ordonnanceur de
# pipelines. Trois faits du code la séparent — le point d'exclamation du « Up! »
# écrit en dur, le pluriel de pipelines suivi de son tableau, qui distingue la
# route de sa voisine /status/{pipeline_name}, et la platitude d'un objet dont
# aucun champ n'est un objet.

HAYHOOKS_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "hayhooks-status-exposed.yaml")


def hayhooks_status_body(*pipelines):
    """
    Réponse de GET /status telle que FastAPI sérialise le StatusResponse que
    status_all() construit : deux champs, dans l'ordre de déclaration du modèle,
    écrits compact.
    """
    return json.dumps({"status": "Up!", "pipelines": list(pipelines)},
                      separators=(",", ":"))


HAYHOOKS_STATUS_BODY = hayhooks_status_body("chat_with_website", "rag_qa")

# registry.get_names() rend une liste vide tant qu'aucun pipeline n'est déployé
# — c'est l'état d'un serveur qu'on vient de lancer sans pipelines_dir. Le
# constat ne change pas d'un iota : le même routeur nu répond, et POST
# /deploy_files y écrit puis importe un pipeline_wrapper.py.
HAYHOOKS_EMPTY_STATUS_BODY = hayhooks_status_body()

# Ce que rend la route voisine GET /status/{pipeline_name} : le même « Up! »,
# mais PipelineStatusResponse nomme son second champ « pipeline », au singulier,
# et lui donne une chaîne. Ce n'est pas l'inventaire, et ce n'est pas ce que le
# template interroge.
HAYHOOKS_SINGLE_PIPELINE_BODY = json.dumps({"status": "Up!",
                                            "pipeline": "rag_qa"},
                                           separators=(",", ":"))

# La sonde de santé d'un ordonnanceur de pipelines quelconque : même forme, même
# clé au pluriel, mais aucune de ces valeurs n'est celle que status_all() écrit.
HAYHOOKS_OTHER_HEALTH_BODY = '{"status":"up","pipelines":["etl_nightly"]}'
HAYHOOKS_OTHER_UP_BODY = '{"status":"UP","pipelines":[]}'

# Le schéma que la même instance sert sur /openapi.json : le « Up! » y est, mot
# pour mot, dans la description du champ, et « pipelines » y est nommé — mais
# comme propriété, donc suivi d'un objet.
HAYHOOKS_OPENAPI_SCHEMA_BODY = (
    '{"StatusResponse":{"properties":{"status":{"type":"string","description":'
    '"The current status of the system, \'Up!\' when operational"},"pipelines":'
    '{"items":{"type":"string"},"type":"array","description":"List of all '
    'available pipeline names"}},"type":"object"}}'
)

# Un tableau de supervision qui agrège la réponse de Hayhooks sous une clé à
# lui : les deux clés y sont, avec leurs valeurs exactes, mais ce n'est pas
# l'instance qui a répondu.
HAYHOOKS_COMPOSITE_BODY = (
    '{"hayhooks":{"status":"Up!","pipelines":["rag_qa"]},"checked_at":0}'
)

# L'index d'une application servie sur le même hôte, que le catch-all d'un proxy
# rend en 200 sur un chemin qu'il ne connaît pas.
HAYHOOKS_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Hayhooks</title></head>'
    '<body><div id="root"></div></body></html>'
)

# Refus d'un proxy placé devant l'instance pour fermer ce que le produit ne
# ferme pas : la route ne répond plus à l'anonyme, il n'y a rien à signaler.
HAYHOOKS_PROXY_DENIED_BODY = '{"message":"Unauthorized"}'


def hayhooks_status_block():
    doc = load(HAYHOOKS_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/status" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /status"
    return blocks[0]


def hayhooks_fires(status=200, body=HAYHOOKS_STATUS_BODY):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint. Le paramètre
    de statut est tenu ici pour que les cas d'un intermédiaire se disent, même
    si le bloc n'a pas à en dépendre.
    """
    block = hayhooks_status_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_hayhooks_probe_reads_the_status_route_and_never_deploys():
    doc = load(HAYHOOKS_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'inventaire se lit en GET : sur ce routeur, la méthode POST est "
            "précisément celle qui déploie — /deploy_files écrit un "
            "pipeline_wrapper.py sur le disque de l'instance auditée et "
            "l'importe"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/deploy", "POST /deploy_files et POST /deploy-yaml font "
                            "écrire puis charger du code Python fourni dans le "
                            "corps de la requête — le scanner prendrait la main "
                            "sur ce qu'il audite"),
                ("/undeploy", "POST /undeploy/{nom} retire le pipeline du "
                              "registre, ferme ses routes et efface ses "
                              "fichiers du disque"),
                ("/draw", "GET /draw/{nom} fait rendre le graphe d'un pipeline "
                          "de l'exploitant, ce qui ne dit rien de plus que "
                          "/status sur l'ouverture du routeur"),
                ("/chat/completions", "les routes compatibles OpenAI font "
                                      "tourner un modèle aux frais de "
                                      "l'exploitant"),
                ("/run", "POST /{nom}/run exécute le pipeline nommé"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = hayhooks_status_block().get("path") or []
    assert paths == ["{{BaseURL}}/status"], (
        "le constat tient à une seule lecture, sur le chemin nu : "
        "/status/{pipeline_name} demanderait un nom qu'on n'a pas encore, et "
        f"n'apprendrait rien que l'inventaire ne dise déjà — {paths}"
    )


def test_hayhooks_matcher_needs_the_status_payload_not_any_pipeline_server():
    assert hayhooks_fires(), (
        "le template ne reconnaît pas une instance Hayhooks dont /status répond "
        "à l'anonyme"
    )
    assert hayhooks_fires(
        body='{\n  "status": "Up!",\n  "pipelines": [\n    "rag_qa"\n  ]\n}'), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer la route"
    )
    assert hayhooks_fires(
        body='{"status":"Up!","pipelines":["rag_qa"],"version":"0.12.0"}'), (
        "le template compte les champs : une version ultérieure qui ajouterait "
        "un scalaire à la charge utile le rendrait muet, alors que le routeur "
        "resterait exactement aussi ouvert"
    )

    assert not hayhooks_fires(body=HAYHOOKS_SINGLE_PIPELINE_BODY), (
        "le template se contente du « Up! » : PipelineStatusResponse le rend "
        "aussi sur /status/{pipeline_name}, et c'est le pluriel de pipelines "
        "suivi de son tableau qui dit qu'on lit l'inventaire complet"
    )
    assert not hayhooks_fires(body=HAYHOOKS_OTHER_HEALTH_BODY), (
        "le template déclenche sur la sonde de santé de n'importe quel "
        "ordonnanceur de pipelines : status_all() écrit « Up! » avec son point "
        "d'exclamation, or « up » est ce qu'écrivent la plupart des autres"
    )
    assert not hayhooks_fires(body=HAYHOOKS_OTHER_UP_BODY), (
        "le template se passe de la casse et du point d'exclamation, qui sont "
        "pourtant écrits en dur dans le handler"
    )
    assert not hayhooks_fires(body=HAYHOOKS_OPENAPI_SCHEMA_BODY), (
        "le template retrouve ses deux noms dans le schéma que la même instance "
        "sert sur /openapi.json : le « Up! » y est en description et "
        "« pipelines » y est une propriété, donc suivie d'un objet et non d'un "
        "tableau"
    )
    assert not hayhooks_fires(body=HAYHOOKS_COMPOSITE_BODY), (
        "le template retrouve ses deux clés au fond d'un document composite : "
        "la charge utile de StatusResponse n'a que deux champs, dont aucun "
        "n'est un objet, donc aucune accolade intérieure"
    )
    assert not hayhooks_fires(body=HAYHOOKS_SPA_BODY), (
        "le template déclenche sur l'index d'une application rendu en 200 par "
        "le catch-all d'un proxy sur un chemin qu'il ne connaît pas"
    )


def test_hayhooks_reports_an_instance_that_serves_no_pipeline_yet():
    """
    Le tableau vide n'est pas un cas dégradé, c'est le cas nu. registry
    .get_names() ne rend rien tant qu'aucun pipeline n'est déployé, et ce qui
    est signalé n'est pas l'inventaire mais le fait que le routeur réponde à
    l'anonyme — POST /deploy_files, du même routeur et sans plus de garde, écrit
    puis importe un pipeline_wrapper.py. Une instance vide est celle sur
    laquelle cette route a le plus à prendre.
    """
    assert hayhooks_fires(body=HAYHOOKS_EMPTY_STATUS_BODY), (
        "le template exige un pipeline déjà déployé pour conclure : il tait "
        "alors les instances fraîchement lancées, qui sont tout aussi ouvertes "
        "et dont le registre n'attend qu'un premier dépôt anonyme"
    )


def test_hayhooks_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    status_all() n'a pas de branche d'échec : ni HTTPException, ni statut
    explicite, donc la charge utile ne peut sortir de l'application que sous un
    200. Exiger ce 200 n'écarterait rien que le corps n'écarte déjà, et ferait
    manquer l'instance dont un intermédiaire réécrit le statut. Le constat est
    la charge utile, et elle seule.
    """
    block = hayhooks_status_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : le handler ne rend cette charge "
        "utile que sur un 200, donc ce matcher n'écarte rien et n'ajoute qu'un "
        "risque de silence"
    )
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer : c'est le « Up! » conjoint au "
        "tableau de pipelines qui nomme le produit, aucun des deux seul"
    )

    assert not hayhooks_fires(status=401, body=HAYHOOKS_PROXY_DENIED_BODY), (
        "le template signale une instance dont un proxy refuse déjà la route à "
        "l'anonyme — c'est la seule fermeture possible, puisque le produit "
        "n'offre aucun réglage d'authentification"
    )


def test_hayhooks_extractor_reports_the_pipelines_the_anonymous_caller_enumerates():
    block = hayhooks_status_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement — les noms des pipelines "
        f"déployés — et {len(extractors)} extracteurs feraient remonter autant "
        "de fois la même instance"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("json") == [".pipelines[]"], (
        "l'extracteur ne lit pas .pipelines[] — c'est pourtant tout le contenu "
        "du constat, et ce qui nomme les routes servies : un pipeline déployé "
        "sous « x » ouvre POST /x/run"
    )


# --------------------------------------------------------------------------
# Chez Dagster il n'y a pas de garde à contourner : create_asgi_app() rend un
# Starlette dont la liste de middleware se réduit à DagsterTracedCounterMiddleware
# — un compteur d'appels qui pose x-dagster-call-counts et ne refuse rien —, aucun
# Route() de build_routes() ne reçoit de dependencies=, et
# webserver_info_endpoint() ignore jusqu'à sa requête, dont le paramètre s'écrit
# « _request ». La difficulté du template est donc entièrement de reconnaissance :
# la charge utile est un objet de trois numéros de version, et c'est la forme
# qu'ont les routes d'information de la moitié des serveurs du pack. Trois faits
# du code la séparent — le nom dagster_webserver_version, que le renommage de
# dagit a introduit à la 1.3.14, le nom dagster_graphql_version qui l'accompagne,
# et la platitude d'un objet dont aucun champ n'est un objet.

DAGSTER_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                "dagster-webserver-exposed.yaml")


def dagster_info_body(version="1.13.18"):
    """
    Réponse de GET /server_info telle que webserver_info_endpoint() la
    sérialise : trois champs, dans l'ordre où le handler les écrit, compact. Les
    trois paquets sortent en verrou, donc le même numéro les trois fois.
    """
    return json.dumps({"dagster_webserver_version": version,
                       "dagster_version": version,
                       "dagster_graphql_version": version},
                      separators=(",", ":"))


DAGSTER_INFO_BODY = dagster_info_body()

# Une installation depuis les sources : version.py porte « 1!0+dev » en dur, et
# dagster comme dagster-graphql font de même. L'instance est exactement aussi
# ouverte que celle qui sert une version publiée.
DAGSTER_SOURCE_CHECKOUT_BODY = dagster_info_body("1!0+dev")

# Ce que rendait dagit_info_endpoint() jusqu'à la 1.2, sur /dagit_info : deux des
# trois clés y sont, mot pour mot, mais le composant s'appelait encore dagit et
# son serveur ne portait pas les routes report_asset_* d'aujourd'hui.
DAGSTER_LEGACY_DAGIT_BODY = json.dumps({"dagit_version": "1.2.7",
                                        "dagster_version": "1.2.7",
                                        "dagster_graphql_version": "1.2.7"},
                                       separators=(",", ":"))

# La route d'information d'un service quelconque : même forme, même semver, mais
# aucun de ces noms n'est celui que le handler écrit.
DAGSTER_OTHER_INFO_BODY = '{"version":"1.13.18","api_version":"1.13.18"}'

# L'inventaire de versions d'un déploiement — les valeurs d'un chart, la route de
# build-info d'une plateforme — qui épingle le paquet dagster-webserver parmi
# d'autres. Le nom y est bien une clé, la valeur bien un numéro, et le document
# bien plat : seul dagster_graphql_version, que le handler écrit toujours à côté,
# sépare l'instance qui répond d'elle-même de ce qu'un tiers écrit sur elle.
DAGSTER_PINNED_VERSIONS_BODY = (
    '{"dagster_webserver_version":"1.13.18","chart_version":"1.13.18",'
    '"image_tag":"1.13.18-py3.11"}'
)

# Un catalogue tiers qui documente l'API de Dagster : les deux noms y sont, mais
# comme valeurs — ce ne sont pas les clés d'une réponse d'instance.
DAGSTER_CATALOGUE_BODY = (
    '{"endpoint":"/server_info","fields":"dagster_webserver_version,'
    'dagster_version,dagster_graphql_version"}'
)

# Un tableau de supervision qui agrège la réponse de Dagster sous une clé à lui :
# les trois clés y sont, avec leurs valeurs exactes, mais ce n'est pas l'instance
# qui a répondu.
DAGSTER_COMPOSITE_BODY = (
    '{"dagster":{"dagster_webserver_version":"1.13.18","dagster_version":'
    '"1.13.18","dagster_graphql_version":"1.13.18"},"checked_at":0}'
)

# L'index de l'interface, que le serveur rend lui-même en 200 sur n'importe quel
# chemin qu'il ne connaît pas — Route("/{path:path}", index_html_endpoint).
DAGSTER_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Dagster</title></head>'
    '<body><div id="root"></div></body></html>'
)

# Refus d'un proxy placé devant l'instance pour fermer ce que le produit ne ferme
# pas : la route ne répond plus à l'anonyme, il n'y a rien à signaler.
DAGSTER_PROXY_DENIED_BODY = '{"message":"Unauthorized"}'


def dagster_info_block():
    doc = load(DAGSTER_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/server_info" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /server_info"
    return blocks[0]


def dagster_fires(status=200, body=DAGSTER_INFO_BODY):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint. Le paramètre
    de statut est tenu ici pour que les cas d'un intermédiaire se disent, même si
    le bloc n'a pas à en dépendre.
    """
    block = dagster_info_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_dagster_probe_reads_the_info_route_and_never_reaches_graphql():
    doc = load(DAGSTER_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "les versions se lisent en GET : sur ce routeur, la méthode POST est "
            "celle de /graphql, dont le schéma porte launchRun, et celle des "
            "trois routes report_asset_*, qui écrivent dans le journal "
            "d'événements de l'instance auditée"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/graphql", "launchRun et launchPipelineExecution y feraient "
                             "exécuter les ops de l'exploitant par ses code "
                             "locations, avec les secrets que ses ressources "
                             "portent — le scanner prendrait la main sur ce "
                             "qu'il audite"),
                ("/report_asset", "les trois routes report_asset_* écrivent des "
                                  "événements dans le journal de l'instance, "
                                  "donc mentent à l'orchestrateur sur l'état de "
                                  "ses assets"),
                ("/download_debug", "la route rend un DebugRunPayload gzippé — "
                                    "le run, ses événements et sa configuration "
                                    "—, ce qui est lire le contenu et non "
                                    "signaler l'exposition"),
                ("/logs", "la route rend la sortie capturée des steps, donc ce "
                          "que le code de l'exploitant a écrit sur stdout et "
                          "stderr"),
                ("/notebook", "la route rend un notebook du dépôt de "
                              "l'exploitant"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = dagster_info_block().get("path") or []
    assert paths == ["{{BaseURL}}/server_info"], (
        "le constat tient à une seule lecture, sur le chemin nu : build_routes() "
        "lie webserver_info_endpoint() à /server_info et à /dagit_info, l'alias "
        "hérité que @deprecated(breaking_version=\"2.0\") condamne, et les deux "
        "rendent le même corps octet pour octet — les interroger tous deux ferait "
        f"remonter la même instance deux fois pour un seul fait — {paths}"
    )


def test_dagster_matcher_needs_the_version_trio_not_any_info_route():
    assert dagster_fires(), (
        "le template ne reconnaît pas une instance Dagster dont /server_info "
        "répond à l'anonyme"
    )
    for version in ("1.3.14", "1.9.9", "1.13.18", "1.14.0rc0"):
        assert dagster_fires(body=dagster_info_body(version)), (
            f"le template dépend d'une version précise — ici {version} — alors "
            "que le handler rend la constante du paquet et que la forme de la "
            "réponse n'a pas bougé depuis le renommage de dagit"
        )
    assert dagster_fires(
        body='{\n  "dagster_webserver_version": "1.13.18",\n'
             '  "dagster_version": "1.13.18",\n'
             '  "dagster_graphql_version": "1.13.18"\n}'), (
        "le template exige la sérialisation compacte de JSONResponse : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer la route"
    )
    assert dagster_fires(
        body='{"dagster_webserver_version":"1.13.18","dagster_version":"1.13.18",'
             '"dagster_graphql_version":"1.13.18","dagster_shared_version":'
             '"1.13.18"}'), (
        "le template compte les champs : une version ultérieure qui ajouterait "
        "un scalaire à la charge utile le rendrait muet, alors que le routeur "
        "resterait exactement aussi ouvert"
    )

    assert not dagster_fires(body=DAGSTER_LEGACY_DAGIT_BODY), (
        "le template se contente de dagster_graphql_version : "
        "dagit_info_endpoint() le rendait déjà, à côté de dagster_version, "
        "jusqu'à la 1.2 — c'est dagster_webserver_version qui date le renommage "
        "et nomme le serveur d'aujourd'hui"
    )
    assert not dagster_fires(body=DAGSTER_OTHER_INFO_BODY), (
        "le template déclenche sur la route d'information de n'importe quel "
        "service : ce sont les deux noms de clés, et eux seuls, qui nomment le "
        "produit"
    )
    assert not dagster_fires(body=DAGSTER_PINNED_VERSIONS_BODY), (
        "le template se contente de dagster_webserver_version : le nom d'un "
        "paquet épinglé se retrouve dans l'inventaire de versions d'un "
        "déploiement, plat et chiffré comme la vraie charge utile — c'est "
        "dagster_graphql_version, que le handler écrit toujours à côté, qui dit "
        "que l'instance a répondu d'elle-même"
    )
    assert not dagster_fires(body=DAGSTER_CATALOGUE_BODY), (
        "le template retrouve ses deux noms là où ils sont des valeurs et non "
        "des clés : c'est ce que le deux-points de l'expression doit écarter"
    )
    assert not dagster_fires(body=DAGSTER_COMPOSITE_BODY), (
        "le template retrouve ses clés au fond d'un document composite : la "
        "charge utile de webserver_info_endpoint() n'a que trois champs, tous "
        "scalaires, donc aucune accolade intérieure"
    )
    assert not dagster_fires(body=DAGSTER_SPA_BODY), (
        "le template déclenche sur l'index de l'interface, que le serveur rend "
        "lui-même en 200 sur tout chemin inconnu — Route(\"/{path:path}\", "
        "index_html_endpoint) est la dernière route de build_routes()"
    )


def test_dagster_reports_an_instance_installed_from_source():
    """
    Le numéro n'est pas le constat, il n'en est que le contenu. version.py porte
    « 1!0+dev » tant que le paquet n'est pas publié, et dagster comme
    dagster-graphql font de même : une instance lancée depuis les sources rend
    trois fois cette chaîne, qui n'est pas un triplet. Elle sert pourtant le même
    /graphql, avec les mêmes mutations de lancement.
    """
    assert dagster_fires(body=DAGSTER_SOURCE_CHECKOUT_BODY), (
        "le template exige un numéro de version publié pour conclure : il tait "
        "alors les instances installées depuis les sources, dont le routeur est "
        "exactement aussi nu"
    )


def test_dagster_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    webserver_info_endpoint() n'a pas de branche d'échec : ni HTTPException, ni
    statut explicite passé à JSONResponse, donc la charge utile ne peut sortir de
    l'application que sous un 200. Exiger ce 200 n'écarterait rien que le corps
    n'écarte déjà, et ferait manquer l'instance dont un intermédiaire réécrit le
    statut. Le constat est la charge utile, et elle seule.
    """
    block = dagster_info_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : le handler ne rend cette charge "
        "utile que sur un 200, donc ce matcher n'écarte rien et n'ajoute qu'un "
        "risque de silence"
    )
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer : c'est "
        "dagster_webserver_version conjoint à dagster_graphql_version qui nomme "
        "le produit, aucun des deux seul"
    )

    assert not dagster_fires(status=401, body=DAGSTER_PROXY_DENIED_BODY), (
        "le template signale une instance dont un proxy refuse déjà la route à "
        "l'anonyme — c'est la seule fermeture possible, puisque le produit "
        "n'offre aucun réglage d'authentification"
    )


def test_dagster_extractor_reports_the_version_the_anonymous_caller_obtains():
    block = dagster_info_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "les trois paquets sortent en verrou et portent le même numéro : "
        f"{len(extractors)} extracteurs feraient remonter trois fois le même "
        "renseignement sur la même instance"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("json") == [".dagster_webserver_version"], (
        "l'extracteur ne lit pas .dagster_webserver_version — c'est pourtant la "
        "version du composant exposé, celle qui date le dernier correctif "
        "appliqué, et le seul des trois champs qui nomme ce composant-là"
    )


# --------------------------------------------------------------------------
# Text Embeddings Inference sert le même nom de route que son grand frère TGI,
# dont le pack couvre déjà le /info : deux templates sur GET /info, et deux
# charges utiles qui ouvrent toutes deux sur « model_id ». Chez TEI il n'y a pas
# davantage de garde à contourner — run() (router/src/http/server.rs) monte
# .route("/info", get(get_model_info)) sur un Router nu, et ne pose la couche
# d'autorisation que dans un « if let Some(api_key) = api_key », or --api-key est
# un Option<String> sans valeur par défaut. La difficulté du template est donc
# entièrement de reconnaissance, et elle est double : ne pas revendiquer le
# routeur de génération, et ne pas dépendre d'un champ que toutes les versions
# n'écrivent pas. Trois faits du code la tranchent — l'ouverture du document sur
# model_id, que serde écrit en premier depuis la 0.6, le model_type que TGI n'a
# pas et que #[serde(rename_all = "lowercase")] rend en objet à une clé unique,
# et le nom tokenization_workers là où TGI écrit validation_workers.

TEI_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                            "text-embeddings-inference-exposed.yaml")


def tei_info_body(model_type=None, served_model_name="thenlper/gte-base",
                  auto_truncate=True, version="1.9.3"):
    """
    Réponse de GET /info telle qu'axum sérialise la struct Info : les champs dans
    l'ordre de déclaration de router/src/lib.rs, compact.

    Deux champs se retirent pour dire les versions plus anciennes.
    served_model_name est entré à la 1.9 — la 1.8.1 ne le porte pas — et
    auto_truncate au cours de la ligne 1.2, absent en 1.2.0 et présent en 1.2.3.
    Une instance qui ne les écrit pas n'est pas moins ouverte pour autant.
    """
    payload = {"model_id": "thenlper/gte-base",
               "model_sha": "fca14538aa9956a46526bd1d0d11d69e19b5a101",
               "model_dtype": "float16"}
    if served_model_name is not None:
        payload["served_model_name"] = served_model_name
    payload["model_type"] = model_type or {"embedding": {"pooling": "cls"}}
    payload.update({"max_concurrent_requests": 512,
                    "max_input_length": 512,
                    "max_batch_tokens": 16384,
                    "max_batch_requests": None,
                    "max_client_batch_size": 32})
    if auto_truncate is not None:
        payload["auto_truncate"] = auto_truncate
    payload.update({"tokenization_workers": 8,
                    "version": version,
                    "sha": None,
                    "docker_label": None})
    return json.dumps(payload, separators=(",", ":"))


TEI_INFO_BODY = tei_info_body()

# Une 1.8.x, puis une 1.1.x : ni l'une ni l'autre n'écrit served_model_name, et la
# seconde n'écrit pas non plus auto_truncate. Le routeur qu'elles servent est
# exactement aussi nu que celui d'aujourd'hui.
TEI_INFO_BODY_1_8 = tei_info_body(served_model_name=None, version="1.8.1")
TEI_INFO_BODY_1_1 = tei_info_body(served_model_name=None, auto_truncate=None,
                                  version="1.1.0")

# Les deux autres variantes de ModelType. Sur un classifieur comme sur un
# réordonnanceur, l'enum embarque un ClassifierModel : les tables id2label et
# label2id complètes, donc les classes de l'exploitant, rendues à l'anonyme.
TEI_CLASSIFIER_INFO_BODY = tei_info_body(model_type={"classifier": {
    "id2label": {"0": "safe", "1": "toxic", "2": "spam"},
    "label2id": {"safe": 0, "toxic": 1, "spam": 2}}})
TEI_RERANKER_INFO_BODY = tei_info_body(model_type={"reranker": {
    "id2label": {"0": "LABEL"}, "label2id": {"LABEL": 0}}})

# Une passerelle d'inférence maison : elle ouvre elle aussi sur model_id, nomme un
# model_type et compte ses lots — mais son model_type est une chaîne et non l'objet
# à une clé que rend l'enum étiqueté à l'extérieur, et personne d'autre que TEI
# n'écrit tokenization_workers.
TEI_OTHER_GATEWAY_BODY = (
    '{"model_id":"thenlper/gte-base","model_type":"embedding",'
    '"backend":"triton","version":"1.2.0","max_client_batch_size":8,'
    '"workers":4}'
)

# Le schéma que la même instance sert sur /api-doc/openapi.json : tous les noms de
# champs d'Info y sont, mot pour mot, mais comme propriétés d'un document qui
# s'ouvre sur la version d'OpenAPI.
TEI_OPENAPI_SCHEMA_BODY = (
    '{"openapi":"3.0.3","info":{"title":"Text Embeddings Inference"},'
    '"components":{"schemas":{"Info":{"properties":{"model_id":{"type":'
    '"string","example":"thenlper/gte-base"},"model_type":{"$ref":'
    '"#/components/schemas/ModelType"},"tokenization_workers":{"type":'
    '"integer","example":4},"max_client_batch_size":{"type":"integer",'
    '"example":32}},"type":"object"}}}}'
)

# Un catalogue tiers qui documente l'API de TEI : les noms y sont, mais comme
# valeurs — ce ne sont pas les clés d'une réponse d'instance.
TEI_CATALOGUE_BODY = (
    '{"endpoint":"/info","fields":"model_id,model_type,tokenization_workers,'
    'max_client_batch_size"}'
)

# Un tableau de supervision qui agrège la réponse de TEI sous une clé à lui : la
# charge utile y est entière, avec ses valeurs exactes, mais ce n'est pas
# l'instance qui a répondu.
TEI_COMPOSITE_BODY = '{"tei":%s,"checked_at":0}' % TEI_INFO_BODY

# L'index d'une application servie sur le même hôte, que le catch-all d'un proxy
# rend en 200 sur un chemin qu'il ne connaît pas.
TEI_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Embeddings</title></head>'
    '<body><div id="root"></div></body></html>'
)


def tei_info_block():
    doc = load(TEI_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/info" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /info"
    return blocks[0]


def tei_fires(status=200, body=TEI_INFO_BODY):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint. Le paramètre de
    statut est tenu ici pour que les cas d'un intermédiaire se disent, même si le
    bloc n'a pas à en dépendre.
    """
    block = tei_info_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_tei_probe_reads_the_info_route_and_never_runs_the_model():
    doc = load(TEI_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'empreinte se lit en GET : sur ce routeur, toutes les routes "
            "d'inférence sont en POST — /embed, /embed_all, /embed_sparse, "
            "/predict, /rerank, /similarity, /tokenize, /decode, /embeddings et "
            "/v1/embeddings — et chacune ferait tourner le modèle aux frais de "
            "l'exploitant"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/embed", "POST /embed, /embed_all et /embed_sparse font "
                           "calculer des vecteurs sur le GPU de l'instance "
                           "auditée"),
                ("/predict", "POST /predict fait classer une entrée par le "
                             "modèle de l'exploitant"),
                ("/rerank", "POST /rerank fait réordonner des documents par le "
                            "modèle de l'exploitant"),
                ("/similarity", "POST /similarity enchaîne deux passes du modèle "
                                "pour comparer des entrées"),
                ("/tokenize", "POST /tokenize fait travailler le tokenizer de "
                              "l'instance sur une entrée fournie"),
                ("/decode", "POST /decode fait rendre du texte à partir "
                            "d'identifiants de jetons fournis"),
                ("/invocations", "la route Sagemaker est câblée par run() sur "
                                 "predict, rerank ou embed selon le model_type — "
                                 "c'est la même inférence sous un autre nom"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = tei_info_block().get("path") or []
    assert paths == ["{{BaseURL}}/info"], (
        "le constat tient à une seule lecture, sur le chemin nu : "
        ".route(\"/info\", get(get_model_info)) n'a pas d'alias, et /health, "
        "/ping et /metrics — les seules autres routes en GET — sont montées dans "
        "public_routes, donc répondent avec ou sans clé et ne prouvent rien — "
        f"{paths}"
    )


def test_tei_matcher_needs_the_router_parameters_not_any_info_route():
    assert tei_fires(), (
        "le template ne reconnaît pas une instance TEI dont /info répond à "
        "l'anonyme"
    )
    assert tei_fires(body=json.dumps(json.loads(TEI_INFO_BODY), indent=2)), (
        "le template exige la sérialisation compacte d'axum : un intermédiaire "
        "qui réindente ce qu'il relaie ferait manquer la route"
    )
    assert tei_fires(
        body=TEI_INFO_BODY[:-1] + ',"dense_path":null}'), (
        "le template compte les champs : une version ultérieure qui en "
        "ajouterait un le rendrait muet, alors que le routeur resterait "
        "exactement aussi ouvert"
    )

    assert not tei_fires(body=TEI_OTHER_GATEWAY_BODY), (
        "le template déclenche sur une passerelle d'inférence maison : elle "
        "ouvre elle aussi sur model_id et compte ses lots, mais son model_type "
        "est une chaîne et non l'objet à une clé que rend l'enum de TEI, et elle "
        "n'écrit pas tokenization_workers"
    )
    assert not tei_fires(body=OTHER_INFO_BODY), (
        "le template déclenche sur la route d'information de n'importe quelle "
        "passerelle qui nomme son modèle model_id"
    )
    assert not tei_fires(body=ACTUATOR_INFO_BODY), (
        "le template déclenche sur un /info sans rapport avec l'inférence"
    )
    assert not tei_fires(body=TEI_OPENAPI_SCHEMA_BODY), (
        "le template retrouve ses noms dans le schéma que la même instance sert "
        "sur /api-doc/openapi.json : ils y sont des propriétés, et le document "
        "s'ouvre sur la version d'OpenAPI et non sur model_id"
    )
    assert not tei_fires(body=TEI_CATALOGUE_BODY), (
        "le template retrouve ses noms là où ils sont des valeurs et non des "
        "clés : c'est ce que le deux-points des expressions doit écarter"
    )
    assert not tei_fires(body=TEI_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ouverture sur model_id qui dit que l'instance a "
        "répondu d'elle-même"
    )
    assert not tei_fires(body=TEI_SPA_BODY), (
        "le template déclenche sur l'index d'une application rendu en 200 par le "
        "catch-all d'un proxy sur un chemin qu'il ne connaît pas"
    )

    # Collisions internes au pack : les autres templates de disclosure du modèle
    # servi ne doivent pas être revendiqués par celui-ci.
    for other_body, other_name in (
        (LLAMACPP_PROPS_BODY, "llama.cpp"),
        (SGLANG_MODEL_INFO_BODY, "sglang"),
        (LMSTUDIO_MODELS_BODY, "lmstudio"),
        (VLLM_MODELS_BODY, "vllm"),
        (XINFERENCE_REGISTRATIONS_BODY, "xinference"),
        (AUTOMATIC1111_SD_MODELS_BODY, "automatic1111"),
    ):
        assert not tei_fires(body=other_body), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_tei_matcher_holds_across_versions_and_across_model_types():
    """
    Deux façons de rater des instances tout aussi ouvertes. Par le haut, un champ
    récent : served_model_name n'est entré dans Info qu'à la 1.9, auto_truncate
    qu'au cours de la ligne 1.2. Par le côté, la variante de ModelType : run()
    câble « / » et « /invocations » sur predict, rerank ou embed selon elle, mais
    /info répond de la même façon dans les trois cas.
    """
    for body, version in ((TEI_INFO_BODY_1_8, "1.8.1"),
                          (TEI_INFO_BODY_1_1, "1.1.0")):
        assert tei_fires(body=body), (
            f"le template exige un champ que la {version} n'écrit pas — il "
            "tairait les instances qui traînent exposées depuis cette ligne, "
            "dont le routeur est exactement aussi nu"
        )

    for body, variant in ((TEI_CLASSIFIER_INFO_BODY, "classifier"),
                          (TEI_RERANKER_INFO_BODY, "reranker")):
        assert tei_fires(body=body), (
            f"le template ne reconnaît que la variante embedding : sur un "
            f"déploiement {variant}, /info rend en plus les tables id2label et "
            "label2id, donc les classes de l'exploitant — c'est le cas où il y a "
            "le plus à dire, pas le moins"
        )


def test_tei_and_tgi_templates_do_not_claim_each_other_s_info_route():
    """
    Les deux produits de HuggingFace servent le même chemin, et le pack porte donc
    deux templates sur GET /info. La règle « un produit, un constat » ne les
    sépare pas — elle ne compare que les templates d'un même metadata.product —,
    donc c'est aux matchers de le faire : chacun doit rester muet sur la charge
    utile de l'autre, faute de quoi une seule instance remonterait deux fois sous
    deux noms de produit.
    """
    doc = load(TGI_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/info" in (b.get("path") or [])]
    assert blocks, "le template TGI ne vise plus GET /info"
    tgi_body_matchers = [m for m in (blocks[0].get("matchers") or [])
                         if m.get("part") == "body"]
    assert tgi_body_matchers, "le template TGI ne vérifie plus le corps"

    assert not all(body_matcher_hits(m, TEI_INFO_BODY) for m in tgi_body_matchers), (
        "le template TGI déclenche sur le /info de TEI : les deux charges utiles "
        "partagent model_id et max_concurrent_requests, et c'est max_best_of "
        "conjoint à validation_workers qui doit les séparer"
    )
    assert not tei_fires(body=TGI_INFO_BODY), (
        "le template déclenche sur le /info de TGI, déjà couvert par son propre "
        "template : la charge utile du routeur de génération ouvre elle aussi "
        "sur model_id et porte max_client_batch_size — seuls le model_type, "
        "qu'elle n'a pas, et tokenization_workers, là où elle écrit "
        "validation_workers, les séparent"
    )


def test_tei_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    get_model_info() n'a pas de branche d'échec : « Json(info.0) » sur une
    Extension construite au démarrage, donc la charge utile ne peut sortir de
    l'application que sous un 200. Exiger ce 200 n'écarterait rien que le corps
    n'écarte déjà, et ferait manquer l'instance dont un intermédiaire réécrit le
    statut. Le constat est la charge utile, et elle seule.
    """
    block = tei_info_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : le handler ne rend cette charge "
        "utile que sur un 200, donc ce matcher n'écarte rien et n'ajoute qu'un "
        "risque de silence"
    )
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer : c'est le model_type conjoint "
        "à tokenization_workers qui nomme le produit, aucun des deux seul"
    )

    assert not tei_fires(status=401, body=""), (
        "le template signale une instance lancée avec --api-key : l'intergiciel "
        "de run() rend alors « Err(StatusCode::UNAUTHORIZED) » sur /info, donc "
        "un corps vide, et il n'y a rien à signaler"
    )


def test_tei_extractor_reports_the_model_the_anonymous_caller_learns():
    block = tei_info_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement qui vaille d'être remonté — le "
        f"modèle servi — et {len(extractors)} extracteurs feraient remonter "
        "autant de fois la même instance"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("json") == [".model_id"], (
        "l'extracteur ne lit pas .model_id — c'est pourtant le modèle que "
        "l'appelant anonyme apprend, et celui que les routes d'inférence du même "
        "routeur nu le laissent faire tourner ; served_model_name le redirait le "
        "plus souvent, main.rs le remplissant par "
        "« args.served_model_name.unwrap_or_else(|| args.model_id.clone()) », et "
        "n'existe que depuis la 1.9"
    )


# --------------------------------------------------------------------------
# Infinity sert /models, l'endpoint le plus banal du protocole OpenAI : vLLM, LM
# Studio et l'API d'OpenAI elle-même rendent au même nom la même forme
# {"data":[…],"object":"list"}. Il n'y a pas davantage de garde à contourner —
# create_server() (libs/infinity_emb/infinity_emb/infinity_server.py) ouvre par
# « route_dependencies = [] » et ne pose validate_token que dans un « if api_key:
# », or MANAGER.api_key vaut la chaîne vide. La difficulté du template est donc
# entièrement de reconnaissance, et elle est triple : ne revendiquer aucun des
# autres serveurs compatibles OpenAI que le pack couvre déjà, ne pas dépendre
# d'un champ que toutes les versions n'écrivent pas, et surtout ne pas
# transcrire le handler plutôt que le fil.
#
# Ce dernier point est le piège du produit, et il se lit dans deux fichiers à la
# fois. _models() construit dict(id=…, stats=…, capabilities=…, backend=…,
# embedding_dtype=…, dtype=…, revision=…, lengths_via_tokenize=…, device=…) —
# neuf clés. Mais la route déclare « response_model=OpenAIModelInfo », et
# ModelInfo (fastapi_schemas/pymodels.py) n'en déclare que sept : id, stats,
# object, owned_by, created, backend, capabilities. pydantic étant en extra
# « ignore » par défaut, FastAPI retire les cinq autres avant de sérialiser, et
# le schéma que le produit publie lui-même (docs/assets/openapi.json) le
# confirme : embedding_dtype, dtype, revision, lengths_via_tokenize et device ne
# sont dans aucune des deux définitions. Un matcher qui les exigerait serait muet
# sur toutes les instances.

INFINITY_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "infinity-embedding-server-exposed.yaml")

# Les cinq clés que _models() pose et que response_model retire avant le fil.
INFINITY_KEYS_FILTERED_BY_RESPONSE_MODEL = ("embedding_dtype", "dtype", "revision",
                                            "lengths_via_tokenize", "device")


def infinity_model_entry(model_id="michaelfeil/bge-small-en-v1.5",
                         capabilities=("embed",), backend="torch"):
    """
    Une entrée de data telle que pydantic sérialise ModelInfo : les champs dans
    l'ordre de déclaration, et eux seuls.

    capabilities se retire pour dire les versions antérieures à la 0.0.40 — la
    0.0.36 ne le porte pas encore. Une instance qui ne l'écrit pas n'est pas moins
    ouverte pour autant.
    """
    entry = {"id": model_id,
             "stats": {"queue_fraction": 0.0,
                       "queue_absolute": 0,
                       "results_pending": 0,
                       "batch_size": 32},
             "object": "model",
             "owned_by": "infinity",
             "created": 1755600000,
             "backend": backend}
    if capabilities is not None:
        entry["capabilities"] = list(capabilities)
    return entry


def infinity_models_body(*entries):
    """Réponse de GET /models, telle qu'ORJSONResponse la rend : compacte."""
    if not entries:
        entries = (infinity_model_entry(),)
    return json.dumps({"data": list(entries), "object": "list"},
                      separators=(",", ":"))


INFINITY_MODELS_BODY = infinity_models_body()

# AsyncEngineArray sert autant de moteurs que --model-id a été répété, et chacun
# porte ses propres capacités : c'est l'inventaire que l'appelant anonyme obtient.
INFINITY_MULTI_MODEL_BODY = infinity_models_body(
    infinity_model_entry(),
    infinity_model_entry(model_id="mixedbread-ai/mxbai-rerank-base-v1",
                         capabilities=("embed", "rerank"), backend="optimum"),
    infinity_model_entry(model_id="acme/finetune-v3",
                         capabilities=("classify",), backend="ctranslate2"),
)

# Une instance antérieure à la 0.0.40 : ModelInfo n'y déclare pas encore
# capabilities. Ses routes sont exactement aussi nues.
INFINITY_MODELS_BODY_NO_CAPABILITIES = infinity_models_body(
    infinity_model_entry(capabilities=None))

# Une instance antérieure à la 0.0.31 : OpenAIModelInfo y déclare « data:
# ModelInfo », un objet et non un tableau. Le reste de la charge utile est
# identique, et la route est tout aussi ouverte.
INFINITY_SINGLE_ENTRY_BODY = json.dumps(
    {"data": infinity_model_entry(capabilities=None), "object": "list"},
    separators=(",", ":"))

# Ce que le template ne doit surtout pas exiger : les cinq clés que le handler
# pose et que « response_model=OpenAIModelInfo » retire. Ce corps-là ne sort
# d'aucune instance — il sert à prouver que le matcher ne les réclame pas.
INFINITY_HANDLER_KEYS_BODY = json.dumps(
    {"data": [dict(infinity_model_entry(),
                   embedding_dtype="float32", dtype="float16", revision=None,
                   lengths_via_tokenize=False, device="cuda")],
     "object": "list"},
    separators=(",", ":"))

# Une passerelle d'inférence maison : elle ouvre elle aussi sur data, nomme un
# propriétaire et publie même une file — mais son owned_by n'est pas « infinity »
# et son stats n'est pas l'objet à quatre clés du handler.
INFINITY_OTHER_GATEWAY_BODY = (
    '{"data":[{"id":"bge-small","object":"model","owned_by":"acme-platform",'
    '"backend":"triton","stats":"queue_fraction=0.0"}],"object":"list",'
    '"results_pending":0}'
)

# Le schéma que la même instance sert sur {url_prefix}/openapi.json : tous les
# noms de champs y sont, mot pour mot, jusqu'au const « infinity » d'owned_by —
# mais comme propriétés d'un document qui s'ouvre sur la version d'OpenAPI.
INFINITY_OPENAPI_SCHEMA_BODY = (
    '{"openapi":"3.1.0","info":{"title":"Infinity Embedding API"},'
    '"components":{"schemas":{"ModelInfo":{"properties":{"id":{"type":'
    '"string"},"stats":{"type":"object","title":"Stats"},"owned_by":{"type":'
    '"string","enum":["infinity"],"const":"infinity","default":"infinity"},'
    '"capabilities":{"type":"array"}},"required":["id","stats"]}}}}'
)

# Un catalogue tiers qui documente l'API d'Infinity : les noms y sont, mais comme
# valeurs — ce ne sont pas les clés d'une réponse d'instance.
INFINITY_CATALOGUE_BODY = (
    '{"endpoint":"/models","owned_by":"infinity",'
    '"fields":"data,stats,queue_fraction,results_pending,owned_by"}'
)

# Un tableau de supervision qui agrège la réponse d'Infinity sous une clé à lui :
# la charge utile y est entière, avec ses valeurs exactes, mais ce n'est pas
# l'instance qui a répondu.
INFINITY_COMPOSITE_BODY = '{"infinity":%s,"checked_at":0}' % INFINITY_MODELS_BODY

# L'index d'une application servie sur le même hôte, que le catch-all d'un proxy
# rend en 200 sur un chemin qu'il ne connaît pas.
INFINITY_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Embeddings</title></head>'
    '<body><div id="root"></div></body></html>'
)

# Ce que l'intergiciel rend quand INFINITY_API_KEY est posé : HTTPException(401,
# detail="Unauthorized"), donc le corps par défaut de FastAPI.
INFINITY_UNAUTHORIZED_BODY = '{"detail":"Unauthorized"}'


def infinity_models_block():
    doc = load(INFINITY_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/models" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /models"
    return blocks[0]


def infinity_fires(status=200, body=INFINITY_MODELS_BODY):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint. Le paramètre de
    statut est tenu ici pour que les cas d'un intermédiaire se disent, même si le
    bloc n'a pas à en dépendre.
    """
    block = infinity_models_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_infinity_probe_reads_the_models_route_and_never_runs_the_model():
    doc = load(INFINITY_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'inventaire se lit en GET : sur ce serveur, toutes les routes "
            "d'inférence sont en POST — /embeddings, /rerank, /classify, "
            "/embeddings_image et /embeddings_audio — et chacune ferait tourner "
            "le modèle aux frais de l'exploitant"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/embeddings", "POST /embeddings fait calculer des vecteurs sur "
                                "le GPU de l'instance auditée, et ses entrées "
                                "multimodales font en plus sortir un "
                                "« await session.get(img_url) » de l'hôte"),
                ("/rerank", "POST /rerank fait réordonner des documents par le "
                            "modèle de l'exploitant"),
                ("/classify", "POST /classify fait classer une entrée par le "
                              "modèle de l'exploitant"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = infinity_models_block().get("path") or []
    assert paths == ["{{BaseURL}}/models"], (
        "le constat tient à une seule lecture, sur le chemin nu : la route est "
        "écrite f\"{url_prefix}/models\" et MANAGER.url_prefix vaut \"\" par "
        "défaut, tandis que /health et /metrics — les seules autres routes en "
        "GET — sont montés hors de route_dependencies, donc répondent avec ou "
        f"sans clé et ne prouvent rien — {paths}"
    )


def test_infinity_matcher_needs_the_load_telemetry_not_any_openai_models_list():
    assert infinity_fires(), (
        "le template ne reconnaît pas une instance Infinity dont /models répond "
        "à l'anonyme"
    )
    assert infinity_fires(
        body=json.dumps(json.loads(INFINITY_MODELS_BODY), indent=2)), (
        "le template exige la sérialisation compacte d'ORJSONResponse : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer la route"
    )
    assert infinity_fires(body=INFINITY_MULTI_MODEL_BODY), (
        "le template ne reconnaît qu'un déploiement à un seul moteur : "
        "AsyncEngineArray en sert autant que --model-id a été répété, et c'est "
        "l'inventaire complet que l'anonyme obtient"
    )

    assert not infinity_fires(body=INFINITY_OTHER_GATEWAY_BODY), (
        "le template déclenche sur une passerelle d'inférence maison : elle "
        "ouvre elle aussi sur data et publie une file, mais son owned_by n'est "
        "pas le Literal[\"infinity\"] du produit et son stats n'est pas un objet"
    )
    assert not infinity_fires(body=INFINITY_OPENAPI_SCHEMA_BODY), (
        "le template retrouve ses noms dans le schéma que la même instance sert "
        "sur {url_prefix}/openapi.json : ils y sont des propriétés, et le "
        "document s'ouvre sur la version d'OpenAPI et non sur data"
    )
    assert not infinity_fires(body=INFINITY_CATALOGUE_BODY), (
        "le template retrouve ses noms là où ils sont des valeurs et non des "
        "clés : c'est ce que le deux-points des expressions doit écarter"
    )
    assert not infinity_fires(body=INFINITY_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ouverture sur data qui dit que l'instance a répondu "
        "d'elle-même"
    )
    assert not infinity_fires(body=INFINITY_SPA_BODY), (
        "le template déclenche sur l'index d'une application rendu en 200 par le "
        "catch-all d'un proxy sur un chemin qu'il ne connaît pas"
    )

    # Collisions internes au pack : les autres serveurs qui publient leur modèle
    # ne doivent pas être revendiqués par celui-ci. Les trois premiers rendent la
    # même forme {"data":[…],"object":"list"} au même nom de route.
    for other_body, other_name in (
        (VLLM_MODELS_BODY, "vllm"),
        (OTHER_OPENAI_API_BODY, "l'API d'OpenAI"),
        (LMSTUDIO_MODELS_BODY, "lmstudio"),
        (LLAMACPP_PROPS_BODY, "llama.cpp"),
        (SGLANG_MODEL_INFO_BODY, "sglang"),
        (TEI_INFO_BODY, "text-embeddings-inference"),
        (TGI_INFO_BODY, "text-generation-inference"),
        (XINFERENCE_REGISTRATIONS_BODY, "xinference"),
    ):
        assert not infinity_fires(body=other_body), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_infinity_matcher_rests_on_the_wire_payload_not_on_the_handler_keys():
    """
    Le piège du produit, et la seule chose qu'on ne peut pas lire dans _models()
    seul. Le handler pose neuf clés par modèle ; la route déclare
    « response_model=OpenAIModelInfo » et ModelInfo n'en déclare que sept, donc
    pydantic — en extra « ignore » par défaut — retire les cinq restantes avant
    que FastAPI ne sérialise. Le schéma publié par le produit lui-même
    (docs/assets/openapi.json) ne connaît qu'id, stats, object, owned_by, created,
    backend et capabilities.

    Un matcher écrit sur le corps du handler exigerait embedding_dtype, device ou
    lengths_via_tokenize : il serait alors muet sur toutes les instances du monde,
    sans qu'aucun test de reconnaissance ne le dise — la charge utile qui les
    porte n'existe pas.
    """
    written = "\n".join(
        expression
        for matcher in (infinity_models_block().get("matchers") or [])
        for expression in (matcher.get("regex") or []) + (matcher.get("words") or [])
    )
    for key in INFINITY_KEYS_FILTERED_BY_RESPONSE_MODEL:
        assert key not in written, (
            f"le matcher réclame {key} : _models() la pose bien, mais ModelInfo "
            "ne la déclare pas et response_model la retire — aucune instance "
            "n'écrit cette clé sur le fil, et le template serait muet partout"
        )

    assert infinity_fires(body=INFINITY_HANDLER_KEYS_BODY), (
        "le template compte les champs : une version ultérieure qui déclarerait "
        "dans ModelInfo l'une des clés aujourd'hui filtrées le rendrait muet, "
        "alors que les routes resteraient exactement aussi nues"
    )


def test_infinity_matcher_holds_across_versions_and_across_capabilities():
    """
    Deux façons de rater des instances tout aussi ouvertes. Par le haut, un champ
    récent : capabilities n'est entré dans ModelInfo qu'après la 0.0.36. Par le
    bas, la forme du conteneur : OpenAIModelInfo déclarait « data: ModelInfo » —
    un objet — jusqu'à la 0.0.31, où il est devenu « data: list[ModelInfo] ». Le
    quatuor de stats, lui, est posé dans le même ordre depuis la 0.0.20.
    """
    assert infinity_fires(body=INFINITY_MODELS_BODY_NO_CAPABILITIES), (
        "le template exige capabilities, que ModelInfo ne déclare qu'après la "
        "0.0.36 — il tairait les instances qui traînent exposées depuis cette "
        "ligne, dont les routes sont exactement aussi nues"
    )
    assert infinity_fires(body=INFINITY_SINGLE_ENTRY_BODY), (
        "le template exige que data soit un tableau : OpenAIModelInfo y "
        "déclarait un objet unique jusqu'à la 0.0.31, et cette instance-là sert "
        "le même /embeddings sans clé"
    )

    for capabilities in (("embed",), ("embed", "rerank"), ("classify",),
                         ("image_embed", "audio_embed", "embed")):
        body = infinity_models_body(infinity_model_entry(capabilities=capabilities))
        assert infinity_fires(body=body), (
            "le template dépend des capacités déclarées "
            f"({', '.join(capabilities)}) : capabilities est un set[str], donc "
            "un tableau dont l'ordre ne se prédit pas, et /models répond de la "
            "même façon quelle qu'en soit la composition"
        )


def test_infinity_and_vllm_templates_do_not_claim_each_other_s_models_route():
    """
    Les deux produits parlent le protocole OpenAI et rendent la même forme
    {"data":[…],"object":"list"} au même nom de route. Les chemins interrogés
    diffèrent — /models contre /v1/models —, mais rien n'empêche de lancer
    Infinity avec --url-prefix /v1, et une instance remonterait alors deux fois
    sous deux noms de produit. C'est donc aux matchers de les séparer.
    """
    doc = load(VLLM_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v1/models" in (b.get("path") or [])]
    assert blocks, "le template vLLM ne vise plus GET /v1/models"
    vllm_body_matchers = [m for m in (blocks[0].get("matchers") or [])
                          if m.get("part") == "body"]
    assert vllm_body_matchers, "le template vLLM ne vérifie plus le corps"

    assert not all(body_matcher_hits(m, INFINITY_MODELS_BODY)
                   for m in vllm_body_matchers), (
        "le template vLLM déclenche sur le /models d'Infinity : les deux charges "
        "utiles partagent data et owned_by, et c'est la valeur « vllm » conjointe "
        "à max_model_len qui doit les séparer"
    )
    assert not infinity_fires(body=VLLM_MODELS_BODY), (
        "le template déclenche sur le /v1/models de vLLM, déjà couvert par son "
        "propre template : owned_by y vaut « vllm » et la ModelCard n'a pas de "
        "stats"
    )


def test_infinity_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    _models() n'a pas de branche d'échec : il parcourt app.engine_array et rend
    « dict(data=data) », donc la charge utile ne peut sortir de l'application que
    sous un 200. Exiger ce 200 n'écarterait rien que le corps n'écarte déjà, et
    ferait manquer l'instance dont un intermédiaire réécrit le statut. Le constat
    est la charge utile, et elle seule.
    """
    block = infinity_models_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : le handler ne rend cette charge "
        "utile que sur un 200, donc ce matcher n'écarte rien et n'ajoute qu'un "
        "risque de silence"
    )
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer : c'est l'objet stats conjoint "
        "au Literal owned_by qui nomme le produit, aucun des deux seul"
    )

    assert not infinity_fires(status=401, body=INFINITY_UNAUTHORIZED_BODY), (
        "le template signale une instance lancée avec INFINITY_API_KEY : "
        "validate_token lève alors HTTPException(401, detail=\"Unauthorized\") "
        "sur /models, et il n'y a rien à signaler"
    )


def test_infinity_extractor_reports_the_models_the_anonymous_caller_enumerates():
    block = infinity_models_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement qui vaille d'être remonté — "
        f"l'inventaire des modèles servis — et {len(extractors)} extracteurs "
        "feraient remonter autant de fois la même instance"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("json") == [".data[].id"], (
        "l'extracteur ne parcourt pas .data[].id — c'est pourtant l'inventaire "
        "que l'appelant anonyme obtient, et celui que les routes d'inférence du "
        "même processus le laissent faire tourner ; s'arrêter à .data[0].id "
        "tairait les autres moteurs d'un AsyncEngineArray, et le champ vaut le "
        "served_model_name qu'EngineArgs remplit par les deux derniers segments "
        "du chemin des poids"
    )


# --------------------------------------------------------------------------
# NeMo Guardrails rend sur /v1/rails/configs la charge utile la plus pauvre du
# pack : « [{"id": config_id} for config_id in config_ids] », donc un tableau
# d'objets à une seule clé. Il n'y a pas de version à lire, pas de nom de
# produit écrit dans la réponse, pas de télémétrie — rien qu'une liste de noms
# de dossiers. La reconnaissance ne peut donc tenir qu'à deux choses : le chemin
# propre au produit, et la forme entière du corps.
#
# Cette forme est exactement ce qui la sépare d'une liste de ressources
# quelconque. get_rails_configs() ne déclare pas de response_model, donc FastAPI
# sérialise littéralement ce que le handler construit, et le handler ne
# construit qu'une clé. Une API qui rendrait la même liste avec un name ou un
# enabled à côté n'est pas ce serveur.
#
# Le piège du produit est ailleurs, et il est de calendrier. GET /v1/health rend
# « {"status":"pass"} » sous le type de média application/health+json, que
# personne d'autre n'écrit : c'est le témoin le plus net qui soit. Mais ce
# handler n'existe que sur la branche develop — il est absent d'api.py dans
# chaque tag publié jusqu'à la v0.23.0 incluse, qui est la dernière version sur
# PyPI. Un template qui s'y appuierait serait muet sur la totalité des instances
# déployées aujourd'hui.

NEMO_GUARDRAILS_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                        "nemo-guardrails-server-exposed.yaml")


def nemo_guardrails_configs_body(*config_ids):
    """Réponse de GET /v1/rails/configs, telle que FastAPI la sérialise : compacte."""
    return json.dumps([{"id": config_id} for config_id in config_ids],
                      separators=(",", ":"))


# Mode multi-configuration, la forme que la documentation du produit montre
# elle-même au curl. Le handler ne pose qu'une clé par entrée.
NEMO_GUARDRAILS_CONFIGS_BODY = nemo_guardrails_configs_body(
    "content_safety", "jailbreak_detection", "topic_safety")

# Mode mono-configuration : le handler court-circuite os.listdir() et rend
# « [{"id": app.single_config_id}] », c'est-à-dire le nom du dossier racine.
NEMO_GUARDRAILS_SINGLE_CONFIG_BODY = nemo_guardrails_configs_body("content_safety")

# Serveur lancé sans --config et sans dossier ./config local : rails_config_path
# reste utils.get_examples_data_path("bots"), donc les bots d'exemple livrés avec
# le paquet. C'est le cas d'un `nemoguardrails server` tapé tel quel.
NEMO_GUARDRAILS_BUNDLED_BOTS_BODY = nemo_guardrails_configs_body(
    "abc", "abc_v2", "hello_world")

# Un dossier qui ne porte aucune configuration valide : la route répond, mais
# n'énumère rien et ne nomme aucun produit.
NEMO_GUARDRAILS_NO_CONFIG_BODY = "[]"

# Une API quelconque qui rend une liste de ressources identifiées : elle nomme
# elle aussi un id, mais jamais seul. C'est ce que la forme entière doit écarter.
NEMO_GUARDRAILS_OTHER_ID_LIST_BODY = (
    '[{"id":"content_safety","name":"Content Safety","enabled":true},'
    '{"id":"topic_safety","name":"Topic Safety","enabled":false}]'
)

# Le schéma que la même instance sert sur /openapi.json : le chemin y figure mot
# pour mot, et « id » aussi — mais comme propriétés d'un document qui s'ouvre sur
# la version d'OpenAPI.
NEMO_GUARDRAILS_OPENAPI_SCHEMA_BODY = (
    '{"openapi":"3.1.0","info":{"title":"Guardrails Server API",'
    '"version":"0.1.0"},"paths":{"/v1/rails/configs":{"get":{"summary":'
    '"Get List of available rails configurations.","operationId":'
    '"get_rails_configs_v1_rails_configs_get","responses":{"200":'
    '{"description":"Successful Response","content":{"application/json":'
    '{"schema":{"items":{"properties":{"id":{"type":"string"}}}}}}}}}}}}'
)

# Un tableau de supervision qui agrège la réponse sous une clé à lui : la charge
# utile y est entière, avec ses valeurs exactes, mais ce n'est pas l'instance qui
# a répondu.
NEMO_GUARDRAILS_COMPOSITE_BODY = (
    '{"nemo-guardrails":%s,"checked_at":0}' % NEMO_GUARDRAILS_CONFIGS_BODY)

# La console chainlit montée sur /chat, vers laquelle GET / redirige, telle qu'un
# catch-all la rendrait en 200 sur un chemin qu'il ne connaît pas.
NEMO_GUARDRAILS_CHAT_UI_BODY = (
    '<!doctype html><html lang="en"><head><title>Chat</title></head>'
    '<body><div id="root"></div></body></html>'
)

# Ce qu'un FastAPI rend sur un chemin qu'il ne sert pas — donc ce qu'une instance
# antérieure à l'apparition de la route rendrait ici.
NEMO_GUARDRAILS_NOT_FOUND_BODY = '{"detail":"Not Found"}'


def nemo_guardrails_block():
    doc = load(NEMO_GUARDRAILS_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v1/rails/configs" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /v1/rails/configs"
    return blocks[0]


def nemo_guardrails_matcher_expressions():
    """Tout ce que les matchers du bloc écrivent, mots et expressions confondus."""
    return "\n".join(
        expression
        for matcher in (nemo_guardrails_block().get("matchers") or [])
        for expression in (matcher.get("regex") or []) + (matcher.get("words") or [])
    )


def nemo_guardrails_fires(body=NEMO_GUARDRAILS_CONFIGS_BODY, status=200,
                          headers="content-type: application/json"):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint.

    `body_matcher_hits` porte la sémantique de `word` comme de `regex` sans rien
    savoir du sujet qu'on lui donne : elle sert donc aussi bien la part `header`,
    où nuclei présente les en-têtes de la réponse comme une chaîne. Le paramètre
    de statut est tenu ici pour que les cas d'un intermédiaire se disent, même si
    le bloc n'a pas à en dépendre.
    """
    block = nemo_guardrails_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        elif matcher.get("part") == "header":
            verdicts.append(body_matcher_hits(matcher, headers))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_nemo_guardrails_probe_reads_the_configs_route_and_never_runs_the_rails():
    doc = load(NEMO_GUARDRAILS_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'inventaire se lit en GET : sur ce serveur, tout ce qui fait "
            "travailler l'exploitant est en POST — /v1/chat/completions et "
            "/v1/checks — et le routeur nu les sert à l'anonyme comme le reste"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/chat/completions", "POST /v1/chat/completions fait tourner le "
                                      "LLM de la configuration demandée, dont la "
                                      "clé d'API vient de l'environnement de "
                                      "l'exploitant et dont la consommation lui "
                                      "est facturée"),
                ("/checks", "POST /v1/checks fait passer une entrée choisie par "
                            "l'appelant à travers les rails de l'exploitant"),
                ("/models", "GET /v1/models fait interroger le fournisseur de "
                            "modèles configuré depuis l'instance auditée"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = nemo_guardrails_block().get("path") or []
    assert paths == ["{{BaseURL}}/v1/rails/configs"], (
        "le constat tient à une seule lecture, sur le chemin nu : la route est "
        "écrite en dur dans le décorateur, et une instance lancée avec --prefix "
        f"monte l'arbre entier sous ce préfixe, que {{{{BaseURL}}}} porte — {paths}"
    )


def test_nemo_guardrails_matcher_needs_the_configs_payload_not_any_list_of_ids():
    assert nemo_guardrails_fires(), (
        "le template ne reconnaît pas une instance dont /v1/rails/configs "
        "énumère ses configurations pour l'anonyme"
    )
    assert nemo_guardrails_fires(body=NEMO_GUARDRAILS_SINGLE_CONFIG_BODY), (
        "le template exige plusieurs entrées : en mode mono-configuration le "
        "handler rend « [{\"id\": app.single_config_id}] », et cette instance-là "
        "sert le même /v1/chat/completions sans clé"
    )
    assert nemo_guardrails_fires(body=NEMO_GUARDRAILS_BUNDLED_BOTS_BODY), (
        "le template ne reconnaît pas le serveur lancé sans --config, dont "
        "rails_config_path reste celui des bots d'exemple du paquet — c'est "
        "pourtant le `nemoguardrails server` tapé tel quel"
    )
    assert nemo_guardrails_fires(
        body=json.dumps(json.loads(NEMO_GUARDRAILS_CONFIGS_BODY), indent=2)), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer la route"
    )

    assert not nemo_guardrails_fires(body=NEMO_GUARDRAILS_NO_CONFIG_BODY), (
        "le template déclenche sur « [] » : un dossier sans configuration "
        "valide n'énumère rien, ne nomme aucun produit, et ce tableau vide est "
        "la réponse la plus banale du web"
    )
    assert not nemo_guardrails_fires(body=NEMO_GUARDRAILS_OTHER_ID_LIST_BODY), (
        "le template déclenche sur une liste de ressources identifiées "
        "quelconque : le handler écrit « {\"id\": config_id} » et rien d'autre, "
        "donc c'est l'objet à clé unique qui nomme le produit, pas la présence "
        "d'un id"
    )
    assert not nemo_guardrails_fires(body=NEMO_GUARDRAILS_OPENAPI_SCHEMA_BODY), (
        "le template retrouve son chemin et sa clé dans le schéma que la même "
        "instance sert sur /openapi.json : ils y sont des propriétés, et le "
        "document est un objet là où la route rend un tableau"
    )
    assert not nemo_guardrails_fires(body=NEMO_GUARDRAILS_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur les deux crochets qui dit que "
        "l'instance a répondu d'elle-même"
    )
    assert not nemo_guardrails_fires(body=NEMO_GUARDRAILS_CHAT_UI_BODY,
                                     headers="content-type: text/html"), (
        "le template déclenche sur la console chainlit montée sur /chat, qu'un "
        "catch-all rendrait en 200 sur un chemin qu'il ne connaît pas"
    )
    assert not nemo_guardrails_fires(body=NEMO_GUARDRAILS_NOT_FOUND_BODY,
                                     status=404), (
        "le template déclenche sur le « {\"detail\":\"Not Found\"} » d'un "
        "FastAPI qui ne sert pas ce chemin"
    )

    # Collisions internes au pack : aucun des autres serveurs couverts ne doit
    # être revendiqué par celui-ci.
    for other_body, other_name in (
        (VLLM_MODELS_BODY, "vllm"),
        (OTHER_OPENAI_API_BODY, "l'API d'OpenAI"),
        (LMSTUDIO_MODELS_BODY, "lmstudio"),
        (INFINITY_MODELS_BODY, "infinity"),
        (TEI_INFO_BODY, "text-embeddings-inference"),
        (TGI_INFO_BODY, "text-generation-inference"),
        (LETTA_AGENTS_BODY, "letta"),
    ):
        assert not nemo_guardrails_fires(body=other_body), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_nemo_guardrails_matcher_does_not_rest_on_the_unreleased_health_route():
    """
    Le seul point qu'on ne peut pas lire dans api.py seul, et il se paierait
    cher. GET /v1/health rend « {"status":"pass"} » sous le type de média
    application/health+json — une signature que personne d'autre n'écrit, et
    qu'il serait tentant d'exiger en corroboration.

    Mais ce handler n'existe que sur la branche develop : api.py ne le porte dans
    aucun tag publié, ni à la v0.23.0 — la dernière version sur PyPI — ni dans
    aucune de celles d'avant. Un matcher qui en dépendrait, ou une seconde
    requête qui l'exigerait sous req-condition, rendrait le template muet sur la
    totalité des instances déployées aujourd'hui, dont les routes sont
    exactement aussi nues.

    La charge utile de /v1/rails/configs, elle, est écrite mot pour mot de la
    même façon depuis la v0.8.0 : c'est sur elle seule que le constat tient.
    """
    doc = load(NEMO_GUARDRAILS_TEMPLATE)
    for block in (doc.get("http") or []):
        for path in (block.get("path") or []):
            assert "health" not in path, (
                f"le template interroge {path} : /v1/health et /healthz "
                "n'existent que sur develop, et aucune version publiée ne les "
                "sert"
            )

    written = nemo_guardrails_matcher_expressions()
    for absent, why in (
        ("health", "le type de média application/health+json ne sort que d'une "
                   "instance construite depuis develop"),
        ('"pass"', "« {\"status\":\"pass\"} » est le corps de /v1/health, que "
                   "nulle version publiée ne rend"),
    ):
        assert absent not in written, (
            f"le matcher réclame {absent!r} : {why}, et le template serait muet "
            "sur toutes les instances déployées"
        )


def test_nemo_guardrails_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    get_rails_configs() n'a pas de branche d'échec : il rend une liste, donc la
    charge utile ne peut sortir de l'application que sous un 200. Exiger ce 200
    n'écarterait rien que le corps n'écarte déjà, et ferait manquer l'instance
    dont un intermédiaire réécrit le statut.
    """
    block = nemo_guardrails_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : le handler ne rend cette charge "
        "utile que sur un 200, donc ce matcher n'écarte rien et n'ajoute qu'un "
        "risque de silence"
    )
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer : la réponse ne porte ni "
        "version ni nom de produit, et c'est la forme entière du corps, jointe "
        "au type de média, qui la nomme — aucun des deux seul"
    )


def test_nemo_guardrails_extractor_reports_the_configs_the_anonymous_caller_enumerates():
    block = nemo_guardrails_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement qui vaille d'être remonté — "
        f"les configurations de garde-fous chargées — et {len(extractors)} "
        "extracteurs feraient remonter autant de fois la même instance"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un tableau JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("json") == [".[].id"], (
        "l'extracteur ne parcourt pas .[].id — ce sont pourtant les config_id "
        "que l'appelant anonyme énumère, et ceux qu'il peut ensuite citer à "
        "POST /v1/chat/completions ; s'arrêter à .[0].id tairait les autres "
        "politiques du mode multi-configuration"
    )


# --------------------------------------------------------------------------
# Marqo pose la question que tout le pack pose, mais en clair : à quoi sert de
# reconnaître un produit ? Sa racine rend « {"message": "Welcome to Marqo",
# "version": …} », une phrase écrite dans le handler mot pour mot depuis la
# 0.1.0, et c'est tout ce qu'un template de détection regarde en amont. Or cette
# bannière répond aussi bien derrière un proxy qui authentifie le reste de
# l'arbre : elle nomme, elle ne constate rien. Le constat est ailleurs —
# get_indexes() interroge index_management.get_all_indexes() et rend
# « {'results': [{'indexName': index.name} for index in indexes]} », donc l'état
# du moteur lu chez l'exploitant. Le template doit tenir aux deux à la fois, et
# se taire dès que la seconde route ne répond pas.
#
# Le piège du produit est de casse. Jusqu'à la 1.5, get_indexes() passait par
# tensor_search.get_indexes(), qui écrivait « {'index_name': ix} » : la graphie
# chameau est la forme de fil du produit depuis la 2.0, et c'est elle qui
# distingue la réponse de celle de n'importe quel moteur de recherche.

MARQO_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "marqo-unauthenticated.yaml")


def marqo_root_body(version="2.13.0"):
    """Réponse de root(), telle que FastAPI la sérialise : compacte."""
    return json.dumps({"message": "Welcome to Marqo", "version": version},
                      separators=(",", ":"))


def marqo_indexes_body(*index_names):
    """Réponse de get_indexes() depuis la 2.0 : un dictionnaire à clé unique."""
    return json.dumps({"results": [{"indexName": name} for name in index_names]},
                      separators=(",", ":"))


MARQO_ROOT_BODY = marqo_root_body()
MARQO_INDEXES_BODY = marqo_indexes_body("catalogue-produits", "tickets-support")

# Une instance qui n'a pas encore d'index : la route répond, mais n'énumère rien.
# Le tableau vide est la réponse la plus banale du web, et il ne prouve aucun
# accès en lecture au moteur — il n'y a rien à lire.
MARQO_NO_INDEX_BODY = marqo_indexes_body()

# La graphie de la branche 1.x, arrêtée fin 2023 et qui exigeait un marqo-os à
# côté : tensor_search.get_indexes() écrivait « {'index_name': ix} ».
MARQO_LEGACY_INDEXES_BODY = (
    '{"results":[{"index_name":"catalogue-produits"},'
    '{"index_name":"tickets-support"}]}'
)

# Ce qu'un proxy placé devant l'instance rend sur /indexes quand il n'expose que
# la racine : la bannière répond, le plan de données non.
MARQO_PROXY_UNAUTHORIZED_BODY = (
    '<html><head><title>401 Authorization Required</title></head>'
    '<body><center><h1>401 Authorization Required</h1></center></body></html>'
)

# Ce qu'un FastAPI rend sur un chemin qu'il ne sert pas — donc ce que rendrait
# une pile qui n'est pas Marqo mais dont la racine aurait été recopiée.
MARQO_NOT_FOUND_BODY = '{"detail":"Not Found"}'

# Un tableau de supervision qui agrège la réponse sous une clé à lui : la charge
# utile y est entière, avec ses valeurs exactes, mais ce n'est pas l'instance qui
# a répondu.
MARQO_COMPOSITE_INDEXES_BODY = (
    '{"marqo":%s,"checked_at":0}' % MARQO_INDEXES_BODY)

# Les deux façons de citer le produit sans l'être, et que l'ancrage sur la clé
# message doit écarter : un inventaire qui recopie la requête Shodan du template
# de détection amont, et une console qui affiche la bannière sous un nom à elle.
MARQO_BANNER_QUOTED_IN_PROSE_BODY = (
    '{"service":"inventaire","note":"la requete shodan vaut '
    'http.html:\\"Welcome to Marqo\\" et suffit a lister le parc"}'
)
MARQO_BANNER_UNDER_ANOTHER_KEY_BODY = (
    '{"product":"Marqo","banner":"Welcome to Marqo","state":"up"}'
)

# Le catch-all d'une interface : sur un chemin qu'il ne sert pas, le serveur rend
# sa page d'accueil en 200 plutôt qu'un 404.
MARQO_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Marqo</title></head>'
    '<body><div id="app"></div></body></html>'
)


def marqo_block():
    doc = load(MARQO_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/indexes" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /indexes — la bannière de la racine est "
        "déjà tout ce qu'un template de détection regarde, et elle répond "
        "derrière un proxy qui authentifie le reste de l'arbre"
    )
    return blocks[0]


def marqo_responses(root_status=200, root_body=MARQO_ROOT_BODY,
                    indexes_status=200, indexes_body=MARQO_INDEXES_BODY):
    """
    Range les réponses dans l'ordre des chemins déclarés par le template : c'est
    cet ordre qui donne son numéro à chaque body_N sous req-condition.
    """
    ordered = []
    for path in marqo_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        if route == "/":
            ordered.append((root_status, root_body))
        elif route == "/indexes":
            ordered.append((indexes_status, indexes_body))
        else:
            raise AssertionError(f"le template interroge un chemin inattendu : {route}")
    return ordered


def marqo_fires(**kwargs):
    block = marqo_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = marqo_responses(**kwargs)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_marqo_probe_reads_the_two_routes_and_never_runs_the_engine():
    doc = load(MARQO_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'inventaire se lit en GET : sur cette API tout ce qui fait "
            "travailler ou écrire l'exploitant est en POST ou en DELETE, et le "
            "routeur nu les sert à l'anonyme comme le reste"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/search", "POST /indexes/{index}/search fait tourner le "
                            "modèle d'embedding de l'exploitant et rend les "
                            "documents que le template est censé protéger"),
                ("/embed", "POST /indexes/{index}/embed vectorise ce qu'on lui "
                           "donne, donc occupe le GPU de l'hôte, et sur un "
                           "index à média fait sortir une requête HTTP de "
                           "l'instance auditée vers l'URL demandée"),
                ("/documents", "les routes de documents lisent le corpus quand "
                               "elles ne le réécrivent pas : POST "
                               "/indexes/{index}/documents remplace ce que la "
                               "recherche citera ensuite"),
                ("/models", "DELETE /models éjecte le modèle chargé, et lire "
                            "GET /models ne prouve rien de plus que /indexes"),
                ("/upgrade", "POST /upgrade fait migrer l'application Vespa de "
                             "l'exploitant"),
                ("/rollback", "POST /rollback et /rollback-vespa font revenir "
                              "l'exploitant à un état antérieur"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = marqo_block().get("path") or []
    assert paths == ["{{BaseURL}}/", "{{BaseURL}}/indexes"], (
        "le constat tient à deux lectures, sur les chemins nus et dans cet "
        "ordre : les deux routes sont écrites en dur dans leur décorateur, "
        "l'application ne connaît pas de préfixe, et la bannière doit précéder "
        f"la preuve — {paths}"
    )


def test_marqo_matcher_needs_the_index_enumeration_not_just_the_banner():
    block = marqo_block()
    assert block.get("req-condition") is True, (
        "sans req-condition les deux réponses ne partagent pas d'espace de "
        "noms : la bannière conclurait seule, et c'est exactement ce qu'un "
        "template de détection fait déjà en amont"
    )

    assert marqo_fires(), (
        "le template ne reconnaît pas une instance dont /indexes énumère ses "
        "index pour l'anonyme"
    )
    assert marqo_fires(indexes_body=marqo_indexes_body("index-unique")), (
        "le template exige plusieurs index : une instance qui n'en porte qu'un "
        "sert le même /indexes/{index}/search sans rien demander"
    )
    assert marqo_fires(root_body=json.dumps(json.loads(MARQO_ROOT_BODY), indent=2),
                       indexes_body=json.dumps(json.loads(MARQO_INDEXES_BODY),
                                               indent=2)), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer l'instance"
    )
    assert marqo_fires(root_body=marqo_root_body("2.0.0")), (
        "le template contraint le numéro de version, qui change à chaque "
        "publication — la bannière ne doit tenir qu'à la phrase du handler"
    )

    # La frontière du constat, et c'est elle qui sépare ce template du template
    # de détection amont : la bannière seule ne dit rien.
    assert not marqo_fires(indexes_status=401,
                           indexes_body=MARQO_PROXY_UNAUTHORIZED_BODY), (
        "le template déclenche sur une instance placée derrière un proxy qui "
        "n'expose que la racine : la bannière répond toujours, mais le plan de "
        "données ne répond plus, et c'est lui qui porte le constat"
    )
    assert not marqo_fires(indexes_status=404,
                           indexes_body=MARQO_NOT_FOUND_BODY), (
        "le template déclenche sur le « {\"detail\":\"Not Found\"} » d'une "
        "application qui ne sert pas /indexes"
    )
    assert not marqo_fires(indexes_body=MARQO_SPA_BODY), (
        "le template déclenche sur la page d'accueil qu'un catch-all rend en "
        "200 sur un chemin qu'il ne connaît pas"
    )
    assert not marqo_fires(indexes_body=MARQO_COMPOSITE_INDEXES_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture du corps qui dit que "
        "l'instance a répondu d'elle-même"
    )

    # Le tableau vide : la route répond, mais il n'y a rien à énumérer, donc
    # rien qui prouve un accès en lecture au moteur.
    assert not marqo_fires(indexes_body=MARQO_NO_INDEX_BODY), (
        "le template déclenche sur « {\"results\":[]} » : une instance sans "
        "index n'a rien à livrer à l'appelant anonyme, et ce tableau vide est "
        "trop banal pour porter un constat de sévérité haute"
    )

    # La graphie, et ce qu'il en coûterait d'accepter les deux.
    assert not marqo_fires(indexes_body=MARQO_LEGACY_INDEXES_BODY), (
        "le template confirme sur « index_name » : c'est la graphie de la "
        "branche 1.x, arrêtée fin 2023, et c'est surtout le nom que tout "
        "moteur de recherche donne à ses index — la casse chameau est la forme "
        "de fil du produit depuis la 2.0"
    )

    # La bannière doit être la valeur du champ message, pas un mot qui traîne.
    assert not marqo_fires(root_body=MARQO_BANNER_QUOTED_IN_PROSE_BODY), (
        "le template trouve la phrase du produit n'importe où dans le corps : "
        "il déclencherait sur un inventaire qui recopie la requête Shodan du "
        "template de détection amont"
    )
    assert not marqo_fires(root_body=MARQO_BANNER_UNDER_ANOTHER_KEY_BODY), (
        "le template accepte la bannière sous une clé quelconque : root() "
        "l'écrit sous « message », et une console qui l'affiche sous un nom à "
        "elle n'est pas l'instance"
    )

    # Collisions internes au pack : aucun des autres serveurs couverts ne doit
    # être revendiqué par celui-ci.
    for other_body, other_name in (
        (VLLM_MODELS_BODY, "vllm"),
        (LMSTUDIO_MODELS_BODY, "lmstudio"),
        (INFINITY_MODELS_BODY, "infinity"),
        (XINFERENCE_REGISTRATIONS_BODY, "xinference"),
        (TEI_INFO_BODY, "text-embeddings-inference"),
        (TGI_INFO_BODY, "text-generation-inference"),
        (SGLANG_MODEL_INFO_BODY, "sglang"),
    ):
        assert not marqo_fires(root_body=other_body, indexes_body=other_body), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_marqo_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    Ni root() ni get_indexes() n'ont de branche d'échec : ils rendent un
    dictionnaire, que FastAPI ne peut sortir que sous un 200. Exiger ce 200
    n'écarterait rien que les corps n'écartent déjà — un 401 de proxy rend du
    HTML, un 404 rend « {"detail":"Not Found"} » — et ferait manquer l'instance
    dont un intermédiaire réécrit le statut.
    """
    block = marqo_block()

    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : les deux handlers ne rendent "
        "leur charge utile que sur un 200, donc ce matcher n'écarte rien et "
        "n'ajoute qu'un risque de silence"
    )

    written = "\n".join(expr for m in (block.get("matchers") or [])
                        if m.get("type") == "dsl"
                        for expr in (m.get("dsl") or []))
    assert "status_code_" not in written, (
        "une expression dsl porte le statut : le constat doit tenir aux deux "
        "charges utiles, pas au code de réponse"
    )

    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "dsl":
            assert matcher.get("condition") == "and", (
                "les expressions doivent toutes devoir passer : la bannière "
                "nomme sans constater, l'énumération constate sans nommer, et "
                "aucune des deux ne conclut seule"
            )

    # Le template ne conclut toujours pas si l'énumération manque, quel que soit
    # le statut que l'intermédiaire renvoie.
    assert not marqo_fires(indexes_status=200,
                           indexes_body=MARQO_PROXY_UNAUTHORIZED_BODY), (
        "un proxy qui rend sa page de refus en 200 suffit à faire conclure le "
        "template : c'est le corps de /indexes qui porte la preuve"
    )


def test_marqo_extractor_reports_the_indexes_the_anonymous_caller_enumerates():
    block = marqo_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement qui vaille d'être remonté — "
        f"les index que l'exploitant a nommés — et {len(extractors)} "
        "extracteurs feraient remonter autant de fois la même instance sous "
        "req-condition. La version se lit de toute façon sur la racine, que "
        "l'instance soit fermée ou non ; elle ne fait pas partie du constat"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en charger"
    )
    assert extractor.get("part") == "body_2", (
        "l'extracteur n'est pas borné à la réponse de /indexes : sous "
        "req-condition le moteur l'évalue contre chaque réponse, et la bannière "
        "n'a pas d'index à donner"
    )
    assert extractor.get("json") == [".results[].indexName"], (
        "l'extracteur ne parcourt pas .results[].indexName — ce sont pourtant "
        "les noms que l'exploitant a choisis, et le {index_name} que réclame "
        "ensuite tout le reste de l'arbre ; s'arrêter à .results[0].indexName "
        "tairait les autres index de l'instance"
    )


# --------------------------------------------------------------------------
# Kedro-Viz est le cas où le défaut de liaison est correct — DEFAULT_HOST vaut
# "127.0.0.1" et « kedro viz run » en part —, donc l'exposition vient d'un
# « --host 0.0.0.0 » posé à la main. Le routeur, lui, est nu : APIRouter(
# prefix="/api", …) sans dependencies=, aucun Depends() dans les handlers, et
# une application qui n'ajoute qu'un StaticFiles et des en-têtes de réponse.
#
# Ce qui rend ce template particulier est la route qui le nomme.
# save_api_responses_to_fs() écrit api/main, api/nodes/*, api/pipelines/* et
# api/run-status — mais pas api/metadata —, et create_api_app_from_file(), qui
# sert une instance --load-file, redéclare les mêmes routes sans /api/metadata.
# Un site produit par « kedro viz build » rend donc /api/main et rien d'autre du
# constat : c'est une publication choisie, sans POST /api/deploy ni lecture du
# projet à chaud, et le template doit rester muet dessus. C'est l'exigence de
# /api/metadata qui l'y oblige, pas une intention écrite quelque part.

KEDRO_VIZ_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "kedro-viz-exposed.yaml")


def kedro_viz_metadata_body(*packages, has_missing_dependencies=False):
    """
    Réponse de /api/metadata telle qu'ORJSONResponse la sérialise : compacte, et
    dans l'ordre de déclaration de MetadataAPIResponse puis de
    PackageCompatibility.
    """
    return json.dumps({
        "has_missing_dependencies": has_missing_dependencies,
        "package_compatibilities": [
            {"package_name": name, "package_version": version,
             "is_compatible": compatible}
            for name, version, compatible in packages
        ],
    }, separators=(",", ":"))


def kedro_viz_main_body(*node_names, pipelines=("__default__", "data_science")):
    """
    Réponse de /api/main : GraphAPIResponse, dans l'ordre nodes, edges, layers,
    tags, pipelines, modular_pipelines, selected_pipeline.
    """
    return json.dumps({
        "nodes": [
            {"id": "%08x" % (index + 0x6ab908b8), "name": name, "tags": [],
             "pipelines": list(pipelines), "type": "task",
             "modular_pipelines": ["data_science"], "node_extras": None,
             "parameters": {"test_size": 0.2},
             "full_name": "data_science.%s" % name}
            for index, name in enumerate(node_names)
        ],
        "edges": [{"source": "d7b83b05", "target": "6ab908b8"}],
        "layers": ["primary"],
        "tags": [{"id": "nightly", "name": "nightly"}],
        "pipelines": [{"id": name, "name": name} for name in pipelines],
        "modular_pipelines": {
            "__root__": {"id": "__root__", "name": "Root", "inputs": [],
                         "outputs": [], "children": [
                             {"id": "data_science", "type": "modularPipeline"}]},
        },
        "selected_pipeline": pipelines[0],
    }, separators=(",", ":"))


KEDRO_VIZ_METADATA_BODY = kedro_viz_metadata_body(("fsspec", "2024.6.1", True))
KEDRO_VIZ_MAIN_BODY = kedro_viz_main_body("split_data_node", "train_model_node")

# Une instance lancée en mode lite : le drapeau bascule, et c'est une instance
# exposée comme une autre.
KEDRO_VIZ_LITE_METADATA_BODY = kedro_viz_metadata_body(
    ("fsspec", "0.0.0", False), has_missing_dependencies=True)

# Les versions qui déclaraient deux paquets dans PACKAGE_REQUIREMENTS — la forme
# que le json_schema_extra du modèle montre encore.
KEDRO_VIZ_TWO_PACKAGES_METADATA_BODY = kedro_viz_metadata_body(
    ("fsspec", "2024.6.1", True), ("kedro-datasets", "4.0.0", True))

# La liste de compatibilité vide : les deux noms de champ sont là, mais le
# triplet qui nomme le produit n'y est pas.
KEDRO_VIZ_NO_PACKAGE_METADATA_BODY = kedro_viz_metadata_body()

# Un projet dont le pipeline sélectionné ne porte aucun nœud : la route répond,
# mais il n'y a pas de graphe à divulguer.
KEDRO_VIZ_EMPTY_GRAPH_BODY = kedro_viz_main_body()

# Ce qu'un FastAPI rend sur un chemin qu'il ne sert pas — donc ce que rendent le
# site statique de « kedro viz build » et l'instance --load-file sur
# /api/metadata, qu'aucun des deux ne déclare.
KEDRO_VIZ_NOT_FOUND_BODY = '{"detail":"Not Found"}'

# La seule branche d'échec de la route : le handler journalise puis rend ce
# corps sous un 500.
KEDRO_VIZ_METADATA_FAILURE_BODY = '{"message":"Failed to get app metadata"}'

# Ce qu'un proxy placé devant l'instance rend quand il authentifie le préfixe.
KEDRO_VIZ_PROXY_UNAUTHORIZED_BODY = (
    '<html><head><title>401 Authorization Required</title></head>'
    '<body><center><h1>401 Authorization Required</h1></center></body></html>'
)

# Le catch-all de l'interface : sur un chemin qu'il ne sert pas, le serveur rend
# index.html en 200 plutôt qu'un 404.
KEDRO_VIZ_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Kedro-Viz</title></head>'
    '<body><div id="root"></div></body></html>'
)

# Un tableau de supervision qui agrège les deux réponses sous une clé à lui : les
# charges utiles y sont entières, mais ce n'est pas l'instance qui a répondu.
KEDRO_VIZ_COMPOSITE_METADATA_BODY = (
    '{"kedro_viz":%s,"checked_at":0}' % KEDRO_VIZ_METADATA_BODY)
KEDRO_VIZ_COMPOSITE_MAIN_BODY = (
    '{"kedro_viz":%s,"checked_at":0}' % KEDRO_VIZ_MAIN_BODY)

# Une autre API de graphe, qui rend elle aussi des nœuds et des arêtes : c'est la
# forme la plus banale du web, et ce sont modular_pipelines et selected_pipeline
# qui l'en séparent.
KEDRO_VIZ_OTHER_GRAPH_BODY = (
    '{"nodes":[{"id":"n1","name":"extract","type":"task"},'
    '{"id":"n2","name":"load","type":"task"}],'
    '"edges":[{"source":"n1","target":"n2"}],"layers":[],"tags":[]}'
)

# Le pire de ce genre : une réponse qui satisfait tout ce que le template attend
# de /api/main sauf un champ. Chacune isole l'expression qui la refuse — sans
# quoi l'une des deux pourrait tomber du template sans que rien ne le dise.
# Celle qui perd l'arbre garde le modular_pipelines de ses nœuds, qui est une
# liste : c'est l'accolade, et elle seule, qui vise le champ de premier niveau.
KEDRO_VIZ_GRAPH_WITHOUT_TREE_BODY = json.dumps(
    {key: value for key, value in json.loads(KEDRO_VIZ_MAIN_BODY).items()
     if key != "modular_pipelines"}, separators=(",", ":"))
KEDRO_VIZ_GRAPH_WITHOUT_SELECTION_BODY = json.dumps(
    {key: value for key, value in json.loads(KEDRO_VIZ_MAIN_BODY).items()
     if key != "selected_pipeline"}, separators=(",", ":"))

# La même réponse, mais dont modular_pipelines n'est que le champ de nœud — une
# liste, pas l'arbre de premier niveau.
KEDRO_VIZ_NODE_LEVEL_MODULAR_BODY = (
    '{"nodes":[{"id":"6ab908b8","name":"split_data_node","tags":[],'
    '"pipelines":["__default__"],"type":"task","modular_pipelines":'
    '["data_science"]}],"edges":[],"layers":[],"tags":[],'
    '"pipelines":[{"id":"__default__","name":"__default__"}],'
    '"selected_pipeline":"__default__"}'
)


def kedro_viz_block():
    doc = load(KEDRO_VIZ_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/metadata" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /api/metadata — c'est pourtant la seule "
        "route que save_api_responses_to_fs() n'écrit pas et que "
        "create_api_app_from_file() ne déclare pas, donc la seule qui distingue "
        "un serveur qui lit le projet à chaud d'un site statique publié"
    )
    return blocks[0]


def kedro_viz_responses(metadata_status=200, metadata_body=KEDRO_VIZ_METADATA_BODY,
                        main_status=200, main_body=KEDRO_VIZ_MAIN_BODY):
    """
    Range les réponses dans l'ordre des chemins déclarés par le template : c'est
    cet ordre qui donne son numéro à chaque body_N sous req-condition.
    """
    ordered = []
    for path in kedro_viz_block().get("path") or []:
        route = path.replace("{{BaseURL}}", "")
        if route == "/api/metadata":
            ordered.append((metadata_status, metadata_body))
        elif route == "/api/main":
            ordered.append((main_status, main_body))
        else:
            raise AssertionError(f"le template interroge un chemin inattendu : {route}")
    return ordered


def kedro_viz_fires(**kwargs):
    block = kedro_viz_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = kedro_viz_responses(**kwargs)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_kedro_viz_probe_reads_the_graph_and_never_deploys_nor_opens_a_node():
    doc = load(KEDRO_VIZ_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'inventaire se lit en GET : la seule route de l'arbre qui écrive "
            "quoi que ce soit est POST /api/deploy, et le routeur nu la sert à "
            "l'anonyme comme le reste"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/deploy", "POST /api/deploy appelle "
                            "DeployerFactory.create_deployer(...).deploy(...) et "
                            "ferait écrire le site dans un compartiment nommé "
                            "par l'appelant, avec les identifiants cloud de "
                            "l'hôte"),
                ("/nodes", "GET /api/nodes/{node_id} rend le code du nœud, le "
                           "chemin du fichier sur la machine, les paramètres et "
                           "un aperçu du jeu de données — c'est ce que le "
                           "constat protège, pas ce qui l'établit"),
                ("/run-status", "GET /api/run-status rend les erreurs et les "
                                "horodatages de la dernière exécution du projet"),
                ("/pipelines", "GET /api/pipelines/{registered_pipeline_id} "
                               "redit le graphe que /api/main donne déjà, "
                               "pipeline par pipeline"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = kedro_viz_block().get("path") or []
    assert paths == ["{{BaseURL}}/api/metadata", "{{BaseURL}}/api/main"], (
        "le constat tient à deux lectures, sur les chemins nus et dans cet "
        "ordre : le préfixe « /api » est écrit dans l'APIRouter et chaque route "
        "dans son décorateur, et la signature du produit doit précéder le "
        f"graphe qu'elle qualifie — {paths}"
    )


def test_kedro_viz_matcher_needs_the_graph_not_just_the_metadata_pair():
    block = kedro_viz_block()
    assert block.get("req-condition") is True, (
        "sans req-condition les deux réponses ne partagent pas d'espace de "
        "noms : la signature de /api/metadata conclurait seule, or elle nomme "
        "le produit sans dire que le graphe sort"
    )

    assert kedro_viz_fires(), (
        "le template ne reconnaît pas une instance dont /api/main rend le "
        "graphe du projet à l'anonyme"
    )
    assert kedro_viz_fires(metadata_body=KEDRO_VIZ_LITE_METADATA_BODY), (
        "le template exige has_missing_dependencies faux : une instance lancée "
        "en mode lite le met à vrai et reste exposée au même titre"
    )
    assert kedro_viz_fires(metadata_body=KEDRO_VIZ_TWO_PACKAGES_METADATA_BODY), (
        "le template contraint le nombre d'entrées de package_compatibilities, "
        "qui est celui de PACKAGE_REQUIREMENTS et a déjà changé d'une version "
        "à l'autre"
    )
    assert kedro_viz_fires(main_body=kedro_viz_main_body("split_data_node")), (
        "le template exige plusieurs nœuds : un projet qui n'en porte qu'un "
        "sert le même /api/nodes/{node_id} sans rien demander"
    )
    assert kedro_viz_fires(
        metadata_body=json.dumps(json.loads(KEDRO_VIZ_METADATA_BODY), indent=2),
        main_body=json.dumps(json.loads(KEDRO_VIZ_MAIN_BODY), indent=2)), (
        "le template exige la sérialisation compacte d'ORJSONResponse : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer l'instance"
    )

    # La frontière du constat : le site statique et l'instance --load-file
    # servent /api/main, mais aucun des deux ne déclare /api/metadata.
    assert not kedro_viz_fires(metadata_status=404,
                               metadata_body=KEDRO_VIZ_NOT_FOUND_BODY), (
        "le template déclenche sur un site produit par « kedro viz build » ou "
        "sur une instance --load-file : ni save_api_responses_to_fs() ni "
        "create_api_app_from_file() ne servent /api/metadata, et une "
        "publication choisie qui ne porte ni POST /api/deploy ni la lecture du "
        "projet à chaud n'est pas le constat"
    )
    assert not kedro_viz_fires(metadata_status=500,
                               metadata_body=KEDRO_VIZ_METADATA_FAILURE_BODY), (
        "le template déclenche sur la branche d'échec du handler, qui ne rend "
        "ni le drapeau ni la liste de compatibilité"
    )
    assert not kedro_viz_fires(metadata_status=401,
                               metadata_body=KEDRO_VIZ_PROXY_UNAUTHORIZED_BODY,
                               main_status=401,
                               main_body=KEDRO_VIZ_PROXY_UNAUTHORIZED_BODY), (
        "le template déclenche sur une instance placée derrière un proxy qui "
        "authentifie le préfixe /api"
    )
    assert not kedro_viz_fires(main_status=401,
                               main_body=KEDRO_VIZ_PROXY_UNAUTHORIZED_BODY), (
        "le template conclut alors que le plan de données ne répond plus : "
        "c'est /api/main qui porte la preuve, pas la signature du produit"
    )
    assert not kedro_viz_fires(metadata_body=KEDRO_VIZ_SPA_BODY,
                               main_body=KEDRO_VIZ_SPA_BODY), (
        "le template déclenche sur la page d'accueil qu'un catch-all rend en "
        "200 sur un chemin qu'il ne connaît pas"
    )
    # Le document composite, et une réponse à la fois : les deux corps ont leur
    # ancrage, et les éprouver ensemble laisserait l'un des deux tomber sans que
    # rien ne le dise.
    assert not kedro_viz_fires(metadata_body=KEDRO_VIZ_COMPOSITE_METADATA_BODY), (
        "le template retrouve la signature entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture de /api/metadata qui dit "
        "que l'instance a répondu d'elle-même, et non une supervision qui "
        "agrégerait sa réponse sous une clé à elle"
    )
    assert not kedro_viz_fires(main_body=KEDRO_VIZ_COMPOSITE_MAIN_BODY), (
        "le template retrouve le graphe entier au fond d'un document composite : "
        "c'est l'ancrage sur l'ouverture de /api/main qui dit que l'instance a "
        "répondu d'elle-même"
    )

    # Le graphe vide : la route répond, mais il n'y a rien à divulguer.
    assert not kedro_viz_fires(main_body=KEDRO_VIZ_EMPTY_GRAPH_BODY), (
        "le template déclenche sur « {\"nodes\":[], … } » : un projet dont le "
        "pipeline sélectionné ne porte aucun nœud ne livre ni nom de fonction, "
        "ni jeu de données, ni chemin de machine"
    )

    # La liste de compatibilité vide : les deux noms de champ ne suffisent pas.
    assert not kedro_viz_fires(metadata_body=KEDRO_VIZ_NO_PACKAGE_METADATA_BODY), (
        "le template conclut sur les seuls noms has_missing_dependencies et "
        "package_compatibilities : c'est le triplet package_name / "
        "package_version / is_compatible qui nomme le produit, et "
        "get_package_compatibilities() en rend toujours au moins un"
    )

    # Une autre API de graphe : nœuds et arêtes sont la forme la plus banale du
    # web, et ce sont les deux champs propres à Kedro qui l'en séparent.
    assert not kedro_viz_fires(main_body=KEDRO_VIZ_OTHER_GRAPH_BODY), (
        "le template déclenche sur n'importe quelle API qui rend des nœuds et "
        "des arêtes : modular_pipelines et selected_pipeline sont ce qui "
        "désigne GraphAPIResponse"
    )
    assert not kedro_viz_fires(main_body=KEDRO_VIZ_NODE_LEVEL_MODULAR_BODY), (
        "le template accepte le modular_pipelines d'une entrée de nodes, qui "
        "est une liste : le champ de premier niveau est l'arbre "
        "ModularPipelinesTreeAPIResponse, donc un dictionnaire, et c'est lui "
        "que l'accolade vise"
    )
    assert not kedro_viz_fires(main_body=KEDRO_VIZ_GRAPH_WITHOUT_TREE_BODY), (
        "le template n'exige plus l'arbre des pipelines modulaires — la notion "
        "propre à Kedro — et se contente alors des nœuds, des arêtes et d'un "
        "champ de sélection, que n'importe quelle API de graphe peut rendre"
    )
    assert not kedro_viz_fires(main_body=KEDRO_VIZ_GRAPH_WITHOUT_SELECTION_BODY), (
        "le template n'exige plus selected_pipeline, le dernier champ de "
        "GraphAPIResponse et celui qui nomme le pipeline servi : sans lui la "
        "signature du graphe tient au seul mot modular_pipelines"
    )

    # Collisions internes au pack : aucun des autres services couverts ne doit
    # être revendiqué par celui-ci, à commencer par les ordonnanceurs voisins.
    for other_body, other_name in (
        (DAGSTER_INFO_BODY, "dagster"),
        (HAYHOOKS_STATUS_BODY, "hayhooks"),
        (TEI_INFO_BODY, "text-embeddings-inference"),
        (INFINITY_MODELS_BODY, "infinity"),
        (MARQO_INDEXES_BODY, "marqo"),
    ):
        assert not kedro_viz_fires(metadata_body=other_body, main_body=other_body), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_kedro_viz_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    /api/main n'a pas de branche d'échec — il rend GraphAPIResponse, que FastAPI
    ne peut sortir que sous un 200 — et /api/metadata n'en a qu'une, qui rend
    « {"message":"Failed to get app metadata"} » et que les corps écartent déjà.
    Exiger le 200 n'écarterait donc rien de plus, et ferait manquer l'instance
    dont un intermédiaire réécrit le statut.
    """
    block = kedro_viz_block()

    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : les deux handlers ne rendent leur "
        "charge utile que sous un 200, donc ce matcher n'écarte rien et "
        "n'ajoute qu'un risque de silence"
    )

    written = "\n".join(expr for m in (block.get("matchers") or [])
                        if m.get("type") == "dsl"
                        for expr in (m.get("dsl") or []))
    assert "status_code_" not in written, (
        "une expression dsl porte le statut : le constat doit tenir aux deux "
        "charges utiles, pas au code de réponse"
    )

    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "dsl":
            assert matcher.get("condition") == "and", (
                "les expressions doivent toutes devoir passer : la signature "
                "nomme sans constater, le graphe constate sans nommer, et "
                "aucune des deux ne conclut seule"
            )

    # Le template ne conclut toujours pas quand la preuve manque, quel que soit
    # le statut que l'intermédiaire renvoie.
    assert not kedro_viz_fires(main_status=200,
                               main_body=KEDRO_VIZ_PROXY_UNAUTHORIZED_BODY), (
        "un proxy qui rend sa page de refus en 200 suffit à faire conclure le "
        "template : c'est le corps de /api/main qui porte la preuve"
    )
    assert not kedro_viz_fires(metadata_status=200,
                               metadata_body=KEDRO_VIZ_NOT_FOUND_BODY), (
        "un site statique dont le serveur rend son 404 en 200 fait conclure le "
        "template : c'est le corps de /api/metadata qui distingue le serveur "
        "vivant de la publication"
    )


def test_kedro_viz_extractor_reports_the_registered_pipelines():
    block = kedro_viz_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement borné qui vaille d'être "
        f"remonté — les pipelines enregistrés du projet — et {len(extractors)} "
        "extracteurs feraient remonter autant de fois la même instance sous "
        "req-condition. Les versions de paquets de /api/metadata sont celles de "
        "l'environnement, pas celles du projet ; elles ne font pas le constat"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en charger"
    )
    assert extractor.get("part") == "body_2", (
        "l'extracteur n'est pas borné à la réponse de /api/main : sous "
        "req-condition le moteur l'évalue contre chaque réponse, et "
        "/api/metadata n'a pas de pipeline à donner"
    )
    assert extractor.get("json") == [".pipelines[].id"], (
        "l'extracteur ne parcourt pas .pipelines[].id — ce sont pourtant les "
        "noms que l'exploitant a enregistrés, et le {registered_pipeline_id} "
        "que réclame ensuite GET /api/pipelines/{registered_pipeline_id} ; "
        "s'arrêter à .selected_pipeline tairait les autres pipelines du projet"
    )


# --------------------------------------------------------------------------
# Tabby est le cas où l'authentification existe, mais au-dessus du routeur qui
# porte la route. api_router() (crates/tabby/src/serve.rs) enregistre
# « /v1/health » deux fois — POST puis GET, sur le même Arc<HealthState> — sans
# aucun Depends, et run_app() n'ajoute par-dessus que CorsLayer::permissive(), la
# couche Prometheus et /metrics. Ce qui ferme, quand c'est fermé, est
# routes::create() (ee/tabby-webserver/src/routes/mod.rs) : il enveloppe le
# routeur d'API dans distributed_tabby_layer, dont authorize_request() rend
# (false, None) sur tout chemin en « /v1/ » ou « /v1beta/ » présenté sans jeton
# porteur — le dispatcheur répond alors un 401 au corps vide, ce que rend
# l'instance de démonstration du produit.
#
# Cette couche n'est absente que dans trois cas : le drapeau caché
# « --no-webserver », une construction sans la fonctionnalité « ee »
# (« default = ["ee", …] » dans crates/tabby/Cargo.toml), et les versions
# antérieures à la 0.11, où le serveur web se demandait au lieu de se retirer. Le
# template n'a donc pas à établir que l'instance est ouverte : la charge utile
# n'existe que là où elle l'est, et le corps du refus est vide. Sa difficulté est
# ailleurs — reconnaître cet inventaire sur les trois formes que dix versions lui
# ont données, sans le confondre avec une sonde GPU ou un point de version
# quelconque.

TABBY_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "tabby-health-exposed.yaml")


def tabby_version(describe="v0.32.0"):
    """
    La structure Version : build_date, build_timestamp, git_sha, git_describe,
    dans cet ordre depuis la 0.7. git_describe vient de
    « .git_describe(false, true, None) » dans build.rs, donc le tag.
    """
    return {"build_date": "2026-01-25",
            "build_timestamp": "2026-01-25T17:02:11.000000000Z",
            "git_sha": "3f0a1c9e0f5b4d2a8c7e6b5a4938271605f4e3d2",
            "git_describe": describe}


def tabby_local_model(model_id, device, cuda_devices):
    """
    ModelHealth::Local, dont l'enum est étiqueté par l'extérieur
    (#[serde(rename = "local")]) et dont cuda_devices porte
    skip_serializing_if = "Vec::is_empty".
    """
    local = {"model_id": model_id, "device": device}
    if cuda_devices:
        local["cuda_devices"] = list(cuda_devices)
    return {"local": local}


def tabby_health_body(device="cuda", cuda_devices=("NVIDIA GeForce RTX 4090",),
                      webserver=False, describe="v0.32.0"):
    """
    La charge utile depuis la 0.32, telle que Json<HealthState> la sérialise :
    compacte, et dans l'ordre de déclaration de la structure — model, chat_model,
    chat_device, device, cuda_devices, models, arch, cpu_info, cpu_count,
    version, webserver.
    """
    cuda = list(cuda_devices)
    return json.dumps({
        "model": "StarCoder-1B",
        "chat_model": "Qwen2-1.5B-Instruct",
        "chat_device": device,
        "device": device,
        "cuda_devices": cuda,
        "models": {
            "completion": tabby_local_model("StarCoder-1B", device, cuda),
            "chat": tabby_local_model("Qwen2-1.5B-Instruct", device, cuda),
            "embedding": tabby_local_model("Nomic-Embed-Text", device, cuda),
        },
        "arch": "x86_64",
        "cpu_info": "AMD EPYC 7502P 32-Core Processor",
        "cpu_count": 64,
        "version": tabby_version(describe),
        "webserver": webserver,
    }, separators=(",", ":"))


def tabby_health_body_0_23(device="cuda", cuda_devices=("Tesla T4",),
                           webserver=False):
    """
    La charge utile de la 0.13 à la 0.31 : pas de sous-objet models, et
    cuda_devices déclaré après cpu_count et non avant arch. C'est cette
    permutation qui interdit au template de s'appuyer sur la position du champ.
    """
    return json.dumps({
        "model": "TabbyML/StarCoder-1B",
        "chat_model": "TabbyML/Mistral-7B",
        "chat_device": device,
        "device": device,
        "arch": "x86_64",
        "cpu_info": "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
        "cpu_count": 28,
        "cuda_devices": list(cuda_devices),
        "version": tabby_version("v0.23.0"),
        "webserver": webserver,
    }, separators=(",", ":"))


def tabby_health_body_0_10():
    """
    La charge utile jusqu'à la 0.10 — ni chat_device, ni webserver, ni models —,
    c'est-à-dire l'époque où « --webserver » était un opt-in caché et faux par
    défaut : la route répondait alors à l'anonyme sur une instance par défaut.
    """
    return json.dumps({
        "model": "TabbyML/StarCoder-1B",
        "device": "cuda",
        "arch": "x86_64",
        "cpu_info": "AMD Ryzen 9 5950X 16-Core Processor",
        "cpu_count": 32,
        "cuda_devices": ["NVIDIA GeForce RTX 3090"],
        "version": tabby_version("v0.10.0"),
    }, separators=(",", ":"))


TABBY_HEALTH_BODY = tabby_health_body()

# Un hôte sans NVML — un Mac, un conteneur lancé sans --gpus : read_cuda_devices()
# échoue et cuda_devices vaut « [] », que le Vec de premier niveau écrit tout de
# même puisqu'il n'a pas de skip_serializing_if. L'instance est exposée au même
# titre, et c'est même la plus banale.
TABBY_CPU_ONLY_BODY = tabby_health_body(device="cpu", cuda_devices=())

# Une instance sans modèle de complétion : model, chat_model, chat_device et
# models.completion disparaissent tous, et le premier champ du document devient
# device — le premier que HealthState déclare sans skip_serializing_if.
# webserver y vaut null, ce qu'écrit une construction sans la fonctionnalité
# « ee ».
TABBY_EMBEDDING_ONLY_BODY = json.dumps({
    "device": "cpu",
    "cuda_devices": [],
    "models": {"embedding": tabby_local_model("Nomic-Embed-Text", "cpu", ())},
    "arch": "aarch64",
    "cpu_info": "Apple M2 Pro",
    "cpu_count": 12,
    "version": tabby_version(),
    "webserver": None,
}, separators=(",", ":"))

# Un modèle servi par un fournisseur distant : RemoteModelHealth rend kind,
# model_name et api_endpoint, donc l'URL interne que l'exploitant a configurée.
TABBY_REMOTE_MODEL_BODY = json.dumps({
    **json.loads(TABBY_HEALTH_BODY),
    "model": "qwen2.5-coder",
    "models": {
        "completion": {"remote": {"kind": "openai/completion",
                                  "model_name": "qwen2.5-coder",
                                  "api_endpoint": "http://vllm.internal.corp:8000/v1"}},
        "embedding": {"remote": {"kind": "openai/embedding",
                                 "model_name": "bge-m3",
                                 "api_endpoint": "http://tei.internal.corp:8080"}},
    },
}, separators=(",", ":"))

# Le refus de la couche, tel que l'instance de démonstration du produit le rend
# (vérifié le 2026-08-23) : distributed_tabby_layer construit sa réponse avec
# Body::empty(), donc un 401 sans un octet de corps.
TABBY_UNAUTHORIZED_BODY = ""

# Le refus d'un proxy placé devant l'instance pour fermer ce que « --no-webserver »
# a ouvert.
TABBY_PROXY_DENIED_BODY = (
    '<html><head><title>401 Authorization Required</title></head>'
    '<body><center><h1>401 Authorization Required</h1></center></body></html>'
)

# L'interface servie sur le même port : le routeur d'UI a pour repli une
# redirection vers /swagger-ui, et un proxy peut rendre l'index en 200 sur un
# chemin qu'il ne connaît pas.
TABBY_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Tabby</title></head>'
    '<body><div id="__next"></div></body></html>'
)

# Une supervision qui agrège la charge utile entière sous une clé à elle : tout y
# est, mais ce n'est pas l'instance qui a répondu.
TABBY_COMPOSITE_BODY = '{"tabby":%s,"checked_at":0}' % TABBY_HEALTH_BODY

# Un autre service Rust qui publie le quatuor vergen sous la même clé « version » :
# c'est la sortie canonique de EmitBuilder::all_git(), donc la partie du document
# que Tabby partage avec n'importe qui, et elle ne nomme rien à elle seule.
TABBY_OTHER_VERGEN_BODY = json.dumps({
    "service": "billing-api", "status": "ok", "version": tabby_version("v1.4.2"),
}, separators=(",", ":"))

# Le pire de ce genre : la charge utile de Tabby privée d'un seul de ses trois
# ancrages. Chacune isole l'expression qui la refuse — sans quoi l'une d'elles
# pourrait tomber du template sans que rien ne le dise. Celle qui perd
# l'inventaire GPU part de la forme 0.23 : depuis la 0.32, chaque
# LocalModelHealth du sous-objet models porte à son tour un cuda_devices, et
# retirer le seul champ de premier niveau ne retirerait pas le nom du document.
TABBY_WITHOUT_CPU_BODY = json.dumps(
    {key: value for key, value in json.loads(TABBY_HEALTH_BODY).items()
     if key not in ("cpu_info", "cpu_count")}, separators=(",", ":"))
TABBY_WITHOUT_CUDA_BODY = json.dumps(
    {key: value for key, value in json.loads(tabby_health_body_0_23()).items()
     if key != "cuda_devices"}, separators=(",", ":"))
TABBY_PARTIAL_VERSION_BODY = json.dumps(
    {**json.loads(TABBY_HEALTH_BODY),
     "version": {"git_describe": "v0.32.0"}}, separators=(",", ":"))


def tabby_health_block():
    doc = load(TABBY_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v1/health" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /v1/health"
    return blocks[0]


def tabby_fires(status=200, body=TABBY_HEALTH_BODY):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint.
    """
    block = tabby_health_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_tabby_probe_reads_the_inventory_and_never_asks_the_instance_to_infer():
    doc = load(TABBY_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "l'inventaire se lit en GET : la route est certes enregistrée aussi "
            "en POST, sur le même Arc<HealthState> et avec le même handler, mais "
            "le même routeur nu porte POST /v1/completions et POST /v1/events — "
            "un template ne doit pas prendre l'habitude d'écrire vers une "
            "instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/completions", "POST /v1/completions et POST "
                                 "/v1/chat/completions feraient tourner le "
                                 "modèle sur le GPU de l'exploitant — c'est "
                                 "l'abus que le constat signale, pas ce qui "
                                 "l'établit"),
                ("/events", "POST /v1/events écrirait dans le journal "
                            "d'événements de l'instance auditée"),
                ("/v1beta/models", "GET /v1beta/models décrit le registre des "
                                   "modèles téléchargeables, pas l'instance"),
                ("/metrics", "/metrics est ajouté par run_app() en dehors des "
                             "préfixes que authorize_request() regarde : il "
                             "répond même quand le serveur web est actif, donc "
                             "il ne dit rien de l'ouverture"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = tabby_health_block().get("path") or []
    assert paths == ["{{BaseURL}}/v1/health"], (
        "le constat tient à une seule lecture, sur le chemin nu : le handler "
        "rend Json(state.as_ref().clone()) sans lire ni paramètre ni en-tête, "
        f"donc rien d'autre n'apprendrait quoi que ce soit — {paths}"
    )


def test_tabby_matcher_needs_the_host_inventory_not_any_build_info():
    block = tabby_health_block()
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer : le quatuor de version est "
        "celui de vergen et ne nomme personne, l'inventaire matériel ne date "
        "rien, et aucun des deux ne conclut seul"
    )

    assert tabby_fires(), (
        "le template ne reconnaît pas une instance dont /v1/health rend "
        "l'inventaire de la machine d'inférence à l'anonyme"
    )
    assert tabby_fires(body=tabby_health_body_0_23()), (
        "le template dépend de la place de cuda_devices, qui suivait cpu_count "
        "jusqu'à la 0.31 et précède models depuis la 0.32 : ces instances-là "
        "sont exactement aussi ouvertes"
    )
    assert tabby_fires(body=tabby_health_body_0_10()), (
        "le template exige un champ que les versions antérieures à la 0.11 "
        "n'écrivaient pas — chat_device, webserver ou models — alors que ce "
        "sont celles où le serveur web était un opt-in caché, donc celles qui "
        "répondaient à l'anonyme sans qu'on ait rien retiré"
    )
    assert tabby_fires(body=TABBY_CPU_ONLY_BODY), (
        "le template exige une carte dans cuda_devices : read_cuda_devices() "
        "rend un tableau vide dès que NVML n'est pas là — un Mac, un conteneur "
        "sans --gpus — et l'instance est exposée au même titre"
    )
    assert tabby_fires(body=TABBY_EMBEDDING_ONLY_BODY), (
        "le template s'ancre sur model : les trois premiers champs de "
        "HealthState portent skip_serializing_if, donc une instance sans modèle "
        "de complétion ouvre son document sur device"
    )
    assert tabby_fires(body=TABBY_REMOTE_MODEL_BODY), (
        "le template suppose des modèles locaux : sur un fournisseur distant, "
        "models porte des RemoteModelHealth — et c'est là que se lit "
        "l'api_endpoint interne de l'exploitant"
    )
    assert tabby_fires(body=tabby_health_body(webserver=None)), (
        "le template exige « webserver »: false : une construction sans la "
        "fonctionnalité « ee » passe None, donc null, et c'est justement une "
        "instance dont le routeur n'a aucune couche"
    )
    assert tabby_fires(body=json.dumps(json.loads(TABBY_HEALTH_BODY), indent=2)), (
        "le template exige la sérialisation compacte de Json<HealthState> : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer l'instance"
    )

    # Le refus, sous ses deux formes : la couche du produit et le proxy qu'on
    # place devant elle.
    assert not tabby_fires(body=TABBY_UNAUTHORIZED_BODY), (
        "le template conclut sur le corps vide que distributed_tabby_layer "
        "renvoie — Body::empty() sous un 401 — alors que c'est exactement la "
        "réponse d'une instance dont la couche de comptes est en place"
    )
    assert not tabby_fires(body=TABBY_PROXY_DENIED_BODY), (
        "le template signale une instance dont un proxy refuse déjà /v1/ à "
        "l'anonyme"
    )
    assert not tabby_fires(body=TABBY_SPA_BODY), (
        "le template déclenche sur l'interface rendue en 200 par un catch-all "
        "sur un chemin qu'il ne connaît pas"
    )
    assert not tabby_fires(body=TABBY_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture du corps qui dit que "
        "l'instance a répondu d'elle-même, et non une supervision qui "
        "agrégerait sa réponse sous une clé à elle"
    )

    # Les trois ancrages, isolés un à un.
    assert not tabby_fires(body=TABBY_OTHER_VERGEN_BODY), (
        "le template conclut sur le seul quatuor vergen — build_date, "
        "build_timestamp, git_sha, git_describe —, que publie n'importe quel "
        "projet Rust bâti avec EmitBuilder::all_git()"
    )
    assert not tabby_fires(body=TABBY_WITHOUT_CPU_BODY), (
        "le template n'exige plus le couple cpu_info / cpu_count, que "
        "read_cpu_info() écrit adjacent depuis la 0.7 et qui est ce qui nomme "
        "la machine d'inférence"
    )
    assert not tabby_fires(body=TABBY_WITHOUT_CUDA_BODY), (
        "le template n'exige plus cuda_devices, le champ que NVML remplit et "
        "que HealthState écrit toujours puisque son Vec n'a pas de "
        "skip_serializing_if"
    )
    assert not tabby_fires(body=TABBY_PARTIAL_VERSION_BODY), (
        "le template se contente d'un objet version qui porte git_describe : "
        "c'est le quatuor entier, dans son ordre, qui distingue la structure "
        "Version d'un champ de version quelconque"
    )

    # Collisions : les produits du pack qui décrivent eux aussi un hôte GPU, et
    # la sonde générique qui emploie le même vocabulaire sans être personne.
    for other_body, other_name in (
        (COMFYUI_SYSTEM_STATS_BODY, "comfyui"),
        (OTHER_GPU_STATS_BODY, "une sonde de supervision GPU"),
        (LLAMACPP_PROPS_BODY, "llama.cpp"),
        (TEI_INFO_BODY, "text-embeddings-inference"),
        (LANGFUSE_HEALTH_BODY, "langfuse"),
    ):
        assert not tabby_fires(body=other_body), (
            f"le template déclenche sur {other_name}, qui décrit lui aussi un "
            "hôte ou une version sans être Tabby"
        )


def test_tabby_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    Le handler n'a pas de branche d'échec — « Json(state.as_ref().clone()) », donc
    un 200 —, et le refus de la couche est un 401 au corps vide que les
    expressions écartent déjà. Exiger le 200 n'écarterait donc rien de plus, et
    ferait manquer l'instance dont un intermédiaire réécrit le statut.
    """
    block = tabby_health_block()

    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : le handler ne rend sa charge "
        "utile que sous un 200, donc ce matcher n'écarte rien et n'ajoute qu'un "
        "risque de silence"
    )

    assert tabby_fires(status=503), (
        "le template dépend du statut alors qu'aucun matcher n'est censé le "
        "lire : la charge utile suffit, quel que soit le code qu'un "
        "intermédiaire pose devant"
    )
    assert not tabby_fires(status=200, body=TABBY_UNAUTHORIZED_BODY), (
        "un 200 au corps vide fait conclure le template : c'est le corps qui "
        "porte la preuve, et le refus de la couche n'en a pas"
    )
    assert not tabby_fires(status=200, body=TABBY_PROXY_DENIED_BODY), (
        "un proxy qui rend sa page de refus en 200 suffit à faire conclure le "
        "template"
    )


def test_tabby_extractors_report_the_build_the_gpus_and_the_account_layer():
    block = tabby_health_block()
    extractors = block.get("extractors") or []

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
            f"charger — {extractor.get('name')!r}"
        )
        assert extractor.get("part") in (None, "body"), (
            "le bloc n'a qu'une requête et un seul corps à lire — "
            f"part={extractor.get('part')!r}"
        )

    found = {e.get("name"): e.get("json") for e in extractors}
    assert found == {
        "version": [".version.git_describe"],
        "gpu": [".cuda_devices[]"],
        "webserver": [".webserver"],
    }, (
        "les trois renseignements du constat ne sont pas remontés tels quels — "
        f"{found}. git_describe date l'instance au tag, là où git_sha dirait la "
        "même chose sans être lisible ; .cuda_devices[] nomme les cartes qu'un "
        "appelant anonyme peut faire travailler par POST /v1/completions, et "
        "s'arrêter à .cuda_devices[0] tairait les autres ; .webserver dit si la "
        "couche de comptes existe, et c'est le champ qui explique pourquoi le "
        "document a pu être servi"
    )


# --------------------------------------------------------------------------
# Chainlit est le cas où l'authentification n'existe pas tant que l'application
# ne la déclare pas. get_current_user() ouvre sur « if not require_login():
# return None » (backend/chainlit/auth/__init__.py), et require_login() n'est
# vrai que sous CHAINLIT_CUSTOM_AUTH, un password_auth_callback, un
# header_auth_callback, ou un oauth_callback pourvu d'un fournisseur configuré.
# Le handler project_settings (backend/chainlit/server.py) porte donc
# « current_user: UserParam » sans que cela ferme quoi que ce soit : la
# dépendance rend None, et la configuration entière de l'application sort.
#
# La difficulté du template est de calendrier. Les clés que la réponse porte
# aujourd'hui ne sont pas celles qu'elle portait hier : maskUserEnv et
# threadSharing datent de la 2.8, starterCategories de la 2.10, starters et
# debugUrl de la 1.1. Seules ui, features, userEnv, dataPersistence,
# threadResumable, markdown et chatProfiles traversent toutes les versions
# publiées, et ce sont elles qui doivent porter la reconnaissance — sans quoi le
# template serait muet sur les instances anciennes, précisément celles qui
# traînent exposées.

CHAINLIT_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "chainlit-project-settings-exposed.yaml")


def chainlit_ui(name="Assistant Support"):
    """UISettings.model_dump(), tronqué : name est le seul champ obligatoire."""
    return {"name": name, "description": "", "cot": "full",
            "default_theme": "dark", "language": None, "layout": "default",
            "custom_css": None, "custom_js": None, "header_links": None}


def chainlit_features():
    """FeaturesSettings.model_dump(), tronqué de la même façon."""
    return {"spontaneous_file_upload": None,
            "audio": {"enabled": False, "sample_rate": 24000},
            "mcp": {"enabled": False, "sse": {"enabled": True},
                    "stdio": {"enabled": True}},
            "latex": False, "unsafe_allow_html": False, "edit_message": True,
            "allow_thread_sharing": False}


def chainlit_profiles(*names):
    """ChatProfile.to_dict(), config_overrides retiré par le handler lui-même."""
    return [{"name": name, "markdown_description": "", "icon": None,
             "display_name": None, "default": False, "starters": None}
            for name in names]


def chainlit_settings_body(user_env=(), chat_profiles=(),
                           data_persistence=False, thread_resumable=False,
                           name="Assistant Support"):
    """
    La charge utile depuis la 2.10, telle que JSONResponse la sérialise :
    compacte — separators=(",", ":") — et dans l'ordre d'insertion du
    dictionnaire que construit le handler.
    """
    return json.dumps({
        "ui": chainlit_ui(name),
        "features": chainlit_features(),
        "userEnv": list(user_env),
        "maskUserEnv": False,
        "dataPersistence": data_persistence,
        "threadResumable": thread_resumable,
        "threadSharing": False,
        "markdown": None,
        "chatProfiles": chainlit_profiles(*chat_profiles),
        "starters": [],
        "starterCategories": [],
        "debugUrl": None,
    }, separators=(",", ":"))


def chainlit_settings_body_2_6(user_env=None):
    """
    La charge utile de la 1.1 à la 2.7 : ni maskUserEnv, ni threadSharing, ni
    starterCategories. userEnv y vaut null quand aucun config.toml ne pose
    « user_env = [] », ProjectSettings le déclarant Optional[List[str]] = None.
    """
    return json.dumps({
        "ui": chainlit_ui(),
        "features": chainlit_features(),
        "userEnv": user_env,
        "dataPersistence": True,
        "threadResumable": True,
        "markdown": "# Bienvenue",
        "chatProfiles": chainlit_profiles("GPT-4o", "Claude"),
        "starters": [{"label": "Résumer un contrat", "message": "…",
                      "command": None, "icon": None}],
        "debugUrl": None,
    }, separators=(",", ":"))


def chainlit_settings_body_1_0():
    """
    La charge utile jusqu'à la 1.0 : ni starters, ni debugUrl. C'est la forme la
    plus pauvre que la route ait jamais rendue, et elle reste exposée au même
    titre.
    """
    return json.dumps({
        "ui": chainlit_ui("Chatbot"),
        "features": {"unsafe_allow_html": False, "latex": False},
        "userEnv": [],
        "dataPersistence": False,
        "threadResumable": False,
        "markdown": None,
        "chatProfiles": [],
    }, separators=(",", ":"))


CHAINLIT_SETTINGS_BODY = chainlit_settings_body()

# L'instance qui réclame ses clés à l'utilisateur : userEnv nomme alors le
# fournisseur de modèle branché derrière, et load_user_env() refuse la connexion
# websocket tant que les variables ne sont pas toutes fournies.
CHAINLIT_USER_ENV_BODY = chainlit_settings_body(
    user_env=("OPENAI_API_KEY", "TAVILY_API_KEY"),
    chat_profiles=("GPT-4o mini", "o3"), data_persistence=True,
    thread_resumable=True, name="Copilote juridique")

# Le refus de la dépendance quand un rappel d'authentification est déclaré :
# authenticate_user() appelle decode_jwt() sur un jeton absent, l'exception
# remonte en HTTPException(401) et FastAPI n'écrit que le détail.
CHAINLIT_UNAUTHENTICATED_BODY = '{"detail":"Invalid authentication token"}'

# Le refus de Pydantic sur un language hors du motif : même forme, autre cause.
CHAINLIT_UNPROCESSABLE_BODY = (
    '{"detail":[{"type":"string_pattern_mismatch","loc":["query","language"],'
    '"msg":"String should match pattern","input":"fr_FR"}]}'
)

# La coquille de l'interface, servie en 200 par « @router.get("/{full_path:path}") »
# sur n'importe quel chemin — donc aussi sur /project/settings si un
# intermédiaire réécrit la route, et sur toute instance protégée.
CHAINLIT_SPA_BODY = (
    '<!doctype html><html lang="en"><head><title>Chainlit</title>'
    '<meta name="description" content="Chainlit/chainlit"></head>'
    '<body><div id="root"></div></body></html>'
)

# Le refus d'un proxy placé devant l'instance.
CHAINLIT_PROXY_DENIED_BODY = (
    '<html><head><title>401 Authorization Required</title></head>'
    '<body><center><h1>401 Authorization Required</h1></center></body></html>'
)

# Une supervision qui agrège la charge utile entière sous une clé à elle : tout
# y est, mais ce n'est pas l'instance qui a répondu.
CHAINLIT_COMPOSITE_BODY = '{"chainlit":%s,"checked_at":0}' % CHAINLIT_SETTINGS_BODY

# Les trois ancrages du corps, isolés un à un. Chacun retire d'un document par
# ailleurs complet ce que le template est censé exiger — sans quoi l'expression
# correspondante pourrait tomber du template sans que rien ne le dise.
CHAINLIT_WITHOUT_USER_ENV_BODY = json.dumps(
    {key: value for key, value in json.loads(CHAINLIT_SETTINGS_BODY).items()
     if key != "userEnv"}, separators=(",", ":"))
CHAINLIT_WITHOUT_CHAT_PROFILES_BODY = json.dumps(
    {key: value for key, value in json.loads(CHAINLIT_SETTINGS_BODY).items()
     if key != "chatProfiles"}, separators=(",", ":"))
CHAINLIT_SPLIT_COUPLE_BODY = json.dumps(
    {"ui": chainlit_ui(), "userEnv": [], "dataPersistence": False,
     "markdown": None, "threadResumable": False, "chatProfiles": []},
    separators=(",", ":"))


def chainlit_settings_block():
    doc = load(CHAINLIT_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/project/settings" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /project/settings"
    return blocks[0]


def chainlit_fires(status=200, body=CHAINLIT_SETTINGS_BODY):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare, et matchers-condition les joint.
    """
    block = chainlit_settings_block()

    verdicts = []
    for matcher in block.get("matchers") or []:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        else:
            verdicts.append(body_matcher_hits(matcher, body))
    assert verdicts, "bloc sans matcher"

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_chainlit_probe_reads_the_settings_and_never_opens_a_session():
    doc = load(CHAINLIT_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "la configuration se lit en GET : le même routeur porte POST "
            "/project/action, POST /project/file et POST /mcp, et un template "
            "n'a pas à écrire vers une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/socket.io", "le montage websocket est l'endroit où "
                               "on_message fait tourner le modèle configuré — "
                               "c'est l'abus que le constat signale, pas ce "
                               "qui l'établit"),
                ("/project/action", "POST /project/action appellerait un "
                                    "rappel d'action de l'application"),
                ("/project/file", "POST /project/file écrirait dans le "
                                  "répertoire de session de l'instance auditée"),
                ("/mcp", "POST /mcp ferait ouvrir à l'instance une connexion "
                         "vers un serveur MCP choisi par l'appelant"),
                ("/project/threads", "POST /project/threads interrogerait la "
                                     "couche de données pour les conversations "
                                     "conservées"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    paths = chainlit_settings_block().get("path") or []
    assert paths == ["{{BaseURL}}/project/settings"], (
        "le constat tient à une seule lecture, sur le chemin nu : le routeur "
        "est construit par « APIRouter(prefix=config.run.root_path) » et "
        "root_path est vide tant que --root-path n'est pas posé, donc la route "
        f"s'écrit telle qu'elle est déclarée — {paths}"
    )


def test_chainlit_matcher_needs_the_settings_payload_not_any_chat_config():
    block = chainlit_settings_block()
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer : aucune des clés de la "
        "réponse ne nomme le produit à elle seule, et c'est leur réunion dans "
        "un même corps qui conclut"
    )

    assert chainlit_fires(), (
        "le template ne reconnaît pas une instance dont /project/settings rend "
        "sa configuration à l'anonyme"
    )
    assert chainlit_fires(body=CHAINLIT_USER_ENV_BODY), (
        "le template exige un userEnv vide : l'instance qui réclame ses clés à "
        "l'utilisateur est justement celle dont la liste renseigne le plus"
    )
    assert chainlit_fires(body=chainlit_settings_body_2_6()), (
        "le template exige maskUserEnv, threadSharing ou starterCategories, "
        "que la route n'a sérialisés qu'à partir de la 2.8 puis de la 2.10 — "
        "les instances antérieures sont exactement aussi ouvertes"
    )
    assert chainlit_fires(body=chainlit_settings_body_2_6(user_env=[])), (
        "le template ne reconnaît pas la même version quand un config.toml "
        "pose « user_env = [] », ce que le fichier généré écrit par défaut"
    )
    assert chainlit_fires(body=chainlit_settings_body_1_0()), (
        "le template exige starters ou debugUrl, absents jusqu'à la 1.0 — or "
        "ce sont ces instances-là qui traînent exposées"
    )
    assert chainlit_fires(body=chainlit_settings_body(chat_profiles=())), (
        "le template exige un profil de conversation : une application sans "
        "set_chat_profiles rend « [] » et sert le même back-end de chat"
    )
    assert chainlit_fires(
        body=json.dumps(json.loads(CHAINLIT_SETTINGS_BODY), indent=2)), (
        "le template exige la sérialisation compacte de JSONResponse : un "
        "intermédiaire qui réindente ce qu'il relaie ferait manquer l'instance"
    )

    # Le refus, sous ses trois formes : la dépendance, le validateur de requête,
    # et le proxy qu'on place devant.
    assert not chainlit_fires(body=CHAINLIT_UNAUTHENTICATED_BODY), (
        "le template conclut sur le 401 d'une instance dont un rappel "
        "d'authentification est déclaré — c'est exactement l'instance fermée"
    )
    assert not chainlit_fires(body=CHAINLIT_UNPROCESSABLE_BODY), (
        "le template conclut sur le refus de validation de Pydantic, qui "
        "n'apprend rien de l'ouverture"
    )
    assert not chainlit_fires(body=CHAINLIT_PROXY_DENIED_BODY), (
        "le template signale une instance dont un proxy refuse déjà la route à "
        "l'anonyme"
    )
    assert not chainlit_fires(body=CHAINLIT_SPA_BODY), (
        "le template déclenche sur la coquille de l'interface, que "
        "« @router.get(\"/{full_path:path}\") » rend en 200 sur n'importe quel "
        "chemin — donc sur toute instance Chainlit vivante, protégée comprise"
    )
    assert not chainlit_fires(body=CHAINLIT_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture du corps qui dit que "
        "l'instance a répondu d'elle-même, et non une supervision qui "
        "agrégerait sa réponse sous une clé à elle"
    )

    # Les trois ancrages du corps, isolés un à un.
    assert not chainlit_fires(body=CHAINLIT_WITHOUT_USER_ENV_BODY), (
        "le template n'exige plus userEnv, la clé qui nomme les variables "
        "d'environnement réclamées à l'utilisateur et sans laquelle la "
        "signature se réduit à des booléens"
    )
    assert not chainlit_fires(body=CHAINLIT_WITHOUT_CHAT_PROFILES_BODY), (
        "le template n'exige plus chatProfiles, le vocabulaire propre à "
        "Chainlit dans cette réponse"
    )
    assert not chainlit_fires(body=CHAINLIT_SPLIT_COUPLE_BODY), (
        "le template accepte dataPersistence et threadResumable séparés par "
        "une autre clé : c'est leur adjacence, inchangée depuis la 1.0, qui "
        "sépare ce document de deux booléens homonymes"
    )

    # Collisions : les autres interfaces de chat du pack, qui servent elles
    # aussi une configuration anonyme sur une route de configuration.
    for other_body, other_name in (
        (GRADIO_CONFIG_BODY, "gradio"),
        (GRADIO_OLD_CONFIG_BODY, "gradio, dans sa forme ancienne"),
        (OPENWEBUI_CONFIG_SIGNUP_OPEN_BODY, "open-webui"),
        (LIBRECHAT_CONFIG_REGISTRATION_OPEN_BODY, "librechat"),
        (DIFY_SETUP_NOT_STARTED_BODY, "dify"),
    ):
        assert not chainlit_fires(body=other_body), (
            f"le template déclenche sur {other_name}, qui sert lui aussi une "
            "configuration d'interface de chat sans être Chainlit"
        )


def test_chainlit_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    Le handler n'a pas de branche d'échec — il rend JSONResponse, donc un 200 —
    et les deux refus possibles ouvrent tous deux sur "detail", que l'ancrage
    écarte déjà. Exiger le 200 n'écarterait donc rien de plus, et ferait manquer
    l'instance dont un intermédiaire réécrit le statut ; le catch-all, lui, sert
    son HTML sous un 200 et ne serait pas davantage écarté.
    """
    block = chainlit_settings_block()

    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : le handler ne rend sa charge "
        "utile que sous un 200, donc ce matcher n'écarte rien et n'ajoute "
        "qu'un risque de silence"
    )

    assert chainlit_fires(status=503), (
        "le template dépend du statut alors qu'aucun matcher n'est censé le "
        "lire : la charge utile suffit, quel que soit le code qu'un "
        "intermédiaire pose devant"
    )
    assert not chainlit_fires(status=200, body=CHAINLIT_UNAUTHENTICATED_BODY), (
        "un 200 portant le refus de la dépendance fait conclure le template : "
        "c'est le corps qui porte la preuve"
    )
    assert not chainlit_fires(status=200, body=CHAINLIT_SPA_BODY), (
        "la coquille de l'interface, rendue en 200 sur tout chemin, suffit à "
        "faire conclure le template"
    )


def test_chainlit_extractors_report_what_the_anonymous_caller_obtains():
    block = chainlit_settings_block()
    extractors = block.get("extractors") or []

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
            f"charger — {extractor.get('name')!r}"
        )
        assert extractor.get("part") in (None, "body"), (
            "le bloc n'a qu'une requête et un seul corps à lire — "
            f"part={extractor.get('part')!r}"
        )

    found = {e.get("name"): e.get("json") for e in extractors}
    assert found == {
        "name": [".ui.name"],
        "userenv": [".userEnv[]?"],
        "profile": [".chatProfiles[].name"],
    }, (
        "les trois renseignements du constat ne sont pas remontés tels quels — "
        f"{found}. .ui.name est le seul champ obligatoire d'UISettings et "
        "rattache l'instance à un projet ; .userEnv[] nomme les clés d'API que "
        "l'application réclame à l'utilisateur, donc le fournisseur de modèle "
        "branché derrière, et le « ? » est ce qui l'empêche de fauter quand la "
        "clé vaut null ; .chatProfiles[].name nomme les modèles servis, et "
        "s'arrêter au premier tairait les autres"
    )


# --------------------------------------------------------------------------
# MLServer sert le même triplet name/version/extensions que Triton, sur le
# même chemin nu /v2 : c'est le vocabulaire du protocole KServe v2, pas la
# signature d'un produit. OTHER_KSERVE_METADATA_BODY, plus haut dans ce
# fichier, en est déjà la preuve côté Triton — il porte "name":"mlserver" sans
# faire déclencher le template de Triton. Celui-ci doit tenir la relation
# inverse : ne jamais déclencher sur le /v2 réel de Triton, ni sur la forme
# nue du protocole sans la littérale du produit.

MLSERVER_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "mlserver-metadata-exposed.yaml")


def mlserver_metadata_body(name="mlserver", version="1.7.1", extensions=()):
    """
    Ce que DataPlane.metadata() rend (mlserver/handlers/dataplane.py), dans la
    sérialisation compacte d'encode_to_json_bytes — orjson, ou son repli
    json.dumps(..., separators=(",", ":")).
    """
    return json.dumps({"name": name, "version": version, "extensions": list(extensions)},
                      separators=(",", ":"))


MLSERVER_METADATA_BODY = mlserver_metadata_body()

# extensions n'est peuplé par aucun runtime connu du paquet, mais Settings ne
# l'interdit pas : le template ne doit pas dépendre d'une liste vide.
MLSERVER_METADATA_WITH_EXTENSIONS_BODY = mlserver_metadata_body(
    extensions=["mlflow.mlserver.io/schema"])

# Le même corps relayé par un intermédiaire qui réindente ce que MLServer sert
# compact.
MLSERVER_METADATA_REFORMATTED_BODY = json.dumps(
    json.loads(MLSERVER_METADATA_BODY), indent=2)

# server_name renommé via MLSERVER_SERVER_NAME : Settings ne l'interdit pas
# non plus, mais la littérale est la limite assumée de ce template — une
# instance renommée ne doit, à dessein, pas être reconnue.
MLSERVER_METADATA_RENAMED_BODY = mlserver_metadata_body(name="prod-inference-01")

# La charge utile entière, retrouvée au fond d'un document composite qu'une
# supervision agrégerait sous une clé à elle : ce n'est pas l'instance qui a
# répondu d'elle-même.
MLSERVER_COMPOSITE_METADATA_BODY = '{"mlserver":%s,"checked_at":0}' % MLSERVER_METADATA_BODY


def mlserver_block():
    doc = load(MLSERVER_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/v2" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /v2"
    return blocks[0]


def mlserver_fires(body):
    block = mlserver_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    verdicts = [body_matcher_hits(m, body) for m in matchers]
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_mlserver_probe_reads_the_bare_route_and_never_touches_the_dataplane():
    doc = load(MLSERVER_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "metadata() se lit en GET : tout ce qui ferait tourner un modèle "
            "ou toucherait au dépôt est en POST sur ce même routeur nu"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/infer", "POST /v2/models/{name}/infer ferait tourner le "
                           "modèle sur le matériel de l'exploitant"),
                ("/generate", "POST /v2/models/{name}/generate ou "
                              "/generate_stream ferait produire du texte aux "
                              "frais de l'exploitant"),
                ("/repository", "les routes de dépôt chargeraient, "
                                "déchargeraient ou énuméreraient les modèles "
                                "de l'exploitant — la littérale de /v2 suffit "
                                "à établir le constat sans y toucher"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    assert mlserver_block().get("path") == ["{{BaseURL}}/v2"], (
        "le constat tient à une seule lecture, sur le chemin nu que "
        'APIRoute("/v2", endpoints.metadata) déclare — '
        f"{mlserver_block().get('path')}"
    )


def test_mlserver_matcher_needs_the_product_literal_not_just_the_kserve_shape():
    assert mlserver_fires(MLSERVER_METADATA_BODY), (
        "le template ne reconnaît pas la réponse par défaut de "
        "DataPlane.metadata() sur une instance dont l'exploitant n'a rien "
        "changé"
    )
    assert mlserver_fires(MLSERVER_METADATA_WITH_EXTENSIONS_BODY), (
        "le template exige une liste d'extensions non vide : Settings la "
        "vaut [] par défaut, et aucun runtime connu ne la peuple"
    )
    assert mlserver_fires(MLSERVER_METADATA_REFORMATTED_BODY), (
        "le template exige la sérialisation compacte de MLServer : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )
    assert mlserver_fires(mlserver_metadata_body(version="0.6.0")), (
        "le template contraint le numéro de version, qui change à chaque "
        "publication — le constat ne doit tenir que de la littérale du nom"
    )

    # La frontière avec Triton, qui sert le même triplet sur le même chemin.
    assert not mlserver_fires(TRITON_METADATA_BODY), (
        "le template déclenche sur le /v2 réel de Triton : name, version et "
        "extensions sont le vocabulaire du protocole KServe v2 que les deux "
        "serveurs partagent, et Triton a déjà son propre template"
    )
    assert not mlserver_fires(OTHER_GATEWAY_QUOTING_TRITON_BODY), (
        "le template déclenche sur un serveur KServe v2 quelconque qui n'est "
        "ni Triton ni MLServer : la forme du protocole ne suffit pas, il "
        'faut la littérale "mlserver"'
    )

    # Limite assumée : server_name peut être renommé, et le template ne doit
    # alors plus reconnaître l'instance — c'est le choix que la roadmap a
    # retenu en désignant la littérale comme signature.
    assert not mlserver_fires(MLSERVER_METADATA_RENAMED_BODY), (
        "le template dépend de MLSERVER_SERVER_NAME : c'est une limite "
        "assumée du template, pas un oubli, mais elle doit rester vérifiée "
        "pour ne pas se resserrer sans qu'on s'en aperçoive"
    )

    # La littérale doit être la valeur du champ name, pas un mot qui traîne.
    assert not mlserver_fires(MLSERVER_COMPOSITE_METADATA_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'objet plat qui dit que l'instance "
        "a répondu d'elle-même"
    )
    assert not mlserver_fires(
        '{"service":"inventaire","note":"le produit est mlserver et sa '
        'version 1.7.1"}'
    ), (
        "le template trouve la littérale n'importe où dans le corps : il "
        "déclencherait sur un inventaire qui la cite en prose"
    )


def test_mlserver_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    metadata() n'a pas de branche d'échec — elle rend un objet, que FastAPI ne
    peut sortir que sous un 200. Exiger ce 200 n'écarterait rien de plus, et
    ferait manquer l'instance dont un intermédiaire réécrit le statut.
    """
    block = mlserver_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : metadata() ne rend sa charge "
        "utile que sur un 200, donc ce matcher n'écarte rien et n'ajoute "
        "qu'un risque de silence"
    )


def test_mlserver_extractor_reports_the_exact_package_version():
    block = mlserver_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement qui vaille d'être remonté "
        "au-delà de la littérale qui l'identifie — le numéro exact du paquet "
        "installé"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("part") in (None, "body"), (
        "l'extracteur n'est pas borné au corps de l'unique réponse"
    )
    assert extractor.get("json") == [".version"], (
        "l'extracteur ne parcourt pas .version — c'est pourtant "
        "self._settings.server_version, le seul renseignement daté que la "
        "route livre"
    )


METAFLOW_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "metaflow-metadata-service-exposed.yaml")


def metaflow_ping_block():
    doc = load(METAFLOW_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/ping" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /ping"
    return blocks[0]


def metaflow_fires(body="pong", headers="metadata_service_version: 2.15.0",
                   status=200):
    """
    Sémantique nuclei d'un bloc à une seule requête : chaque matcher est évalué
    contre la part qu'il déclare (`header` ou `body`), et matchers-condition les
    joint. `body_matcher_hits` sert les deux parts sans rien savoir du sujet
    qu'on lui donne — nuclei présente les en-têtes de la réponse comme une
    chaîne, au même titre que le corps.
    """
    block = metaflow_ping_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"

    verdicts = []
    for matcher in matchers:
        if matcher.get("type") == "status":
            verdicts.append(status in (matcher.get("status") or []))
        elif matcher.get("part") == "header":
            verdicts.append(body_matcher_hits(matcher, headers))
        else:
            verdicts.append(body_matcher_hits(matcher, body))

    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_metaflow_probe_reads_the_ping_route_and_never_touches_flows_or_auth():
    doc = load(METAFLOW_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "ping() se lit en GET : c'est l'unique méthode que "
            "AuthApi.__init__() enregistre pour cette route"
        )
        for path in (block.get("path") or []):
            for forbidden, why in (
                ("/flows", "GET /flows énumère tous les flows enregistrés "
                           "— noms de projet et propriétaires — sur le même "
                           "routeur nu ; la littérale de /ping suffit à "
                           "établir le constat sans les lire"),
                ("/auth/token", "GET /auth/token ferait rendre de vraies "
                                "identifiants AWS STS quand le processus "
                                "porte un rôle IAM : le template signalerait "
                                "l'exposition en causant lui-même la fuite "
                                "qu'il dénonce"),
            ):
                assert forbidden not in path, f"{path} : {why}"

    assert metaflow_ping_block().get("path") == ["{{BaseURL}}/ping"], (
        "le constat tient à une seule lecture, sur la route la plus nue du "
        "routeur — " + str(metaflow_ping_block().get("path"))
    )


def test_metaflow_matcher_needs_the_product_header_not_just_the_generic_pong_body():
    assert metaflow_fires(), (
        "le template ne reconnaît pas la réponse par défaut de ping() sur "
        "une instance dont l'exploitant n'a rien changé"
    )
    assert metaflow_fires(headers="metadata_service_version: 1.0.0"), (
        "le template contraint le numéro de version, qui change à chaque "
        "publication — le constat ne doit tenir que du nom de l'en-tête"
    )
    assert metaflow_fires(headers="Metadata_Service_Version: 2.15.0"), (
        "le template dépend de la casse exacte de l'en-tête : un client Go "
        "recanonise METADATA_SERVICE_VERSION en Metadata_Service_Version "
        "sans en changer le sens, et le matcher doit rester insensible à la "
        "casse"
    )

    # Le corps "pong" seul est un motif de health-check générique — c'est
    # justement ce que la roadmap interdit de tenir pour suffisant.
    assert not metaflow_fires(headers="content-type: text/plain"), (
        "le template déclenche sur le seul corps \"pong\" : n'importe quel "
        "health-check générique le rend, et ce n'est pas la signature du "
        "produit"
    )
    assert not metaflow_fires(headers=""), (
        "le template déclenche sans aucun en-tête METADATA_SERVICE_VERSION "
        "dans la réponse"
    )

    # Le corps est ancré : ni un JSON qui envelopperait le mot, ni une prose
    # qui le citerait en passant, ne doivent faire déclencher le template.
    assert not metaflow_fires(body='{"status":"pong"}'), (
        "le template déclenche sur un corps JSON qui porte \"pong\" en "
        "valeur : ping() ne rend jamais que les quatre caractères nus"
    )
    assert not metaflow_fires(body="ping pong service"), (
        "le template déclenche sur une prose qui cite \"pong\" en passant : "
        "l'ancrage doit exiger que le corps entier soit ce mot, rien de plus"
    )


def test_metaflow_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    ping() n'a pas de branche d'échec — elle rend web.Response(text="pong",
    ...) sans condition, qu'aiohttp ne peut sortir que sous un 200. Exiger ce
    200 n'écarterait rien de plus, et ferait manquer l'instance dont un
    intermédiaire réécrit le statut.
    """
    block = metaflow_ping_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : ping() ne rend sa charge "
        "utile que sur un 200, donc ce matcher n'écarte rien et n'ajoute "
        "qu'un risque de silence"
    )


def test_metaflow_extractor_reports_the_exact_package_version():
    block = metaflow_ping_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "la réponse ne porte qu'un renseignement qui vaille d'être remonté "
        "au-delà de la littérale qui l'identifie — le numéro exact du "
        "paquet metadata_service installé"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "regex", (
        "le renseignement est porté par un en-tête, pas par un corps JSON : "
        "un extracteur json n'a pas à s'en charger"
    )
    assert extractor.get("part") == "header", (
        "l'extracteur n'est pas borné à l'en-tête de l'unique réponse — "
        "c'est pourtant là, et non dans le corps, que METADATA_SERVICE_VERSION "
        "est porté"
    )
    assert extractor.get("group") == 1, (
        "l'extracteur doit isoler la valeur, pas le couple nom-valeur entier "
        "de l'en-tête"
    )


# --------------------------------------------------------------------------
# RAGFlow sert la même route de configuration sous deux implémentations
# distinctes du serveur — Python (api/apps/restful_apis/system_api.py) et Go
# (internal/handler+service/system.go) — qui n'accordent ni l'ordre des
# clés (alphabétique côté Quart, déclaratif côté encoding/json, et les deux
# ordres sont inverses l'un de l'autre) ni le type de registerEnabled (entier
# 0/1 en Python, booléen strict en Go). Le template doit reconnaître les deux
# sans jamais dépendre de leur ordre ou de leur forme commune.

RAGFLOW_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "ragflow-config-exposed.yaml")


def ragflow_config_body(register_enabled=1, disable_password_login=False,
                        order=("disablePasswordLogin", "registerEnabled"),
                        extra=None, message="success", code=0):
    """
    L'enveloppe que get_json_result() (Python) et le type response
    (internal/common/http.go, Go) construisent tous deux — code, puis data,
    puis message — avec data sérialisé dans l'ordre demandé, pour couvrir
    aussi bien le tri alphabétique de Quart que l'ordre de déclaration de Go.
    """
    values = {"disablePasswordLogin": disable_password_login,
              "registerEnabled": register_enabled}
    if extra:
        values.update(extra)
    data = {key: values[key] for key in order}
    return json.dumps({"code": code, "data": data, "message": message},
                      separators=(",", ":"))


# La forme par défaut du dépôt principal (Python, tri alphabétique de Quart) :
# deux clés seulement, disablePasswordLogin avant registerEnabled.
RAGFLOW_CONFIG_BODY = ragflow_config_body()

# La forme observée sur une instance publique (fork "-mt") : un champ inséré
# alphabétiquement entre les deux, ce qu'un ancrage sur leur adjacence
# manquerait.
RAGFLOW_CONFIG_WITH_EXTRA_FIELD_BODY = ragflow_config_body(
    order=("disablePasswordLogin", "emailVerificationEnabled", "registerEnabled"),
    extra={"emailVerificationEnabled": True})

# La forme Go : ordre de déclaration du struct ConfigResponse
# (registerEnabled puis disablePasswordLogin — l'inverse de l'ordre
# alphabétique Python) et un booléen strict pour registerEnabled plutôt que
# l'entier 0/1 que lit settings.REGISTER_ENABLED côté Python.
RAGFLOW_CONFIG_GO_SHAPE_BODY = ragflow_config_body(
    register_enabled=True, order=("registerEnabled", "disablePasswordLogin"))

# L'inscription fermée et le mot de passe désactivé au sens de l'interface :
# registerEnabled=0, disablePasswordLogin=true.
RAGFLOW_CONFIG_SSO_ONLY_BODY = ragflow_config_body(
    register_enabled=0, disable_password_login=True)

# Le même corps relayé par un intermédiaire qui réindente ce que Quart sert
# compact.
RAGFLOW_CONFIG_REFORMATTED_BODY = json.dumps(json.loads(RAGFLOW_CONFIG_BODY), indent=2)

# Le 404 de RAGFlow lui-même sur un chemin que le back-end ne connaît pas —
# /v1/system/config sans le préfixe /api, par exemple : un code non nul, une
# data nulle, jamais les deux réglages.
RAGFLOW_NOT_FOUND_BODY = ('{"code":404,"data":null,"error":"Not Found",'
                          '"message":"Not Found: /api/v1/system/config"}')

# GET /system/version, servi par le même fichier et tout aussi dépourvu de
# @login_required, mais dont le corps ne porte aucun vocabulaire propre à
# RAGFlow : un entier de code, une chaîne de version, un message.
RAGFLOW_VERSION_BODY = '{"code":0,"data":"v0.26.4","message":"success"}'

# La même enveloppe générique (code/data/message, code=0, message="success"),
# sans le couple de réglages propre à RAGFlow : ce n'est pas un fait rare,
# get_json_result() est le format que toutes les routes du produit partagent.
RAGFLOW_GENERIC_WRAPPER_BODY = '{"code":0,"data":{"id":"abc123"},"message":"success"}'

# Chacun des deux réglages, retiré un à un d'un corps par ailleurs complet :
# ce sont ensemble qu'ils nomment RAGFlow, jamais l'un sans l'autre.
RAGFLOW_WITHOUT_REGISTER_ENABLED_BODY = json.dumps(
    {"code": 0, "data": {"disablePasswordLogin": False}, "message": "success"},
    separators=(",", ":"))
RAGFLOW_WITHOUT_DISABLE_PASSWORD_LOGIN_BODY = json.dumps(
    {"code": 0, "data": {"registerEnabled": 1}, "message": "success"},
    separators=(",", ":"))

# La charge utile entière, retrouvée au fond d'un document composite qu'une
# supervision agrégerait sous une clé à elle.
RAGFLOW_COMPOSITE_BODY = '{"ragflow":%s,"checked_at":0}' % RAGFLOW_CONFIG_BODY


def ragflow_config_block():
    doc = load(RAGFLOW_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/v1/system/config" in (b.get("path") or [])]
    assert blocks, "le template ne vise pas GET /api/v1/system/config"
    return blocks[0]


def ragflow_fires(body):
    block = ragflow_config_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    verdicts = [body_matcher_hits(m, body) for m in matchers]
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_ragflow_probe_reads_the_bare_config_and_never_touches_registration():
    doc = load(RAGFLOW_TEMPLATE)

    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "get_config() et GetConfig() se lisent en GET : le même fichier "
            "porte POST /api/v1/users, gouverné par la même variable "
            "REGISTER_ENABLED, et un template n'a pas à créer de compte sur "
            "une instance qu'il découvre"
        )
        for path in (block.get("path") or []):
            assert "/users" not in path and "/auth/login" not in path, (
                f"{path} : la création de compte et la connexion sont "
                "l'abus que le constat signale, pas ce qui l'établit"
            )

    assert ragflow_config_block().get("path") == ["{{BaseURL}}/api/v1/system/config"], (
        "le constat tient à une seule lecture, sur le chemin que "
        '@manager.route("/system/config") monte sous le préfixe /api/v1 — '
        f"{ragflow_config_block().get('path')}"
    )


def test_ragflow_matcher_needs_both_settings_not_just_the_shared_envelope():
    block = ragflow_config_block()
    assert block.get("matchers-condition") == "and", (
        "aucune des expressions ne nomme RAGFlow à elle seule : "
        "l'enveloppe code/data/message est celle de toutes les routes du "
        "produit, et chaque réglage pris seul est un nom de champ banal"
    )

    assert ragflow_fires(RAGFLOW_CONFIG_BODY), (
        "le template ne reconnaît pas la forme par défaut du dépôt principal"
    )
    assert ragflow_fires(RAGFLOW_CONFIG_WITH_EXTRA_FIELD_BODY), (
        "le template exige l'adjacence des deux réglages : un fork qui "
        "insère un champ entre eux (observé sur une instance publique) "
        "resterait alors méconnu"
    )
    assert ragflow_fires(RAGFLOW_CONFIG_GO_SHAPE_BODY), (
        "le template manque l'implémentation Go du serveur : son struct "
        "ConfigResponse déclare registerEnabled avant disablePasswordLogin "
        "(l'ordre inverse du tri alphabétique de Quart) et sérialise "
        "registerEnabled en booléen strict plutôt qu'en entier 0/1"
    )
    assert ragflow_fires(RAGFLOW_CONFIG_SSO_ONLY_BODY), (
        "le template dépend de la valeur des réglages : l'instance qui "
        "ferme l'inscription et cache le mot de passe est exposée au même "
        "titre que celle qui les laisse ouverts"
    )
    assert ragflow_fires(RAGFLOW_CONFIG_REFORMATTED_BODY), (
        "le template exige la sérialisation compacte de Quart : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )

    # Le même fichier, sans le vocabulaire du produit.
    assert not ragflow_fires(RAGFLOW_NOT_FOUND_BODY), (
        "le template déclenche sur le 404 générique de RAGFlow — code n'y "
        "vaut jamais 0, et data y est toujours nulle"
    )
    assert not ragflow_fires(RAGFLOW_VERSION_BODY), (
        "le template déclenche sur GET /system/version, tout aussi dépourvu "
        "de @login_required mais dont le corps ne porte ni registerEnabled "
        "ni disablePasswordLogin"
    )
    assert not ragflow_fires(RAGFLOW_GENERIC_WRAPPER_BODY), (
        "le template déclenche sur la seule enveloppe code/data/message, "
        "que get_json_result() applique à chaque route du produit — il lui "
        "faut le couple de réglages propre à /system/config"
    )
    assert not ragflow_fires(RAGFLOW_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture de l'enveloppe qui dit "
        "que l'instance a répondu d'elle-même"
    )

    # Les deux réglages, isolés un à un.
    assert not ragflow_fires(RAGFLOW_WITHOUT_REGISTER_ENABLED_BODY), (
        "le template ne dépend pas de registerEnabled : disablePasswordLogin "
        "seul n'est pas un nom de champ propre à RAGFlow"
    )
    assert not ragflow_fires(RAGFLOW_WITHOUT_DISABLE_PASSWORD_LOGIN_BODY), (
        "le template ne dépend pas de disablePasswordLogin : registerEnabled "
        "seul est un nom de champ trop banal pour nommer le produit"
    )


def test_ragflow_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    get_config() et GetConfig() n'ont ni l'un ni l'autre de branche d'échec
    sur cette route — ils recopient deux réglages du process sans jamais
    lever — donc les deux ne peuvent rendre que 200. Exiger ce statut
    n'écarterait rien de plus et ferait manquer l'instance dont un
    intermédiaire réécrit le code retourné.
    """
    kinds = {m.get("type") for m in (ragflow_config_block().get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut alors qu'aucune des deux "
        "implémentations n'a de branche d'échec sur cette route"
    )


def test_ragflow_extractors_report_both_settings():
    extractors = ragflow_config_block().get("extractors") or []
    assert len(extractors) == 2, (
        "les deux réglages valent d'être remontés : registerEnabled "
        "conditionne réellement POST /api/v1/users, et disablePasswordLogin "
        "dit l'intention d'interface à vérifier séparément"
    )
    reported = {(e.get("name"), tuple(e.get("json") or [])) for e in extractors}
    assert reported == {
        ("register_enabled", (".data.registerEnabled",)),
        ("disable_password_login", (".data.disablePasswordLogin",)),
    }, reported


# --------------------------------------------------------------------------
# LangGraph Server sert le tableau d'Assistant sans jamais dépendre de l'ordre
# de ses clés : le backend en mémoire (langgraph-runtime-inmem, celui de
# `langgraph dev`) et le backend Postgres/gRPC de production ne sont pas
# documentés comme sérialisant dans le même ordre, et le template ne doit donc
# reposer que sur la présence des six champs qui nomment le produit.

LANGGRAPH_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                  "langgraph-server-unauthenticated.yaml")

OK_ROUTE = "/ok"
ASSISTANTS_SEARCH_ROUTE = "/assistants/search"


def langgraph_assistant(assistant_id="9f6a3b2e-1c4d-4e9a-8b7f-2d5e6c1a0f3b",
                        graph_id="agent", version=1, name=None,
                        description=None, extra=None):
    """Un objet Assistant tel que register_graph() en enregistre un par graphe
    déclaré dans langgraph.json, avant même qu'un utilisateur n'en crée un."""
    values = {
        "assistant_id": assistant_id,
        "graph_id": graph_id,
        "config": {},
        "context": {},
        "metadata": {"created_by": "system"},
        "name": name or graph_id,
        "created_at": "2026-08-26T12:00:00+00:00",
        "updated_at": "2026-08-26T12:00:00+00:00",
        "version": version,
        "description": description,
    }
    if extra:
        values.update(extra)
    return values


def langgraph_search_body(assistants=None):
    assistants = assistants if assistants is not None else [langgraph_assistant()]
    return json.dumps(assistants, separators=(",", ":"))


OK_BODY = '{"ok":true}'
LANGGRAPH_SEARCH_BODY = langgraph_search_body()

# Le backend Postgres/gRPC déclare les mêmes champs dans un ordre différent de
# celui du backend en mémoire (langgraph_api/schema.py ne fixe qu'un TypedDict,
# pas un ordre de sérialisation) : le template ne doit pas y être sensible.
LANGGRAPH_SEARCH_REORDERED_BODY = json.dumps(
    [{
        "version": 1, "updated_at": "2026-08-26T12:00:00+00:00",
        "metadata": {"created_by": "system"}, "created_at": "2026-08-26T12:00:00+00:00",
        "context": {}, "config": {"configurable": {}}, "graph_id": "agent",
        "assistant_id": "9f6a3b2e-1c4d-4e9a-8b7f-2d5e6c1a0f3b",
        "name": "agent", "description": None,
    }],
    separators=(",", ":"),
)

# Le même corps relayé par un intermédiaire qui réindente ce que orjson sert
# compact.
LANGGRAPH_SEARCH_REFORMATTED_BODY = json.dumps(json.loads(LANGGRAPH_SEARCH_BODY), indent=2)

# Plusieurs assistants, pour vérifier que le template ne dépend pas d'un
# tableau à un seul élément.
LANGGRAPH_SEARCH_MULTIPLE_BODY = langgraph_search_body([
    langgraph_assistant(graph_id="agent"),
    langgraph_assistant(assistant_id="1f2e3d4c-5b6a-4978-8899-aabbccddeeff",
                        graph_id="chatbot", name="chatbot"),
])

# Une instance qui n'a jamais eu de graphe enregistré : le cas n'est censé
# jamais se produire sur un serveur réellement configuré, register_graph()
# enregistrant un assistant système au démarrage de chaque graphe déclaré.
LANGGRAPH_EMPTY_SEARCH_BODY = "[]"

# Un 401 renvoyé par un module d'autorisation personnalisé — le cas que la
# remédiation demande de mettre en place, précisément ce que le template ne
# doit pas signaler comme ouvert.
LANGGRAPH_UNAUTHORIZED_BODY = '{"detail":"Unauthorized"}'

# La charge utile entière, retrouvée au fond d'un document composite qu'une
# supervision agrégerait sous une clé à elle.
LANGGRAPH_COMPOSITE_BODY = '{"langgraph":%s,"checked_at":0}' % LANGGRAPH_SEARCH_BODY

# Le vocabulaire de KServe v2 (Triton, MLServer) et d'autres API du pack :
# aucune ne partage le trio assistant_id/graph_id/version sur ce chemin.
OTHER_API_BODY = '{"name":"mlserver","version":"1.7.1","extensions":[]}'


def langgraph_block():
    doc = load(LANGGRAPH_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(ASSISTANTS_SEARCH_ROUTE in raw for raw in (b.get("raw") or []))]
    assert blocks, (
        f"le template n'interroge pas {ASSISTANTS_SEARCH_ROUTE} — c'est "
        "pourtant lui qui porte le tableau d'Assistant"
    )
    return blocks[0]


def langgraph_requests():
    """
    (méthode, chemin) de chaque requête brute, dans l'ordre déclaré : c'est cet
    ordre qui donne son numéro à chaque body_N.

    Le bloc emploie `raw` et non `path` parce que les méthodes diffèrent — /ok
    ne répond qu'en GET, /assistants/search exige un corps JSON que seul POST
    porte.
    """
    out = []
    for raw in langgraph_block().get("raw") or []:
        start_line = raw.strip().splitlines()[0].split()
        assert len(start_line) >= 2, f"requête brute illisible : {raw!r}"
        out.append((start_line[0], start_line[1]))
    return out


def langgraph_responses(scenario):
    ordered = []
    for _, route in langgraph_requests():
        assert route in scenario, (
            f"le template interroge un chemin que LangGraph Server ne sert "
            f"pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def langgraph_fires(ok=(200, OK_BODY), search=(200, LANGGRAPH_SEARCH_BODY)):
    scenario = {OK_ROUTE: ok, ASSISTANTS_SEARCH_ROUTE: search}
    block = langgraph_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = langgraph_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
               if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_langgraph_probe_reads_search_with_an_empty_body_and_touches_nothing_else():
    assert langgraph_block().get("req-condition") is True, (
        "le template ne lie pas les deux réponses : sans req-condition, ni "
        "body_N ni status_code_N n'existent, et /ok — générique à lui seul — "
        "conclurait de son côté"
    )

    assert langgraph_requests() == [
        ("GET", OK_ROUTE), ("POST", ASSISTANTS_SEARCH_ROUTE),
    ], (
        "les deux requêtes ne sont plus celles que le template documente — "
        f"{langgraph_requests()}"
    )

    for raw in langgraph_block().get("raw") or []:
        method, route = raw.strip().splitlines()[0].split()[:2]
        if route == ASSISTANTS_SEARCH_ROUTE:
            body = raw.strip().split("\n\n", 1)[1].strip()
            assert body == "{}", (
                "AssistantSearchRequest n'a aucun champ requis : envoyer plus "
                "qu'un corps vide ne prouverait rien de plus et risquerait de "
                "filtrer la réponse (graph_id, name, metadata...)"
            )
        for forbidden, why in (
            ("/threads",
             "POST /threads puis /threads/{thread_id}/runs exécuteraient le "
             "graphe que la liste vient de nommer — la même absence de garde "
             "les couvre, mais signaler l'exposition ne demande d'en toucher "
             "aucun"),
            ("/runs",
             "POST /runs ferait tourner un graphe en mode stateless sur "
             "l'instance auditée"),
            ("/assistants/{",
             "PATCH et DELETE sur un assistant précis modifieraient ou "
             "effaceraient une ressource de l'exploitant"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_langgraph_matcher_needs_six_assistant_fields_not_just_an_array():
    assert langgraph_fires(), (
        "le template ne reconnaît pas la réponse par défaut de "
        "search_assistants() sur une instance dont l'exploitant n'a rien "
        "changé"
    )
    assert langgraph_fires(search=(200, LANGGRAPH_SEARCH_REORDERED_BODY)), (
        "le template dépend de l'ordre des clés de l'objet Assistant : rien "
        "ne garantit que le backend Postgres/gRPC de production sérialise "
        "dans le même ordre que le backend en mémoire de `langgraph dev`"
    )
    assert langgraph_fires(search=(200, LANGGRAPH_SEARCH_REFORMATTED_BODY)), (
        "le template exige la sérialisation compacte d'orjson : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )
    assert langgraph_fires(search=(200, LANGGRAPH_SEARCH_MULTIPLE_BODY)), (
        "le template ne reconnaît qu'un tableau à un seul assistant, alors "
        "qu'une instance qui sert plusieurs graphes en enregistre un par "
        "graphe"
    )

    assert not langgraph_fires(ok=(200, '{"ok":false}')), (
        'le template déclenche sur /ok sans exiger exactement "ok":true — '
        "un corps quelconque du même processus ne prouve rien de plus"
    )
    assert not langgraph_fires(search=(200, LANGGRAPH_EMPTY_SEARCH_BODY)), (
        "le template remonte une instance dont /assistants/search rend un "
        "tableau vide : aucun graphe n'y est enregistré, et il n'y a rien à "
        "divulguer — un cas que register_graph() ne produit jamais sur un "
        "serveur réellement configuré"
    )
    assert not langgraph_fires(search=(401, LANGGRAPH_UNAUTHORIZED_BODY)), (
        "le template déclenche sur le refus que rendrait un module "
        "d'autorisation personnalisé — précisément la remédiation que le "
        "template recommande"
    )
    assert not langgraph_fires(search=(200, LANGGRAPH_COMPOSITE_BODY)), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture du tableau qui dit que "
        "l'instance a répondu d'elle-même"
    )
    assert not langgraph_fires(search=(200, OTHER_API_BODY)), (
        "le template déclenche sur le vocabulaire de KServe v2 (name/version/"
        "extensions) — aucun autre produit du pack ne partage le trio "
        "assistant_id/graph_id/version sur ce chemin"
    )


def test_langgraph_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    Ni ok() ni search_assistants() n'ont de branche d'échec sur un corps
    valide — le premier rend {"ok": true} sans condition, le second son
    tableau, que Starlette ne peut sortir que sous un 200. Les deux
    expressions du matcher DSL exigent déjà `status_code_N == 200` : il n'y a
    pas de matcher `status` séparé à écarter, mais le format même de
    l'exigence doit rester DSL, pas un raccourci sur le seul code.
    """
    block = langgraph_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les deux réponses par leur numéro"
    )


def test_langgraph_extractor_reports_the_graph_id_not_the_uuid():
    block = langgraph_block()
    extractors = block.get("extractors") or []
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le "
        "moteur émet un résultat par extracteur qui rend quelque chose, donc "
        "la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la réponse est un tableau JSON : une expression regex n'a pas à "
        "s'en charger"
    )
    assert extractor.get("part") == "body_2", (
        "l'extracteur n'est pas borné à body_2 — la réponse de /ok (body_1) "
        "n'a rien à en tirer"
    )
    assert extractor.get("json") == [".[].graph_id"], (
        "l'extracteur ne parcourt pas .[].graph_id — c'est pourtant le nom "
        "du graphe agent, le premier renseignement qu'un tiers tire de la "
        "liste, et ce qui désignerait la cible d'un run ultérieur"
    )


# --------------------------------------------------------------------------
# FlyteAdmin rend le même document sous deux orthographes et sous un espacement
# tiré au sort, et le template doit tenir sur les deux axes à la fois.
#
# L'orthographe d'abord : le grpc-gateway choisit son marshaleur sur la valeur
# exacte de l'en-tête Accept. Celui que flyteadmin déclare pour application/json
# porte « UseProtoNames: true » et rend « control_plane_version » ; celui par
# défaut de grpc-gateway v2, retenu pour toute autre valeur, rend
# « controlPlaneVersion ». Une sonde qui ne joint pas d'Accept tombe sur le
# second, mais un intermédiaire qui en pose un tombe sur le premier.
#
# L'espacement ensuite, et c'est le piège propre à ce produit : protojson insère
# en sortie sur une seule ligne une espace surnuméraire tirée au sort après
# chaque virgule (protobuf-go, internal/encoding/json/encode.go : « For
# single-line output, add a random extra space after each comma to make output
# unstable » / « if detrand.Bool() { e.out = append(e.out, ' ') } »). Deux
# réponses successives du même serveur ne sont donc pas octet pour octet
# identiques, et aucune expression du template ne peut dépendre de ce qui suit un
# séparateur.

FLYTEADMIN_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                   "flyteadmin-api-exposed.yaml")

PROJECTS_ROUTE = "/api/v1/projects"
VERSION_ROUTE = "/api/v1/version"


def flyteadmin_project(identifier="flytesnacks", name="flytesnacks"):
    """
    Un Project tel que FromProjectModels() le rend : les trois domaines que pose
    domainsConfig par défaut (development, staging, production), et les champs
    vides émis quand même — le marshaleur du gateway porte « EmitUnpopulated:
    true » des deux côtés.
    """
    return {
        "id": identifier,
        "name": name,
        "domains": [
            {"id": "development", "name": "development"},
            {"id": "staging", "name": "staging"},
            {"id": "production", "name": "production"},
        ],
        "description": "",
        "labels": None,
        "state": "ACTIVE",
        "org": "",
    }


def flyteadmin_projects_body(projects=None, spaced=False, indent=None):
    """
    `spaced` pousse le tirage de detrand.Bool() à son extrême — une espace après
    chacune des virgules, là où le serveur n'en met qu'après certaines.
    """
    projects = projects if projects is not None else [flyteadmin_project()]
    document = {"projects": projects, "token": ""}
    if indent is not None:
        return json.dumps(document, indent=indent)
    return json.dumps(document,
                      separators=(", ", ":") if spaced else (",", ":"))


def flyteadmin_version_body(key="controlPlaneVersion", spaced=False):
    document = {key: {"Build": "a1b2c3d", "Version": "1.16.0",
                      "BuildTime": "2026-08-26 12:00:00"}}
    return json.dumps(document, separators=(", ", ":") if spaced else (",", ":"))


FLYTEADMIN_PROJECTS_BODY = flyteadmin_projects_body()
FLYTEADMIN_VERSION_BODY = flyteadmin_version_body()

# La même paire, telle que le marshaleur application/json de flyteadmin la rend :
# les noms du .proto, donc control_plane_version. Les champs de Project sont tous
# d'un seul mot, ils ne changent pas d'orthographe d'un marshaleur à l'autre.
FLYTEADMIN_VERSION_PROTO_NAMES_BODY = flyteadmin_version_body("control_plane_version")

# Le tirage de detrand poussé au bout : une espace après chaque virgule.
FLYTEADMIN_PROJECTS_SPACED_BODY = flyteadmin_projects_body(spaced=True)
FLYTEADMIN_VERSION_SPACED_BODY = flyteadmin_version_body(spaced=True)

# Le même corps relayé par un intermédiaire qui réindente ce que le gateway sert
# compact.
FLYTEADMIN_PROJECTS_REFORMATTED_BODY = flyteadmin_projects_body(indent=2)

# Plusieurs projets : ListProjects ne valide pas le limit annoté « +required »,
# et ProjectRepo.List n'applique de LIMIT que s'il est non nul, donc une requête
# nue rend tout l'inventaire non archivé.
FLYTEADMIN_PROJECTS_MULTIPLE_BODY = flyteadmin_projects_body([
    flyteadmin_project(),
    flyteadmin_project("flytesnacks-staging", "flytesnacks-staging"),
])

# Une instance dont aucun projet n'a été enregistré : rien n'y est divulgué.
FLYTEADMIN_PROJECTS_EMPTY_BODY = '{"projects":[],"token":""}'

# Le refus que rend le gateway lorsque server.security.useAuth est posé — soit
# exactement la remédiation que le template recommande.
FLYTEADMIN_UNAUTHENTICATED_BODY = (
    '{"code":16,"message":"Request unauthenticated with Bearer","details":[]}'
)

# La charge utile entière, retrouvée au fond d'un document composite qu'une
# supervision agrégerait sous une clé à elle.
FLYTEADMIN_COMPOSITE_BODY = (
    '{"flyte":%s,"checked_at":0}' % FLYTEADMIN_PROJECTS_BODY
)

# Une autre plateforme qui servirait une liste de projets sur le même chemin,
# sans le tableau de Domain imbriqué qui est propre au modèle de Flyte.
OTHER_PROJECT_LIST_BODY = (
    '{"projects":[{"id":"p1","name":"p1","created_at":"2026-08-26T12:00:00Z"}],'
    '"token":""}'
)

# Un endpoint de version quelconque : la casse minuscule est la règle en JSON,
# et c'est justement ce que Build/Version/BuildTime ne suivent pas.
OTHER_VERSION_BODY = '{"version":"1.16.0","build":"a1b2c3d","buildTime":"2026-08-26"}'


def flyteadmin_block():
    doc = load(FLYTEADMIN_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(PROJECTS_ROUTE) for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {PROJECTS_ROUTE} — c'est pourtant lui qui "
        "porte l'inventaire des projets"
    )
    return blocks[0]


def flyteadmin_requests():
    """
    (méthode, chemin) de chaque requête, dans l'ordre déclaré : c'est cet ordre
    qui donne son numéro à chaque body_N.

    Le bloc emploie `path` et non `raw` parce que les deux routes répondent à la
    même méthode et ne prennent aucun corps.
    """
    block = flyteadmin_block()
    return [normalise_route(block.get("method"), target)
            for target in (block.get("path") or [])]


def flyteadmin_responses(scenario):
    ordered = []
    for _, route in flyteadmin_requests():
        assert route in scenario, (
            f"le template interroge un chemin que FlyteAdmin ne sert pas : {route}"
        )
        ordered.append(scenario[route])
    return ordered


def flyteadmin_fires(projects=(200, FLYTEADMIN_PROJECTS_BODY),
                     version=(200, FLYTEADMIN_VERSION_BODY)):
    scenario = {PROJECTS_ROUTE: projects, VERSION_ROUTE: version}
    block = flyteadmin_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = flyteadmin_responses(scenario)
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_flyteadmin_probe_reads_two_routes_and_touches_no_write_route():
    assert flyteadmin_block().get("req-condition") is True, (
        "le template ne lie pas les deux réponses : sans req-condition, ni "
        "body_N ni status_code_N n'existent, et /api/v1/version — générique à "
        "lui seul — conclurait de son côté"
    )

    assert flyteadmin_requests() == [
        ("GET", PROJECTS_ROUTE), ("GET", VERSION_ROUTE),
    ], (
        "les deux requêtes ne sont plus celles que le template documente — "
        f"{flyteadmin_requests()}"
    )

    doc = load(FLYTEADMIN_TEMPLATE)
    for method, route in sorted(request_routes(doc)):
        assert method == "GET", (
            f"{method} {route} : le même gwmux sans garde sert des routes en "
            "écriture, et aucune n'est nécessaire pour signaler l'exposition"
        )
        for forbidden, why in (
            ("/api/v1/executions",
             "POST /api/v1/executions lancerait un workflow sur le cluster "
             "Kubernetes de l'exploitant, avec ses images et ses quotas"),
            ("/api/v1/tasks",
             "POST /api/v1/tasks enregistrerait une tâche dans le registre de "
             "l'exploitant"),
            ("/api/v1/dataproxy",
             "les routes dataproxy rendent des URL signées vers le bucket de "
             "métadonnées — les emprunter extrairait des données"),
            ("/api/v1/events",
             "les routes d'événements écrivent dans l'historique d'exécution"),
        ):
            assert forbidden not in route, f"{route} : {why}"

    assert not any("{" in route for _, route in request_routes(doc)), (
        "une route paramétrée désigne une ressource précise de l'exploitant — "
        "PUT /api/v1/projects/{id} pourrait notamment l'archiver"
    )


def test_flyteadmin_matcher_needs_the_domains_array_not_just_a_project_list():
    assert flyteadmin_fires(), (
        "le template ne reconnaît pas la réponse par défaut de ListProjects sur "
        "une instance dont l'exploitant n'a rien changé"
    )
    assert flyteadmin_fires(projects=(200, FLYTEADMIN_PROJECTS_MULTIPLE_BODY)), (
        "le template ne reconnaît qu'un inventaire à un seul projet, alors "
        "qu'une requête nue rend tout l'inventaire non archivé — ListProjects "
        "ne valide pas le limit annoté « +required »"
    )
    assert flyteadmin_fires(projects=(200, FLYTEADMIN_PROJECTS_REFORMATTED_BODY)), (
        "le template exige la sérialisation compacte du gateway : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )

    assert not flyteadmin_fires(projects=(200, FLYTEADMIN_PROJECTS_EMPTY_BODY)), (
        "le template remonte une instance dont /api/v1/projects rend un "
        "inventaire vide : rien n'y est divulgué, et il n'y a pas de constat à "
        "porter"
    )
    assert not flyteadmin_fires(projects=(401, FLYTEADMIN_UNAUTHENTICATED_BODY)), (
        "le template déclenche sur le refus que rend le gateway quand "
        "server.security.useAuth est posé — précisément la remédiation que le "
        "template recommande"
    )
    assert not flyteadmin_fires(projects=(200, FLYTEADMIN_COMPOSITE_BODY)), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur la clé racine qui dit que l'instance a "
        "répondu d'elle-même"
    )
    assert not flyteadmin_fires(projects=(200, OTHER_PROJECT_LIST_BODY)), (
        "le template déclenche sur une liste de projets quelconque — c'est le "
        "tableau de Domain imbriqué dans chaque Project qui est propre au "
        "modèle de Flyte"
    )


def test_flyteadmin_matcher_holds_under_both_marshalers_and_random_spacing():
    """
    Les deux axes sur lesquels la même instance rend deux octets différents :
    l'orthographe de la clé racine, choisie par l'en-tête Accept, et l'espace
    surnuméraire que protojson tire au sort après chaque virgule.
    """
    assert flyteadmin_fires(version=(200, FLYTEADMIN_VERSION_PROTO_NAMES_BODY)), (
        "le template n'admet qu'une orthographe de la clé racine de "
        "GetVersionResponse : le marshaleur que flyteadmin déclare pour "
        "application/json porte « UseProtoNames: true » et rend "
        "control_plane_version, là où le marshaleur par défaut de grpc-gateway "
        "v2 rend controlPlaneVersion"
    )
    assert flyteadmin_fires(projects=(200, FLYTEADMIN_PROJECTS_SPACED_BODY),
                            version=(200, FLYTEADMIN_VERSION_SPACED_BODY)), (
        "le template dépend de ce qui suit une virgule : protojson insère une "
        "espace tirée au sort après chacune d'elles en sortie sur une seule "
        "ligne, donc deux réponses du même serveur ne sont pas octet pour "
        "octet identiques"
    )

    assert not flyteadmin_fires(version=(200, OTHER_VERSION_BODY)), (
        "le template déclenche sur un endpoint de version quelconque — ce sont "
        "les capitales de Build/Version/BuildTime, héritées telles quelles des "
        "champs du .proto, qui signent le produit"
    )
    assert not flyteadmin_fires(version=(404, '{"code":5,"message":"Not Found"}')), (
        "le template conclut sans que /api/v1/version ait confirmé : la "
        "corroboration par un chemin de code disjoint est ce qui écarte un "
        "cache ou un proxy statique"
    )


def test_flyteadmin_conclusion_rests_on_the_payload_not_on_the_http_status():
    block = flyteadmin_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les deux réponses par leur numéro"
    )


def test_flyteadmin_extractor_reports_the_project_identifiers():
    extractors = flyteadmin_block().get("extractors") or []
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le moteur "
        "émet un résultat par extracteur qui rend quelque chose, donc la même "
        "instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la réponse est un document JSON : une expression regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("part") == "body_1", (
        "l'extracteur n'est pas borné à body_1 — la réponse de /api/v1/version "
        "(body_2) n'est qu'une corroboration, elle ne divulgue rien de "
        "l'exploitant"
    )
    assert extractor.get("json") == [".projects[].id"], (
        "l'extracteur ne parcourt pas .projects[].id — c'est pourtant ce que "
        "l'exposition divulgue, et la moitié du couple (projet, domaine) dont "
        "dépendent toutes les routes de tâches, de workflows et d'exécutions"
    )


# --------------------------------------------------------------------------
# Optuna Dashboard rend le même document sous deux écritures et sous deux
# formes, et le template doit tenir sur les deux axes à la fois.
#
# L'écriture d'abord : la vue ne sérialise rien, elle rend un dictionnaire, et
# c'est le greffon JSON que Bottle installe par défaut qui appelle
# « json_dumps(rv) » (bottle.py, JSONPlugin.apply). Or bottle.py importe ce
# json_dumps de ujson quand ce paquet est présent — sortie compacte — et
# retombe sur json.dumps sinon, qui insère une espace après chaque « : » et
# chaque « , ». Deux instances de la même version ne rendent donc pas les mêmes
# octets.
#
# La forme ensuite : serialize_frozen_study() rend study_id, study_name,
# directions, user_attrs et is_preferential, mais ce dernier champ n'existe que
# depuis la 0.13.0. Jusqu'à la 0.12.0, serialize_study_summary() rendait à sa
# place system_attrs, et datetime_start quand il était renseigné. Un template
# qui n'exigerait que la forme récente manquerait précisément les instances
# anciennes, celles qui traînent exposées.

OPTUNA_DASHBOARD_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                         "optuna-dashboard-exposed.yaml")


def optuna_study_summary(study_id=1, study_name="quadratic-simple",
                         directions=("minimize",), user_attrs=None,
                         is_preferential=False):
    """
    Une entrée telle que serialize_frozen_study() la construit depuis la
    0.13.0 : cinq clés, dans l'ordre du dictionnaire Python.
    """
    return {
        "study_id": study_id,
        "study_name": study_name,
        "directions": list(directions),
        "user_attrs": list(user_attrs or []),
        "is_preferential": is_preferential,
    }


def optuna_legacy_study_summary(study_id=1, study_name="quadratic-simple",
                                directions=("minimize",)):
    """
    La même entrée telle que serialize_study_summary() la rendait jusqu'à la
    0.12.0 : system_attrs à la place d'is_preferential, et datetime_start
    lorsque le résumé le portait.
    """
    return {
        "study_id": study_id,
        "study_name": study_name,
        "directions": list(directions),
        "user_attrs": [],
        "system_attrs": [],
        "datetime_start": "2026-08-26T12:00:00",
    }


def optuna_studies_body(summaries=None, compact=False, indent=None):
    """
    `compact` est la sortie d'ujson, le défaut sans argument celle de
    json.dumps — les deux écritures que le greffon JSON de Bottle produit selon
    que ujson est installé ou non.
    """
    if summaries is None:
        summaries = [optuna_study_summary()]
    document = {"study_summaries": list(summaries)}
    if indent is not None:
        return json.dumps(document, indent=indent)
    if compact:
        return json.dumps(document, separators=(",", ":"))
    return json.dumps(document)


# La réponse par défaut d'une instance qui sert une étude, sous les deux
# écritures du greffon JSON.
OPTUNA_STUDIES_BODY = optuna_studies_body()
OPTUNA_STUDIES_COMPACT_BODY = optuna_studies_body(compact=True)

# Le même corps relayé par un intermédiaire qui réindente ce qu'il relaie.
OPTUNA_STUDIES_REFORMATTED_BODY = optuna_studies_body(indent=2)

# get_all_studies() ne filtre ni ne pagine : une requête nue rend tout
# l'inventaire, en multi-objectif comme en mode préférentiel, avec les
# métadonnées que le chercheur a attachées.
OPTUNA_STUDIES_MULTIPLE_BODY = optuna_studies_body([
    optuna_study_summary(),
    optuna_study_summary(2, "pricing-model-v3", ("minimize", "maximize"),
                         [{"key": "dataset", "value": "s3://internal/train"}]),
    optuna_study_summary(3, "human-feedback", is_preferential=True),
])

# La forme d'avant la 0.13.0, celle des instances anciennes.
OPTUNA_LEGACY_STUDIES_BODY = optuna_studies_body([optuna_legacy_study_summary()])

# Une étude enregistrée sans direction : StudyDirection.NOT_SET s'écrit
# "not_set" sous « d.name.lower() » comme les deux autres membres.
OPTUNA_STUDIES_NOT_SET_BODY = optuna_studies_body(
    [optuna_study_summary(directions=("not_set",))])

# Une instance sur laquelle aucune étude n'a été enregistrée : rien n'y est
# divulgué.
OPTUNA_EMPTY_INVENTORY_BODY = '{"study_summaries":[]}'

# La charge utile entière, retrouvée au fond d'un document composite qu'une
# supervision agrégerait sous une clé à elle.
OPTUNA_COMPOSITE_BODY = '{"optuna":%s,"checked_at":0}' % OPTUNA_STUDIES_COMPACT_BODY

# GET /api/meta, servi par le même Bottle et tout aussi dépourvu de garde, mais
# dont le corps ne dit rien de ce qui est divulgué : quatre drapeaux de
# capacité.
OPTUNA_META_BODY = ('{"artifact_is_available":false,"llm_is_available":false,'
                    '"plotlypy_is_available":true,"allow_unsafe":false}')

# GET /api/studies/{study_id}, le détail d'une seule étude : il porte bien
# directions et user_attrs, mais pas la clé racine de l'inventaire — c'est
# l'énumération qui est le constat, pas la lecture d'une étude nommée.
OPTUNA_STUDY_DETAIL_BODY = (
    '{"name":"quadratic-simple","directions":["minimize"],"user_attrs":[],'
    '"trials":[],"best_trials":[],"has_intermediate_values":false}'
)

# Une autre plateforme de suivi d'expériences servant son propre inventaire :
# même intention, aucun des noms de champ d'Optuna.
OTHER_EXPERIMENT_LIST_BODY = (
    '{"experiments":[{"experiment_id":"1","name":"quadratic-simple",'
    '"lifecycle_stage":"active"}]}'
)


def optuna_dashboard_block():
    doc = load(OPTUNA_DASHBOARD_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/studies" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /api/studies — c'est pourtant lui qui "
        "porte l'inventaire des études"
    )
    return blocks[0]


def optuna_dashboard_fires(body):
    block = optuna_dashboard_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    verdicts = [body_matcher_hits(m, body) for m in matchers]
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_optuna_dashboard_probe_reads_the_inventory_and_never_writes():
    doc = load(OPTUNA_DASHBOARD_TEMPLATE)

    assert optuna_dashboard_block().get("path") == ["{{BaseURL}}/api/studies"], (
        "le constat tient à une seule lecture, sur la route que "
        '@app.get("/api/studies") monte — '
        f"{optuna_dashboard_block().get('path')}"
    )

    for method, route in sorted(request_routes(doc)):
        assert method == "GET", (
            f"{method} {route} : le même Bottle sans garde sert des routes en "
            "écriture, et aucune n'est nécessaire pour signaler l'exposition"
        )
        for forbidden, why in (
            ("/tell",
             "POST /api/trials/{trial_id}/tell fixerait l'état et les valeurs "
             "objectives d'un essai, donc fausserait l'expérience de tuning "
             "que le template vient signaler"),
            ("/user-attrs",
             "POST /api/trials/{trial_id}/user-attrs écrirait dans les "
             "métadonnées de l'exploitant"),
            ("/rename",
             "POST /api/studies/{study_id}/rename recrée l'étude sous un "
             "autre nom et supprime l'originale"),
            ("/artifacts",
             "les routes d'artefacts servent les fichiers eux-mêmes — les "
             "emprunter extrairait des données"),
            ("/csv",
             "GET /csv/{study_id} exporte tous les essais d'une étude, ce que "
             "signaler l'exposition ne demande pas"),
        ):
            assert forbidden not in route, f"{route} : {why}"

    assert not any("{" in route.replace("{{BaseURL}}", "")
                   for _, route in request_routes(doc)), (
        "une route paramétrée désigne une étude précise de l'exploitant — "
        "DELETE /api/studies/{study_id} la supprimerait, avec ses artefacts"
    )


def test_optuna_dashboard_matcher_needs_the_summary_shape_not_any_study_list():
    block = optuna_dashboard_block()
    assert block.get("matchers-condition") == "and", (
        "aucune des expressions ne nomme le produit à elle seule : study_id, "
        "directions et is_preferential sont des noms de champ qu'un autre "
        "document pourrait porter, et c'est leur réunion sous la clé racine "
        "study_summaries qui désigne Optuna Dashboard"
    )

    assert optuna_dashboard_fires(OPTUNA_STUDIES_BODY), (
        "le template ne reconnaît pas la réponse par défaut de list_studies() "
        "sur une instance qui sert une étude"
    )
    assert optuna_dashboard_fires(OPTUNA_STUDIES_MULTIPLE_BODY), (
        "le template ne reconnaît qu'un inventaire mono-objectif à une seule "
        "étude, alors que get_all_studies() ne filtre ni ne pagine — une "
        "requête nue rend tout l'inventaire, multi-objectif et préférentiel "
        "compris"
    )
    assert optuna_dashboard_fires(OPTUNA_STUDIES_NOT_SET_BODY), (
        "le template n'admet pas la troisième valeur de StudyDirection : "
        "« d.name.lower() » écrit not_set comme il écrit minimize et maximize"
    )
    assert optuna_dashboard_fires(OPTUNA_STUDIES_REFORMATTED_BODY), (
        "le template exige la sérialisation d'origine : un intermédiaire qui "
        "réindenterait ce qu'il relaie ferait manquer l'instance"
    )

    assert not optuna_dashboard_fires(OPTUNA_EMPTY_INVENTORY_BODY), (
        "le template remonte une instance dont /api/studies rend un "
        "inventaire vide : rien n'y est divulgué, et il n'y a pas de constat "
        "à porter"
    )
    assert not optuna_dashboard_fires(OPTUNA_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur la clé racine qui dit que l'instance "
        "a répondu d'elle-même"
    )
    assert not optuna_dashboard_fires(OPTUNA_META_BODY), (
        "le template déclenche sur GET /api/meta, servi par le même Bottle et "
        "tout aussi dépourvu de garde, mais dont le corps ne divulgue rien de "
        "l'exploitant"
    )
    assert not optuna_dashboard_fires(OPTUNA_STUDY_DETAIL_BODY), (
        "le template déclenche sur le détail d'une seule étude, qui porte bien "
        "directions et user_attrs : c'est l'énumération sous study_summaries "
        "qui est le constat, pas la lecture d'une étude déjà nommée"
    )
    assert not optuna_dashboard_fires(OTHER_EXPERIMENT_LIST_BODY), (
        "le template déclenche sur l'inventaire d'une autre plateforme de "
        "suivi d'expériences"
    )


def test_optuna_dashboard_matcher_holds_across_versions_and_both_json_writers():
    """
    Les deux axes sur lesquels deux instances rendent des octets différents :
    le sérialiseur retenu par Bottle et la forme de l'entrée, qui a changé à la
    0.13.0.
    """
    assert optuna_dashboard_fires(OPTUNA_STUDIES_COMPACT_BODY), (
        "le template dépend de l'espacement : bottle.py importe json_dumps "
        "d'ujson quand ce paquet est présent — sortie compacte — et retombe "
        "sur json.dumps sinon, qui insère une espace après chaque séparateur"
    )
    assert optuna_dashboard_fires(OPTUNA_LEGACY_STUDIES_BODY), (
        "le template exige is_preferential, qui n'existe que depuis la "
        "0.13.0 : jusqu'à la 0.12.0 serialize_study_summary() rendait "
        "system_attrs à sa place, et ce sont les instances anciennes qui "
        "traînent exposées"
    )


def test_optuna_dashboard_conclusion_rests_on_the_payload_not_on_the_http_status():
    """
    list_studies() n'a pas de branche d'échec — il recopie get_all_studies() —
    donc il ne peut rendre que 200. Exiger ce statut n'écarterait rien de plus
    et ferait manquer l'instance dont un intermédiaire réécrit le code retourné.
    """
    kinds = {m.get("type") for m in (optuna_dashboard_block().get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut alors que la route n'a pas de "
        "branche d'échec"
    )


def test_optuna_dashboard_extractors_report_the_studies_the_caller_enumerates():
    extractors = optuna_dashboard_block().get("extractors") or []
    assert len(extractors) == 2, (
        "les deux valent d'être remontés : study_name est ce que l'exposition "
        "divulgue en premier, et study_id est la clé qui adresse le détail des "
        "essais, l'export CSV, les artefacts et les routes en écriture"
    )
    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "la réponse est un document JSON : une expression regex n'a pas à "
            "s'en charger"
        )
    reported = {(e.get("name"), tuple(e.get("json") or [])) for e in extractors}
    assert reported == {
        ("study_name", (".study_summaries[].study_name",)),
        ("study_id", (".study_summaries[].study_id",)),
    }, reported


# --------------------------------------------------------------------------
# KoboldCpp met les deux moitiés du constat dans la même réponse, et c'est ce
# qui rend le template particulier : "result":"KoboldCpp" nomme le produit,
# "protected":false dit que le global « password = "" #if empty, no auth key
# required » est resté vide. Le statut HTTP ne départage rien — la route rend
# 200 aussi bien sur une instance fermée, où elle écrit "protected":true.
#
# Deux axes font varier les octets d'une instance à l'autre. L'espacement
# d'abord : get_capabilities() rend un dictionnaire que json.dumps sérialise
# avec une espace après chaque « : » et chaque « , », là où le littéral lu dans
# koboldcpp.py est compact — et un intermédiaire peut réindenter ce qu'il
# relaie. Le jeu de clés ensuite, qui n'a fait que croître : jusqu'à la 1.60 la
# route ne rendait que result et version, la 1.61 y ajoute protected, txt2img et
# vision, la 1.67 transcribe, la 1.80 multiplayer, et les versions récentes une
# dizaine d'autres (llm, audio, music, savedata, admin, router, guidance, jinja,
# mcp). Un template qui exigerait le jeu complet daterait l'instance au lieu de
# désigner le produit.

KOBOLDCPP_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                  "koboldcpp-server-exposed.yaml")

KOBOLDCPP_VERSION_ROUTE = "/api/extra/version"
KOBOLDCPP_MODEL_ROUTE = "/api/v1/model"

# Les jeux de clés successifs de get_capabilities(), dans l'ordre où le
# dictionnaire Python les rend — c'est cet ordre que json.dumps recopie.
KOBOLDCPP_FLAGS_1_61 = ("txt2img", "vision")
KOBOLDCPP_FLAGS_1_67 = KOBOLDCPP_FLAGS_1_61 + ("transcribe",)
KOBOLDCPP_FLAGS_1_80 = KOBOLDCPP_FLAGS_1_67 + ("multiplayer",)
KOBOLDCPP_FLAGS_CURRENT = (
    "llm", "txt2img", "vision", "audio", "transcribe", "multiplayer",
    "websearch", "tts", "embeddings", "music", "savedata", "router",
    "guidance", "jinja", "mcp",
)


def koboldcpp_version_body(protected=False, version="1.98.1",
                           flags=KOBOLDCPP_FLAGS_CURRENT, compact=False,
                           indent=None):
    """
    Ce que rend GET /api/extra/version : get_capabilities() sérialisé par
    json.dumps, donc une espace après chaque séparateur. `compact` écrit le
    même document tel que le littéral apparaît dans koboldcpp.py, `indent` tel
    qu'un intermédiaire qui réindente le relaierait.
    """
    document = {"result": "KoboldCpp", "version": version, "protected": protected}
    for flag in flags:
        document[flag] = False
    if indent is not None:
        return json.dumps(document, indent=indent)
    if compact:
        return json.dumps(document, separators=(",", ":"))
    return json.dumps(document)


def koboldcpp_model_body(name="koboldcpp/Mistral-7B-Instruct-v0.3-Q4_K_M"):
    """
    Ce que rend GET /api/v1/model : un objet à une seule clé, dont la valeur est
    friendlymodelname — construit par le serveur en « "koboldcpp/" +
    sanitize_string(...) », donc toujours préfixé.
    """
    return json.dumps({"result": name})


KOBOLDCPP_VERSION_BODY = koboldcpp_version_body()
KOBOLDCPP_MODEL_BODY = koboldcpp_model_body()

# L'exemple de réponse que le produit documente lui-même pour cette route
# (embd_res/kcpp_docs.embd), recopié clé pour clé.
KOBOLDCPP_DOCUMENTED_VERSION_BODY = (
    '{\n   "result": "KoboldCpp",\n   "version": "2025.06.03",\n'
    '   "protected": false,\n   "txt2img": false,\n   "vision": false,\n'
    '   "transcribe": false,\n   "multiplayer": false,\n'
    '   "websearch": false,\n   "tts": false,\n   "embeddings": false\n}'
)

# Jusqu'à la 1.60, la route ne rendait que le produit et sa version : rien dans
# la réponse ne dit alors si une clé est exigée.
KOBOLDCPP_VERSION_BODY_1_60 = '{"result": "KoboldCpp", "version": "1.60"}'

# La même instance, --password posé : has_password vaut True et la route répond
# quand même, puisqu'elle n'est pas gardée.
KOBOLDCPP_PROTECTED_VERSION_BODY = koboldcpp_version_body(protected=True)

# Ce que rend alors /api/v1/model : le vrai nom est remplacé, mais le préfixe
# reste. C'est /api/extra/version, et lui seul, qui doit écarter cette instance.
KOBOLDCPP_PROTECTED_MODEL_BODY = koboldcpp_model_body("koboldcpp/protected-model")

# Une instance sans modèle chargé : friendlymodelname vaut encore sa valeur
# initiale. Elle ne sert rien, il n'y a pas de constat à porter.
KOBOLDCPP_INACTIVE_MODEL_BODY = koboldcpp_model_body("inactive")

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
KOBOLDCPP_COMPOSITE_VERSION_BODY = (
    '{"kobold": %s, "checked_at": 0}' % KOBOLDCPP_VERSION_BODY
)

# KoboldAI United sert la même route /api/v1/model, avec la même clé racine,
# mais son nom de modèle ne porte pas le préfixe que KoboldCpp ajoute.
KOBOLDAI_UNITED_MODEL_BODY = koboldcpp_model_body("KoboldAI/OPT-6.7B-Nerybus-Mix")

# Un serveur quelconque qui répond 200 et un objet JSON à tout ce qu'on lui
# demande.
OTHER_RESULT_BODY = '{"result": "ok"}'


def koboldcpp_block():
    doc = load(KOBOLDCPP_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(KOBOLDCPP_VERSION_ROUTE)
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {KOBOLDCPP_VERSION_ROUTE} — c'est "
        "pourtant la seule route qui dit à la fois le produit et l'absence de "
        "mot de passe"
    )
    return blocks[0]


def koboldcpp_requests():
    """
    (méthode, chemin) de chaque requête, dans l'ordre déclaré : c'est cet ordre
    qui donne son numéro à chaque body_N.
    """
    block = koboldcpp_block()
    return [normalise_route(block.get("method"), target)
            for target in (block.get("path") or [])]


def koboldcpp_fires(version=(200, KOBOLDCPP_VERSION_BODY),
                    model=(200, KOBOLDCPP_MODEL_BODY)):
    scenario = {KOBOLDCPP_VERSION_ROUTE: version, KOBOLDCPP_MODEL_ROUTE: model}
    block = koboldcpp_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = []
    for _, route in koboldcpp_requests():
        assert route in scenario, (
            f"le template interroge un chemin que KoboldCpp ne sert pas : {route}"
        )
        responses.append(scenario[route])
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_koboldcpp_probe_reads_two_routes_and_never_runs_a_generation():
    assert koboldcpp_block().get("req-condition") is True, (
        "le template ne lie pas les deux réponses : sans req-condition, ni "
        "body_N ni status_code_N n'existent, et /api/v1/model — qui ne dit "
        "rien de l'absence d'authentification — conclurait de son côté"
    )

    assert koboldcpp_requests() == [
        ("GET", KOBOLDCPP_VERSION_ROUTE), ("GET", KOBOLDCPP_MODEL_ROUTE),
    ], (
        "les deux requêtes ne sont plus celles que le template documente — "
        f"{koboldcpp_requests()}"
    )

    doc = load(KOBOLDCPP_TEMPLATE)
    for method, route in sorted(request_routes(doc)):
        assert method == "GET", (
            f"{method} {route} : le même processus sans garde sert des routes "
            "qui consomment le GPU de l'exploitant, et aucune n'est nécessaire "
            "pour signaler l'exposition"
        )
        for forbidden, why in (
            ("generate",
             "les routes de génération font tourner le modèle de l'exploitant "
             "sur son matériel"),
            ("completions",
             "/v1/completions et /v1/chat/completions font tourner le modèle "
             "au même titre"),
            ("sdapi",
             "les routes sdapi lancent le moteur Stable Diffusion, et ce sont "
             "précisément celles qu'aucun mot de passe ne garde"),
            ("images",
             "/images/generations lance la génération d'image sur le matériel "
             "de l'exploitant"),
            ("admin",
             "POST /api/admin/reload_config déchargerait le modèle ou "
             "rebasculerait l'instance sur une autre configuration"),
            ("transcribe",
             "/api/extra/transcribe fait tourner le moteur Whisper"),
            ("embeddings",
             "/api/extra/embeddings fait tourner le moteur de vectorisation"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_koboldcpp_matcher_rests_on_the_capability_literal_not_on_the_status():
    assert koboldcpp_fires(), (
        "le template ne reconnaît pas la réponse par défaut de "
        "get_capabilities() sur une instance dont l'exploitant n'a rien changé"
    )
    assert koboldcpp_fires(version=(200, KOBOLDCPP_DOCUMENTED_VERSION_BODY)), (
        "le template ne reconnaît pas l'exemple de réponse que le produit "
        "documente lui-même pour cette route (embd_res/kcpp_docs.embd)"
    )

    assert not koboldcpp_fires(version=(200, KOBOLDCPP_PROTECTED_VERSION_BODY),
                               model=(200, KOBOLDCPP_PROTECTED_MODEL_BODY)), (
        "le template remonte une instance lancée avec --password : la route de "
        "découverte n'est pas gardée et répond de la même façon, "
        "« protected »:true près, donc c'est ce booléen — et non le statut "
        "HTTP, qui vaut 200 des deux côtés — qui doit trancher"
    )
    assert not koboldcpp_fires(version=(200, KOBOLDCPP_COMPOSITE_VERSION_BODY)), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur la clé racine qui dit que l'instance "
        "a répondu d'elle-même"
    )
    assert not koboldcpp_fires(version=(401, '{"detail": {"error": '
                                             '"Unauthorized"}}')), (
        "le template conclut alors qu'un intermédiaire a refusé la requête"
    )
    assert not koboldcpp_fires(version=(200, OTHER_RESULT_BODY),
                               model=(200, OTHER_RESULT_BODY)), (
        "le template déclenche sur un serveur quelconque qui rend un objet "
        "JSON à clé « result » — c'est le littéral « KoboldCpp », écrit en dur "
        "par get_capabilities(), qui nomme le produit"
    )

    # Collisions internes au pack : les autres serveurs d'inférence locaux ne
    # doivent pas être revendiqués par celui-ci.
    for other_body, other_name in (
        (LLAMACPP_PROPS_BODY, "llama.cpp"),
        (LMSTUDIO_MODELS_BODY, "lmstudio"),
    ):
        assert not koboldcpp_fires(version=(200, other_body),
                                   model=(200, other_body)), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_koboldcpp_matcher_holds_across_versions_and_spacings():
    """
    Le jeu de clés n'a fait que croître, et l'espacement dépend du sérialiseur
    autant que des intermédiaires : le template ne doit dépendre ni de l'un ni
    de l'autre.
    """
    for flags, release in (
        (KOBOLDCPP_FLAGS_1_61, "1.61"),
        (KOBOLDCPP_FLAGS_1_67, "1.67"),
        (KOBOLDCPP_FLAGS_1_80, "1.80"),
    ):
        assert koboldcpp_fires(
            version=(200, koboldcpp_version_body(flags=flags, version=release))
        ), (
            f"le template exige des clés que la {release} ne rend pas encore — "
            "il raterait les instances anciennes, qui sont précisément celles "
            "qui traînent exposées"
        )

    assert koboldcpp_fires(version=(200, koboldcpp_version_body(compact=True))), (
        "le template dépend de l'espacement de json.dumps : le même document "
        "écrit sans espace après les séparateurs ne doit pas lui échapper"
    )
    assert koboldcpp_fires(version=(200, koboldcpp_version_body(indent=2)),
                           model=(200, json.dumps(json.loads(
                               KOBOLDCPP_MODEL_BODY), indent=2))), (
        "le template exige la sérialisation d'origine : un intermédiaire qui "
        "réindenterait ce qu'il relaie ferait manquer l'instance"
    )

    assert not koboldcpp_fires(version=(200, KOBOLDCPP_VERSION_BODY_1_60)), (
        "le template remonte une instance antérieure à la 1.61, dont la route "
        "ne rend que result et version : rien dans cette réponse ne dit si une "
        "clé est exigée, et le constat porte sur l'absence de garde, pas sur "
        "la présence du produit"
    )


def test_koboldcpp_confirmation_needs_a_model_the_server_actually_names():
    assert not koboldcpp_fires(model=(200, KOBOLDCPP_INACTIVE_MODEL_BODY)), (
        "le template remonte une instance sans modèle chargé, dont "
        "friendlymodelname vaut encore « inactive » : elle ne sert rien"
    )
    assert not koboldcpp_fires(model=(200, KOBOLDAI_UNITED_MODEL_BODY)), (
        "le template déclenche sur un serveur KoboldAI qui sert la même route "
        "avec la même clé racine — c'est le préfixe « koboldcpp/ », ajouté par "
        "le serveur et non par l'exploitant, qui désigne ce produit-ci"
    )
    assert not koboldcpp_fires(model=(404, '{"detail": "Not Found"}')), (
        "le template conclut sans que /api/v1/model ait confirmé : la "
        "corroboration par un chemin de code disjoint est ce qui écarte un "
        "cache ou un proxy statique qui rejouerait la première réponse"
    )


def test_koboldcpp_conclusion_is_carried_by_the_dsl_alone():
    block = koboldcpp_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les deux réponses par leur numéro"
    )


def test_koboldcpp_extractor_reports_the_model_the_instance_serves():
    extractors = koboldcpp_block().get("extractors") or []
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le "
        "moteur émet un résultat par extracteur qui rend quelque chose, donc "
        "la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la réponse est un document JSON : une expression regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("part") == "body_2", (
        "l'extracteur n'est pas borné à body_2 — c'est /api/v1/model qui nomme "
        "le modèle de l'exploitant, la réponse de /api/extra/version ne porte "
        "que la version et des booléens"
    )
    assert extractor.get("json") == [".result"], (
        "l'extracteur ne lit pas .result — c'est pourtant le nom du modèle "
        "servi, donc ce que l'exposition divulgue et ce qu'un tiers "
        "consommerait sur /api/v1/generate"
    )


# --------------------------------------------------------------------------
# InvokeAI ne porte pas son authentification en middleware mais en dépendances
# FastAPI déclarées route par route, et le suffixe « OrDefault » de celles que
# presque toutes les routes portent dit exactement ce qu'elles font :
# get_current_user_or_default() ouvre sur « if not config.multiuser: return
# TokenData(user_id="system", email="system@system.invokeai", is_admin=True) »,
# et require_admin_or_default() n'y ajoute qu'un « if not
# current_user.is_admin ». Hors mode multi-utilisateur — qui n'est pas le
# défaut, « multiuser: bool = Field(default=False, ...) » — un appelant anonyme
# est donc servi comme administrateur.
#
# GET /api/v1/app/runtime_config est la route qui en fait la démonstration :
# elle est marquée AdminUserOrDefault et rend
# InvokeAIAppConfigWithSetFields, déclaré « set_fields: set[str] » puis
# « config: InvokeAIAppConfig ». FastAPI sérialise dans l'ordre de déclaration,
# donc set_fields ouvre le document — mais son contenu, lui, ne se prédit pas :
# c'est un ensemble Python, son ordre n'est pas reproductible d'un processus à
# l'autre, et il vaut « [] » sur une instance qui n'a rien surchargé.

INVOKEAI_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                 "invokeai-runtime-config-exposed.yaml")

INVOKEAI_RUNTIME_CONFIG_ROUTE = "/api/v1/app/runtime_config"
INVOKEAI_VERSION_ROUTE = "/api/v1/app/version"
INVOKEAI_MODELS_ROUTE = "/api/v2/models"

# Les champs d'InvokeAIAppConfig dans l'ordre où config_default.py les déclare
# — c'est cet ordre que pydantic recopie, et il place models_dir, outputs_dir
# et patchmatch loin les uns des autres. Un extrait représentatif suffit ici :
# ce que le template doit tolérer, c'est justement qu'il en manque ou qu'il en
# apparaisse.
INVOKEAI_CONFIG_DEFAULTS = {
    "schema_version": "4.0.3",
    "legacy_models_yaml_path": None,
    "host": "0.0.0.0",
    "port": 9090,
    "allow_origins": [],
    "allow_credentials": True,
    "allow_methods": ["*"],
    "allow_headers": ["*"],
    "ssl_certfile": None,
    "ssl_keyfile": None,
    "base_url": None,
    "forwarded_allow_ips": "127.0.0.1",
    "http_compression_level": 9,
    "log_tokenization": False,
    "patchmatch": True,
    "models_dir": "models",
    "convert_cache_dir": "models/.convert_cache",
    "download_cache_dir": "models/.download_cache",
    "legacy_conf_dir": "configs",
    "db_dir": "databases",
    "outputs_dir": "outputs",
    "image_subfolder_strategy": "flat",
    "custom_nodes_dir": "nodes",
    "style_presets_dir": "style_presets",
    "workflow_thumbnails_dir": "workflow_thumbnails",
    "log_handlers": ["console"],
    "log_format": "color",
    "log_level": "info",
    "log_sql": False,
    "log_level_network": "warning",
    "use_memory_db": False,
    "profiles_dir": "profiles",
    "max_cache_ram_gb": None,
    "max_cache_vram_gb": None,
    "device_working_mem_gb": 3.0,
    "enable_partial_loading": True,
    "keep_ram_copy_of_weights": True,
    "ram": None,
    "vram": None,
    "lazy_offload": True,
    "precision": "auto",
    "attention_type": "auto",
    "attention_slice_size": "auto",
    "hashing_algorithm": "blake3_single",
    "remote_api_tokens": None,
    "allow_private_download_urls": False,
    "download_proxy": None,
    "unsafe_disable_picklescan": False,
    "multiuser": False,
    "strict_password_checking": False,
    "external_openai_api_key": None,
}


def invokeai_runtime_config_body(set_fields=("host", "outputs_dir", "precision"),
                                 drop=(), extra=None, indent=None):
    """
    Ce que rend GET /api/v1/app/runtime_config : le modèle de réponse
    sérialisé dans l'ordre de déclaration, donc set_fields puis config.

    `set_fields` est écrit tel quel — c'est un ensemble côté serveur, donc
    l'ordre reçu n'est pas celui d'une exécution à l'autre. `drop` retire des
    champs de config comme le ferait une version plus ancienne, `extra` en
    ajoute comme le ferait une plus récente, `indent` réécrit le document
    comme le ferait un intermédiaire qui réindente ce qu'il relaie.
    """
    config = {k: v for k, v in INVOKEAI_CONFIG_DEFAULTS.items() if k not in drop}
    config.update(extra or {})
    document = {"set_fields": list(set_fields), "config": config}
    if indent is not None:
        return json.dumps(document, indent=indent)
    # La JSONResponse de FastAPI écrit compact.
    return json.dumps(document, separators=(",", ":"))


def invokeai_version_body(version="6.14.0-post1"):
    """AppVersion ne déclare qu'un champ, rempli par invokeai.version.__version__."""
    return json.dumps({"version": version}, separators=(",", ":"))


def invokeai_models_body(names=("sd_xl_base_1.0", "flux-schnell")):
    """ModelsList ne déclare qu'un champ, « models: List[AnyModelConfig] »."""
    return json.dumps(
        {"models": [{"key": "b1a2c3d4", "name": n, "base": "sdxl",
                     "type": "main", "format": "checkpoint"} for n in names]},
        separators=(",", ":"),
    )


INVOKEAI_RUNTIME_CONFIG_BODY = invokeai_runtime_config_body()
INVOKEAI_VERSION_BODY = invokeai_version_body()
INVOKEAI_MODELS_BODY = invokeai_models_body()

# La même instance en mode multi-utilisateur : la dépendance ne synthétise plus
# de jeton system, et FastAPI referme la route avant le handler.
INVOKEAI_MULTIUSER_401_BODY = '{"detail":"Authentication required"}'

# Un compte authentifié mais non administrateur : require_admin_or_default()
# s'arrête sur « if not current_user.is_admin ».
INVOKEAI_NON_ADMIN_403_BODY = '{"detail":"Admin privileges required"}'

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
INVOKEAI_COMPOSITE_BODY = (
    '{"invokeai":%s,"checked_at":0}' % INVOKEAI_RUNTIME_CONFIG_BODY
)

# Un service quelconque qui rend un numéro de version sous la même clé racine —
# c'est-à-dire tout ce que /api/v1/app/version prouve à lui seul.
GENERIC_VERSION_BODY = '{"version":"1.4.2"}'


def invokeai_block():
    doc = load(INVOKEAI_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(INVOKEAI_RUNTIME_CONFIG_ROUTE)
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {INVOKEAI_RUNTIME_CONFIG_ROUTE} — c'est "
        "pourtant la seule route qui prouve qu'un anonyme est servi comme "
        "administrateur, les deux autres répondant sans rien dire du mode"
    )
    return blocks[0]


def invokeai_requests():
    """
    (méthode, chemin) de chaque requête, dans l'ordre déclaré : c'est cet ordre
    qui donne son numéro à chaque body_N.
    """
    block = invokeai_block()
    return [normalise_route(block.get("method"), target)
            for target in (block.get("path") or [])]


def invokeai_fires(runtime_config=(200, INVOKEAI_RUNTIME_CONFIG_BODY),
                   version=(200, INVOKEAI_VERSION_BODY),
                   models=(200, INVOKEAI_MODELS_BODY)):
    scenario = {
        INVOKEAI_RUNTIME_CONFIG_ROUTE: runtime_config,
        INVOKEAI_VERSION_ROUTE: version,
        INVOKEAI_MODELS_ROUTE: models,
    }
    block = invokeai_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = []
    for _, route in invokeai_requests():
        assert route in scenario, (
            f"le template interroge un chemin qu'InvokeAI ne sert pas : {route}"
        )
        responses.append(scenario[route])
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les trois réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_invokeai_probe_reads_three_routes_and_never_writes():
    assert invokeai_block().get("req-condition") is True, (
        "le template ne lie pas les réponses : sans req-condition, ni body_N "
        "ni status_code_N n'existent, et /api/v1/app/version — qui ne porte "
        "aucune dépendance d'authentification et répond donc même en mode "
        "multi-utilisateur — conclurait de son côté"
    )

    assert invokeai_requests() == [
        ("GET", INVOKEAI_RUNTIME_CONFIG_ROUTE),
        ("GET", INVOKEAI_VERSION_ROUTE),
        ("GET", INVOKEAI_MODELS_ROUTE),
    ], (
        "les trois requêtes ne sont plus celles que le template documente — "
        f"{invokeai_requests()}"
    )

    doc = load(INVOKEAI_TEMPLATE)
    for method, route in sorted(request_routes(doc)):
        assert method == "GET", (
            f"{method} {route} : les mêmes dépendances *OrDefault gardent les "
            "verbes d'écriture, à commencer par PATCH "
            "/api/v1/app/runtime_config qui persiste ce qu'il change dans "
            "invokeai.yaml — aucun n'est nécessaire pour signaler l'exposition"
        )
        for forbidden, why in (
            ("/install",
             "POST /api/v2/models/install fait installer un modèle depuis une "
             "URL choisie par l'appelant, sur une instance dont "
             "unsafe_disable_picklescan dit si le contrôle de désérialisation "
             "est actif"),
            ("hf_login",
             "POST /api/v2/models/hf_login écrit un jeton Hugging Face dans le "
             "trousseau de l'hôte"),
            ("/convert",
             "/api/v2/models/convert/{key} réécrit un modèle de l'exploitant"),
            ("empty_model_cache",
             "vider le cache de modèles ferait recharger depuis le disque une "
             "instance qu'on est censé seulement observer"),
            ("/queue",
             "les routes de file de session font tourner le modèle sur le "
             "matériel de l'exploitant"),
            ("/logging",
             "PUT /api/v1/app/logging change le niveau de journalisation de "
             "l'instance, donc ce qu'elle enregistrera de la visite"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_invokeai_matcher_rests_on_the_set_fields_pair_not_on_the_status():
    assert invokeai_fires(), (
        "le template ne reconnaît pas la réponse d'une instance dont "
        "l'exploitant n'a changé que la liaison réseau"
    )

    assert not invokeai_fires(
        runtime_config=(401, INVOKEAI_MULTIUSER_401_BODY),
        models=(401, INVOKEAI_MULTIUSER_401_BODY),
    ), (
        "le template remonte une instance en mode multi-utilisateur, où la "
        "dépendance ne synthétise plus de jeton system : c'est précisément "
        "l'instance qui n'a rien à signaler"
    )
    assert not invokeai_fires(
        runtime_config=(403, INVOKEAI_NON_ADMIN_403_BODY),
    ), (
        "le template remonte une instance où require_admin_or_default() a "
        "refusé l'appelant : la route a répondu, mais pas la configuration"
    )
    assert not invokeai_fires(runtime_config=(200, INVOKEAI_COMPOSITE_BODY)), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur la clé racine qui dit que l'instance "
        "a répondu d'elle-même"
    )
    assert not invokeai_fires(
        runtime_config=(200, GENERIC_VERSION_BODY),
        version=(200, GENERIC_VERSION_BODY),
        models=(200, GENERIC_VERSION_BODY),
    ), (
        "le template conclut sur un service quelconque qui rend un numéro de "
        "version : c'est le couple set_fields + config, propre à "
        "InvokeAIAppConfigWithSetFields, qui nomme le produit"
    )

    # Le statut, seul, ne départage rien : les trois routes rendent 200 sur une
    # instance ouverte comme sur n'importe quel serveur vivant.
    assert not invokeai_fires(runtime_config=(200, '{"config":{}}')), (
        "le template se contente de la clé config : set_fields est la moitié "
        "qui nomme le modèle de réponse d'InvokeAI"
    )

    # Collisions internes au pack : les deux autres interfaces de génération
    # d'images déjà couvertes ne doivent pas être revendiquées par celle-ci.
    for other_body, other_name in (
        (COMFYUI_SYSTEM_STATS_BODY, "ComfyUI"),
        (AUTOMATIC1111_SD_MODELS_BODY, "AUTOMATIC1111"),
    ):
        assert not invokeai_fires(runtime_config=(200, other_body),
                                  version=(200, other_body),
                                  models=(200, other_body)), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_invokeai_matcher_holds_across_config_shapes_and_spacings():
    """
    Rien du contenu de set_fields ne se prédit — c'est un ensemble Python, il
    peut être vide — et le modèle de configuration gagne des champs à chaque
    version. Le template ne doit dépendre ni de l'un ni de l'autre.
    """
    assert invokeai_fires(
        runtime_config=(200, invokeai_runtime_config_body(set_fields=()))
    ), (
        "le template exige un set_fields non vide : une instance qui n'a "
        "surchargé aucun réglage rend « [] », et c'est l'instance la plus "
        "courante — celle qu'on lance sans rien configurer"
    )
    assert invokeai_fires(
        runtime_config=(200, invokeai_runtime_config_body(
            set_fields=("precision", "host", "models_dir", "port")))
    ), (
        "le template dépend de l'ordre des éléments de set_fields : côté "
        "serveur c'est un « set[str] », dont l'itération n'est pas "
        "reproductible d'un processus à l'autre"
    )

    assert invokeai_fires(
        runtime_config=(200, invokeai_runtime_config_body(drop=(
            "image_subfolder_strategy", "workflow_thumbnails_dir",
            "http_compression_level", "external_openai_api_key",
            "strict_password_checking",
        )))
    ), (
        "le template exige des champs que les versions antérieures ne rendent "
        "pas encore — il raterait les instances anciennes, qui sont "
        "précisément celles qui traînent exposées"
    )
    assert invokeai_fires(
        runtime_config=(200, invokeai_runtime_config_body(
            extra={"un_reglage_a_venir": "peu importe"}))
    ), (
        "le template exige une adjacence entre les champs sur lesquels il "
        "s'appuie : le modèle en gagne à chaque version, et ils s'intercalent"
    )

    assert invokeai_fires(
        runtime_config=(200, invokeai_runtime_config_body(indent=2)),
        version=(200, json.dumps(json.loads(INVOKEAI_VERSION_BODY), indent=2)),
        models=(200, json.dumps(json.loads(INVOKEAI_MODELS_BODY), indent=2)),
    ), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )

    assert not invokeai_fires(
        runtime_config=(200, invokeai_runtime_config_body(
            drop=("models_dir", "outputs_dir", "patchmatch")))
    ), (
        "le template se contente du couple set_fields + config sans rien "
        "exiger de la configuration elle-même : trois champs anciens du "
        "modèle sont ce qui distingue InvokeAI d'un service quelconque qui "
        "emploierait les deux mêmes noms"
    )


def test_invokeai_confirmation_needs_both_disjoint_routes():
    assert not invokeai_fires(version=(404, '{"detail":"Not Found"}')), (
        "le template conclut sans que /api/v1/app/version ait confirmé : la "
        "corroboration par un chemin de code disjoint — get_version() lit "
        "__version__ et ne touche pas à get_config() — est ce qui écarte un "
        "cache ou un proxy statique qui rejouerait la première réponse"
    )
    assert not invokeai_fires(models=(401, INVOKEAI_MULTIUSER_401_BODY)), (
        "le template conclut alors que /api/v2/models/ a refusé : c'est cette "
        "route, gardée par CurrentUserOrDefault sur un autre routeur, qui dit "
        "que la couche utilisateur est ouverte elle aussi"
    )
    assert invokeai_fires(models=(200, invokeai_models_body(names=()))), (
        "le template exige un inventaire non vide : une instance fraîchement "
        "installée n'a aucun modèle enregistré, et c'est sa configuration — "
        "pas son inventaire — qui est le constat"
    )


def test_invokeai_conclusion_is_carried_by_the_dsl_alone():
    block = invokeai_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les trois réponses par leur numéro"
    )


def test_invokeai_extractor_reports_the_version_the_instance_serves():
    extractors = invokeai_block().get("extractors") or []
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le "
        "moteur émet un résultat par extracteur qui rend quelque chose, donc "
        "la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la réponse est un document JSON : une expression regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("part") == "body_2", (
        "l'extracteur n'est pas borné à body_2 — c'est /api/v1/app/version qui "
        "rend un champ unique et exploitable, là où la configuration de "
        "body_1 est le constat dans son entier et non l'un de ses champs"
    )
    assert extractor.get("json") == [".version"], (
        "l'extracteur ne lit pas .version — c'est pourtant ce qui permet de "
        "dater l'installation et de la confronter aux avis du dépôt"
    )


# --------------------------------------------------------------------------
# text-generation-webui rend le constat entier dans une seule réponse : le
# handler de GET /v1/internal/model/info tient en deux lignes (payload =
# get_current_model_info() ; return JSONResponse(content=payload)), et ce
# dict à trois clés — model_name, lora_names, loader — est écrit en dur dans
# modules/api/models.py. response_model=ModelInfoResponse ne filtre pas
# « loader » ici, parce que le handler retourne un objet Response construit à
# la main plutôt que le dict brut : FastAPI ne revalide un retour au travers
# de response_model que lorsque la fonction rend la donnée elle-même. Une
# seule route suffit donc à porter le constat, sans req-condition.

TEXTGEN_WEBUI_TEMPLATE = os.path.join(
    TEMPLATES_DIR, "exposure", "text-generation-webui-internal-api-exposed.yaml"
)
TEXTGEN_WEBUI_MODEL_INFO_ROUTE = "/v1/internal/model/info"

# Ce que rend get_current_model_info() : le trio exact, tel que Starlette le
# sérialise (JSONResponse.render, séparateurs compacts).
TEXTGEN_WEBUI_MODEL_INFO_BODY = (
    '{"model_name":"Meta-Llama-3.1-8B-Instruct","lora_names":[],'
    '"loader":"llama.cpp"}'
)

# Une instance avec un LoRA chargé : lora_names n'est pas vide.
TEXTGEN_WEBUI_MODEL_INFO_WITH_LORA_BODY = (
    '{"model_name":"Mistral-7B-Instruct-v0.3","lora_names":["my-finetune"],'
    '"loader":"Transformers"}'
)

# Ce que rendrait la route si FastAPI filtrait réellement le retour au
# travers de ModelInfoResponse, qui ne déclare que model_name et lora_names :
# ce n'est pas ce que le produit sert, mais c'est le cas qui distinguerait un
# matcher qui exigerait à tort le trio complet d'un qui se contenterait des
# deux seuls champs déclarés par le modèle de réponse.
TEXTGEN_WEBUI_MODEL_INFO_NO_LOADER_BODY = (
    '{"model_name":"Meta-Llama-3.1-8B-Instruct","lora_names":[]}'
)

# Un endpoint « model info » quelconque, d'un produit sans rapport.
OTHER_MODEL_INFO_BODY = '{"model_name":"whatever","loader":"custom"}'


def textgen_webui_block():
    doc = load(TEXTGEN_WEBUI_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(TEXTGEN_WEBUI_MODEL_INFO_ROUTE)
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {TEXTGEN_WEBUI_MODEL_INFO_ROUTE} — "
        "c'est pourtant la seule route dont le handler rend le trio "
        "model_name/lora_names/loader sans le filtrer"
    )
    return blocks[0]


def test_textgen_webui_probe_reads_one_route_and_never_touches_generation_or_admin():
    doc = load(TEXTGEN_WEBUI_TEMPLATE)
    routes = request_routes(doc)
    assert routes == {("GET", TEXTGEN_WEBUI_MODEL_INFO_ROUTE)}, (
        "le template ne se limite plus à la seule lecture qui porte le "
        f"constat — {routes}"
    )

    for method, route in routes:
        assert method == "GET", (
            f"{method} {route} : verify_api_key() est un no-op tant que "
            "--api-key n'est pas passé, donc le même processus sans garde "
            "servirait une écriture — aucune n'est nécessaire pour signaler "
            "l'exposition"
        )
        for forbidden, why in (
            ("completions",
             "/v1/completions et /v1/chat/completions font tourner le "
             "modèle sur le matériel de l'exploitant"),
            ("chat-prompt",
             "/v1/internal/chat-prompt construit un prompt à partir d'un "
             "historique de conversation"),
            ("images/generations",
             "/v1/images/generations lance la génération d'image sur le "
             "matériel de l'exploitant"),
            ("audio/transcriptions",
             "/v1/audio/transcriptions fait tourner le moteur de "
             "transcription"),
            ("model/load",
             "POST /v1/internal/model/load déchargerait le modèle en place "
             "pour en charger un autre"),
            ("model/unload",
             "POST /v1/internal/model/unload déchargerait le modèle de "
             "l'exploitant"),
            ("lora/load",
             "POST /v1/internal/lora/load changerait les LoRA appliqués"),
            ("lora/unload",
             "POST /v1/internal/lora/unload retirerait les LoRA appliqués"),
            ("stop-generation",
             "POST /v1/internal/stop-generation agit sur une génération en "
             "cours"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_textgen_webui_matcher_requires_the_full_model_info_trio():
    block = textgen_webui_block()
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature "
        "produit peut être court-circuitée"
    )

    body_matchers = [m for m in (block.get("matchers") or [])
                     if m.get("type") == "word" and m.get("part") == "body"]
    assert body_matchers, "aucun matcher sur le corps : la réponse n'est pas vérifiée"
    assert all(m.get("condition") == "and" for m in body_matchers), (
        "un matcher sur les clés du trio en condition « or » se contenterait "
        "d'une seule d'entre elles, qu'un produit sans rapport peut porter"
    )

    assert all(word_matcher_hits(m, TEXTGEN_WEBUI_MODEL_INFO_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas la réponse par défaut de "
        "get_current_model_info() sur une instance dont l'exploitant n'a "
        "chargé aucun LoRA"
    )
    assert all(word_matcher_hits(m, TEXTGEN_WEBUI_MODEL_INFO_WITH_LORA_BODY)
               for m in body_matchers), (
        "le template ne reconnaît pas une instance avec un LoRA chargé"
    )

    assert not all(word_matcher_hits(m, TEXTGEN_WEBUI_MODEL_INFO_NO_LOADER_BODY)
                  for m in body_matchers), (
        "le template déclenche sur un corps qui ne porte que les deux "
        "champs déclarés par ModelInfoResponse — ce n'est pas ce que le "
        "produit sert réellement, puisque le handler rend le dict brut sans "
        "le filtrer au travers de ce modèle"
    )
    assert not all(word_matcher_hits(m, OTHER_MODEL_INFO_BODY)
                  for m in body_matchers), (
        "le template déclenche sur un endpoint « model info » générique "
        "d'un produit sans rapport — c'est le trio complet, propre à "
        "get_current_model_info(), qui doit désigner text-generation-webui"
    )


def test_textgen_webui_extractors_report_model_name_and_loader():
    extractors = textgen_webui_block().get("extractors") or []
    reported = {(e.get("type"), e.get("part"), e.get("name"),
                tuple(e.get("json") or [])) for e in extractors}
    assert reported == {
        ("json", "body", "model_name", (".model_name",)),
        ("json", "body", "loader", (".loader",)),
    }, reported


# --------------------------------------------------------------------------
# MLRun porte son authentification routeur par routeur, dans api.py, sous la
# forme « dependencies=[Depends(deps.authenticate_request)] ». Presque toutes
# les lignes du fichier la portent ; deux ne la portent pas, dont
# « api_router.include_router(client_spec.router, tags=["client-spec"]) ».
# GET /api/v1/client-spec répond donc aussi sur une instance fermée : sa
# réponse nomme le produit et rend sa configuration, elle ne dit rien du mode.
#
# C'est GET /api/v1/frontend-spec qui le dit : même processus, mais son
# routeur est inclus avec authenticate_request, et son corps transcrit
# littéralement httpdb.authentication.mode sous feature_flags —
# _resolve_feature_flags() pose « authentication =
# mlrun.common.types.AuthenticationMode(mlrun.mlconf.httpdb.authentication.mode) ».
# Le défaut du produit est « "authentication": {"mode": "none" » ; en mode
# none, AuthVerifier.authenticate_request() n'entre dans aucune branche et
# rend un AuthInfo() vide sans lever quoi que ce soit.

MLRUN_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                              "mlrun-client-spec-exposed.yaml")

MLRUN_CLIENT_SPEC_ROUTE = "/api/v1/client-spec"
MLRUN_FRONTEND_SPEC_ROUTE = "/api/v1/frontend-spec"

# Un extrait représentatif de ClientSpec, dans l'ordre où le modèle déclare ses
# champs — c'est cet ordre que pydantic recopie et que FastAPI sérialise, et il
# place version en tête puis ui_url, artifact_path et nuclio_version loin les
# uns des autres. Les valeurs sont celles d'une instance qu'on n'a pas
# configurée : artifact_path et ui_url valent la chaîne vide, et tout ce qui
# passe par _get_config_value_if_not_default() vaut null.
MLRUN_CLIENT_SPEC_DEFAULTS = {
    "version": "1.12.0",
    "namespace": "mlrun",
    "docker_registry": "index.docker.io/mlrun",
    "remote_host": None,
    "mpijob_crd_version": "v1",
    "ui_url": "",
    "artifact_path": "",
    "feature_store_data_prefixes": None,
    "feature_store_default_targets": None,
    "spark_app_image": None,
    "spark_app_image_tag": None,
    "spark_history_server_path": None,
    "spark_operator_version": "spark-3",
    "kfp_image": "mlrun/mlrun:1.12.0",
    "kfp_url": "",
    "dask_kfp_image": "mlrun/ml-base:1.12.0",
    "api_url": "http://mlrun-api:8080",
    "nuclio_version": "1.13.24",
    "ui_projects_prefix": None,
    "scrape_metrics": None,
    "default_function_node_selector": None,
    "igz_version": None,
    "auto_mount_type": None,
    "auto_mount_params": None,
    "default_function_priority_class_name": None,
    "valid_function_priority_class_names": None,
    "default_tensorboard_logs_path": None,
    "default_function_pod_resources": None,
    "preemptible_nodes_node_selector": None,
    "preemptible_nodes_tolerations": None,
    "default_preemption_mode": None,
    "force_run_local": None,
    "function": None,
    "redis_url": "",
    "redis_type": "standalone",
    "sql_url": "",
    "ce": {"mode": "full", "release": "0.7.0"},
    "calculate_artifact_hash": None,
    "generate_artifact_target_path_from_artifact_hash": None,
    "logs": None,
    "packagers": None,
    "external_platform_tracking": None,
    "alerts_mode": None,
    "system_id": None,
    "model_endpoint_monitoring_store_prefixes": None,
    # Ajoutés au modèle en 1.11 seulement, et tous deux filtrés quand la
    # configuration vaut son défaut : authentication_mode par
    # _get_config_value_if_not_default("httpdb.authentication.mode"),
    # default_runtime_image_by_kind par _get_config_value_diff_from_default().
    # Ils valent donc null précisément sur l'instance que ce template cherche.
    "authentication_mode": None,
    "oauth_internal_token_endpoint": None,
    "oauth_external_token_endpoint": None,
    "authorization_namespaces_mlrun": None,
    "default_runtime_image_by_kind": None,
    "telemetry_enabled": None,
}

# Ce que le modèle ne déclarait pas encore avant la 1.11 : une instance de
# cette époque rend le même document sans ces clés-là.
MLRUN_FIELDS_ADDED_IN_1_11 = (
    "authentication_mode",
    "oauth_internal_token_endpoint",
    "oauth_external_token_endpoint",
    "authorization_namespaces_mlrun",
    "default_runtime_image_by_kind",
    "telemetry_enabled",
)


def mlrun_client_spec_body(drop=(), extra=None, indent=None, **overrides):
    """
    Ce que rend GET /api/v1/client-spec : ClientSpec sérialisé dans l'ordre de
    déclaration, champs nuls compris — FastAPI n'omet pas les champs nuls d'un
    response_model, et le test amont test_client_spec le vérifie sans le dire en
    lisant « response_body["scrape_metrics"] is None » sur une clé qui doit donc
    exister.

    `drop` retire des champs comme le ferait une version plus ancienne, `extra`
    en ajoute comme le ferait une plus récente, `indent` réécrit le document
    comme le ferait un intermédiaire qui réindente ce qu'il relaie.
    """
    document = {k: v for k, v in MLRUN_CLIENT_SPEC_DEFAULTS.items()
                if k not in drop}
    document.update(overrides)
    document.update(extra or {})
    if indent is not None:
        return json.dumps(document, indent=indent)
    # La JSONResponse de FastAPI écrit compact.
    return json.dumps(document, separators=(",", ":"))


def mlrun_frontend_spec_body(authentication="none", drop=(), indent=None):
    """
    Ce que rend GET /api/v1/frontend-spec, dans l'ordre de déclaration de
    FrontendSpec. `authentication` est la transcription littérale de
    httpdb.authentication.mode par _resolve_feature_flags().
    """
    document = {
        "jobs_dashboard_url": None,
        "model_monitoring_dashboard_url": None,
        "abortable_function_kinds": ["job", "spark"],
        "feature_flags": {
            "project_membership": "disabled",
            "authentication": authentication,
            "nuclio_streams": "disabled",
            "preemption_nodes": "disabled",
        },
        "default_function_priority_class_name": None,
        "valid_function_priority_class_names": [],
        "default_function_image_by_kind": {},
        "function_deployment_target_image_template":
            "index.docker.io/mlrun/func-{project}-{name}:{tag}",
        "function_deployment_target_image_name_prefix_template": "func-{project}-{name}",
        "function_deployment_target_image_registries_to_enforce_prefix": [],
        "function_deployment_mlrun_requirement": "mlrun[complete]==1.12.0",
        "auto_mount_type": "none",
        "auto_mount_params": {},
        "default_artifact_path": "",
        "default_function_pod_resources": {"requests": {}, "limits": {}},
        "default_function_preemption_mode": "prevent",
        "feature_store_data_prefixes": {"default": "v3io:///projects/{project}"},
        "allowed_artifact_path_prefixes_list": [],
        "ce": {"mode": "full", "release": "0.7.0"},
        "internal_labels": [],
        "artifact_limits": {"max_chunk_size": 10485760,
                            "max_preview_size": 1048576,
                            "max_download_size": 5368709120},
    }
    document = {k: v for k, v in document.items() if k not in drop}
    if indent is not None:
        return json.dumps(document, indent=indent)
    return json.dumps(document, separators=(",", ":"))


MLRUN_CLIENT_SPEC_BODY = mlrun_client_spec_body()
MLRUN_FRONTEND_SPEC_BODY = mlrun_frontend_spec_body()

# La garde a tenu : le routeur frontend-spec porte
# authenticate_request, et _authenticate_basic() lève
# MLRunUnauthorizedError("Missing basic auth header"), que
# _http_status_error_handler() rend sous la clé « detail » de FastAPI.
MLRUN_UNAUTHORIZED_BODY = (
    '{"detail":"MLRunUnauthorizedError(\'Missing basic auth header\')"}'
)

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
MLRUN_COMPOSITE_BODY = '{"mlrun":%s,"checked_at":0}' % MLRUN_CLIENT_SPEC_BODY


def mlrun_block():
    doc = load(MLRUN_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(MLRUN_CLIENT_SPEC_ROUTE)
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {MLRUN_CLIENT_SPEC_ROUTE} — c'est "
        "pourtant la seule route qui rende ClientSpec, donc la seule qui nomme "
        "le produit et divulgue sa configuration"
    )
    return blocks[0]


def mlrun_requests():
    """
    (méthode, chemin) de chaque requête, dans l'ordre déclaré : c'est cet ordre
    qui donne son numéro à chaque body_N.
    """
    block = mlrun_block()
    return [normalise_route(block.get("method"), target)
            for target in (block.get("path") or [])]


def mlrun_fires(client_spec=(200, MLRUN_CLIENT_SPEC_BODY),
                frontend_spec=(200, MLRUN_FRONTEND_SPEC_BODY)):
    scenario = {
        MLRUN_CLIENT_SPEC_ROUTE: client_spec,
        MLRUN_FRONTEND_SPEC_ROUTE: frontend_spec,
    }
    block = mlrun_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = []
    for _, route in mlrun_requests():
        assert route in scenario, (
            f"le template interroge un chemin que MLRun ne sert pas : {route}"
        )
        responses.append(scenario[route])
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_mlrun_probe_reads_two_routes_and_never_submits_nor_builds():
    assert mlrun_block().get("req-condition") is True, (
        "le template ne lie pas les réponses : sans req-condition, ni body_N "
        "ni status_code_N n'existent, et /api/v1/client-spec — dont le routeur "
        "est inclus sans authenticate_request et qui répond donc aussi sur une "
        "instance fermée — conclurait de son côté"
    )

    assert mlrun_requests() == [
        ("GET", MLRUN_CLIENT_SPEC_ROUTE),
        ("GET", MLRUN_FRONTEND_SPEC_ROUTE),
    ], (
        "les deux requêtes ne sont plus celles que le template documente — "
        f"{mlrun_requests()}"
    )

    doc = load(MLRUN_TEMPLATE)
    for method, route in sorted(request_routes(doc)):
        assert method == "GET", (
            f"{method} {route} : en mode « none » l'anonyme est accepté sur "
            "tous les routeurs, y compris ceux qui écrivent — aucun n'est "
            "nécessaire pour signaler l'exposition"
        )
        for forbidden, why in (
            ("submit",
             "POST /api/v1/submit_job fait tourner une fonction sur le "
             "cluster de l'exploitant"),
            ("build",
             "POST /api/v1/build/function déclenche une construction d'image"),
            ("start/function",
             "POST /api/v1/start/function démarre une fonction"),
            ("secrets",
             "GET /api/v1/projects/{project}/secrets rend les secrets de "
             "projet en clair, le contrôle passant par le provider nop"),
            ("/projects",
             "les routes de projet touchent aux données de l'exploitant, et "
             "DELETE /api/v1/projects/{name} en supprime un"),
            ("/logs",
             "les routes de journaux rendent la sortie des exécutions"),
            ("/operations",
             "/api/v1/operations/migrations déclenche une migration de base"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_mlrun_matcher_rests_on_the_client_spec_shape_not_on_the_status():
    assert mlrun_fires(), (
        "le template ne reconnaît pas la réponse d'une instance laissée à ses "
        "défauts — celle, précisément, dont le mode d'authentification est "
        "« none »"
    )

    assert not mlrun_fires(client_spec=(200, MLRUN_COMPOSITE_BODY)), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur la clé racine qui dit que l'instance "
        "a répondu d'elle-même"
    )
    assert not mlrun_fires(client_spec=(200, GENERIC_VERSION_BODY)), (
        "le template conclut sur un service quelconque qui rend un numéro de "
        "version sous la même clé racine : c'est le trio nuclio_version + "
        "artifact_path + ui_url, propre à ClientSpec, qui nomme le produit"
    )

    # Le statut, seul, ne départage rien : les deux routes rendent 200 sur une
    # instance ouverte comme sur n'importe quel serveur vivant.
    assert not mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(
            drop=("nuclio_version", "artifact_path", "ui_url")))
    ), (
        "le template se contente d'un document qui s'ouvre sur « version » : "
        "le trio est ce qui distingue MLRun de tout autre service qui "
        "rendrait sa configuration"
    )

    # Collisions internes au pack : les deux autres plateformes MLOps déjà
    # couvertes ne doivent pas être revendiquées par celle-ci.
    for other_body, other_name in (
        (MLFLOW_EXPERIMENTS_BODY, "MLflow"),
        (KUBEFLOW_PIPELINES_BODY, "Kubeflow Pipelines"),
    ):
        assert not mlrun_fires(client_spec=(200, other_body),
                               frontend_spec=(200, other_body)), (
            f"le template déclenche sur {other_name}, déjà couvert par son "
            "propre template"
        )


def test_mlrun_matcher_holds_across_versions_and_spacings():
    """
    Le modèle gagne des champs à chaque version, et ceux sur lesquels il serait
    tentant de s'appuyer sont justement les plus récents et les plus souvent
    nuls. Le template ne doit dépendre ni des uns ni des autres.
    """
    assert mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(drop=MLRUN_FIELDS_ADDED_IN_1_11))
    ), (
        "le template exige des champs que le modèle n'a gagnés qu'en 1.11 — "
        "authentication_mode et default_runtime_image_by_kind en tête — donc "
        "il raterait toutes les instances antérieures, qui sont précisément "
        "celles qui traînent exposées"
    )
    assert mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(
            extra={"un_reglage_a_venir": "peu importe"}))
    ), (
        "le template exige une adjacence entre les champs sur lesquels il "
        "s'appuie : le modèle en gagne à chaque version, et ils s'intercalent"
    )

    assert mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(
            nuclio_version=None, ui_url="", artifact_path=""))
    ), (
        "le template exige une valeur du trio : resolve_nuclio_version() rend "
        "null quand aucun tableau de bord Nuclio n'est joignable, et les "
        "défauts d'artifact_path et de ui.url sont la chaîne vide — c'est la "
        "présence des clés qui porte le constat"
    )

    assert mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(indent=2)),
        frontend_spec=(200, mlrun_frontend_spec_body(indent=2)),
    ), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )

    assert not mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(drop=(
            "docker_registry", "feature_store_data_prefixes",
            "spark_operator_version")))
    ), (
        "le template se contente du trio : trois champs de plus, tous déclarés "
        "en tête du modèle depuis la 1.4, sont ce qui dit que le document est "
        "bien un ClientSpec et non un objet quelconque portant trois noms en "
        "commun"
    )


def test_mlrun_conclusion_needs_the_route_that_carries_the_guard():
    assert not mlrun_fires(frontend_spec=(401, MLRUN_UNAUTHORIZED_BODY)), (
        "le template conclut alors que /api/v1/frontend-spec a refusé : c'est "
        "la seule des deux routes dont le routeur porte "
        "authenticate_request, donc la seule dont la réponse dise que "
        "l'anonyme a été accepté"
    )
    assert not mlrun_fires(frontend_spec=(404, GENERIC_BAD_REQUEST_BODY)), (
        "le template conclut sans corroboration par un chemin de code "
        "disjoint : c'est elle qui écarte un cache ou un proxy statique qui "
        "rejouerait la première réponse"
    )
    assert not mlrun_fires(frontend_spec=(200, GENERIC_VERSION_BODY)), (
        "le template se contente d'un 200 sur la seconde route : un portail "
        "captif ou un proxy peut rendre 200 sur n'importe quel chemin, et "
        "c'est le couple feature_flags + default_artifact_path qui dit que la "
        "réponse vient bien de FrontendSpec"
    )

    for mode in ("basic", "bearer", "iguazio", "iguazio-v4"):
        assert not mlrun_fires(
            frontend_spec=(200, mlrun_frontend_spec_body(authentication=mode))
        ), (
            f"le template remonte une instance dont feature_flags annonce le "
            f"mode « {mode} » : _resolve_feature_flags() transcrit "
            "httpdb.authentication.mode tel quel, et le constat porte sur le "
            "défaut « none », pas sur la présence du produit"
        )

    assert mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(authentication_mode=None)),
    ), (
        "le template exige une valeur d'authentication_mode dans ClientSpec : "
        "il passe par _get_config_value_if_not_default(), donc il est nul "
        "exactement quand le mode « none » est en vigueur — son absence de "
        "valeur confirme l'exposition, elle ne peut pas l'établir"
    )
    assert not mlrun_fires(
        client_spec=(200, mlrun_client_spec_body(authentication_mode="bearer")),
        frontend_spec=(200, mlrun_frontend_spec_body(authentication="bearer")),
    ), (
        "le template déclenche sur une instance dont l'exploitant a posé un "
        "mode : authentication_mode n'est renseigné que lorsqu'il diffère du "
        "défaut, donc sa présence dit l'inverse du constat"
    )


def test_mlrun_conclusion_is_carried_by_the_dsl_alone():
    block = mlrun_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les deux réponses par leur numéro"
    )


def test_mlrun_extractor_reports_the_version_the_instance_serves():
    extractors = mlrun_block().get("extractors") or []
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le "
        "moteur émet un résultat par extracteur qui rend quelque chose, donc "
        "la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la réponse est un document JSON : une expression regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("part") == "body_1", (
        "l'extracteur n'est pas borné à body_1 — c'est ClientSpec qui porte "
        "« version », rempli par config.version, là où FrontendSpec ne rend "
        "aucun numéro de version"
    )
    assert extractor.get("json") == [".version"], (
        "l'extracteur ne lit pas .version — c'est pourtant ce qui permet de "
        "dater l'installation et de la confronter aux avis du dépôt"
    )


# --------------------------------------------------------------------------
# AutoGen Studio pose bien son authentification en middleware —
# « app.add_middleware(AuthMiddleware, auth_manager=auth_manager) » — mais le
# fournisseur par défaut ne garde rien : AuthConfig déclare « type:
# Literal["none", "github", "msal", "firebase"] = "none" », init_auth_manager()
# retombe sur « AuthConfig(type="none") » dès qu'AUTOGENSTUDIO_AUTH_CONFIG est
# absente ou illisible, et en ce mode dispatch() laisse passer avant de chercher
# un jeton.
#
# GET /api/auth/type le dit dans sa propre réponse : le handler rend « {"type":
# auth_manager.config.type, "exclude_paths":
# auth_manager.config.exclude_paths} ». La route figure dans exclude_paths, donc
# elle répond aussi sur une instance configurée — c'est la valeur « none », et
# non le fait qu'elle réponde, qui porte le constat. GET /api/version corrobore
# par un chemin de code disjoint, et ne peut rien conclure seule pour la même
# raison.

AUTOGEN_STUDIO_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                       "autogen-studio-no-auth.yaml")

AUTOGEN_STUDIO_AUTH_TYPE_ROUTE = "/api/auth/type"
AUTOGEN_STUDIO_VERSION_ROUTE = "/api/version"

# La valeur par défaut d'AuthConfig.exclude_paths, dans l'ordre où le modèle la
# déclare.
AUTOGEN_STUDIO_EXCLUDE_PATHS = [
    "/",
    "/api/health",
    "/api/version",
    "/api/auth/login-url",
    "/api/auth/callback-handler",
    "/api/auth/callback",
    "/api/auth/type",
]


def autogen_studio_auth_type_body(auth_type="none", exclude_paths=None,
                                  extra_paths=(), indent=None):
    """
    Ce que rend GET /api/auth/type : le dictionnaire littéral d'authroutes.py,
    « type » d'abord puis « exclude_paths », sérialisé par FastAPI dans l'ordre
    d'insertion.

    `extra_paths` allonge la liste comme le ferait un exploitant qui a écrit son
    propre fichier de configuration, `indent` réécrit le document comme le
    ferait un intermédiaire qui réindente ce qu'il relaie.
    """
    paths = list(AUTOGEN_STUDIO_EXCLUDE_PATHS if exclude_paths is None
                 else exclude_paths)
    paths.extend(extra_paths)
    document = {"type": auth_type, "exclude_paths": paths}
    if indent is not None:
        return json.dumps(document, indent=indent)
    # La JSONResponse de FastAPI écrit compact.
    return json.dumps(document, separators=(",", ":"))


def autogen_studio_version_body(version="0.4.3", indent=None):
    """
    Ce que rend GET /api/version : l'enveloppe écrite en clair dans app.py, dont
    le libellé est une constante du source.
    """
    document = {
        "status": True,
        "message": "Version retrieved successfully",
        "data": {"version": version},
    }
    if indent is not None:
        return json.dumps(document, indent=indent)
    return json.dumps(document, separators=(",", ":"))


AUTOGEN_STUDIO_AUTH_TYPE_BODY = autogen_studio_auth_type_body()
AUTOGEN_STUDIO_VERSION_BODY = autogen_studio_version_body()

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
AUTOGEN_STUDIO_COMPOSITE_BODY = (
    '{"autogen_studio":%s,"checked_at":0}' % AUTOGEN_STUDIO_AUTH_TYPE_BODY
)

# Un service quelconque qui rendrait « none » sous la même clé racine, sans rien
# de ce qui désigne le produit.
AUTOGEN_STUDIO_BARE_TYPE_BODY = '{"type":"none"}'


def autogen_studio_block():
    doc = load(AUTOGEN_STUDIO_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(AUTOGEN_STUDIO_AUTH_TYPE_ROUTE)
                     for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {AUTOGEN_STUDIO_AUTH_TYPE_ROUTE} — c'est "
        "pourtant la seule route dont la réponse transcrive le mode "
        "d'authentification courant, donc la seule qui puisse conclure"
    )
    return blocks[0]


def autogen_studio_requests():
    """
    (méthode, chemin) de chaque requête, dans l'ordre déclaré : c'est cet ordre
    qui donne son numéro à chaque body_N.
    """
    block = autogen_studio_block()
    return [normalise_route(block.get("method"), target)
            for target in (block.get("path") or [])]


def autogen_studio_fires(auth_type=(200, AUTOGEN_STUDIO_AUTH_TYPE_BODY),
                         version=(200, AUTOGEN_STUDIO_VERSION_BODY)):
    scenario = {
        AUTOGEN_STUDIO_AUTH_TYPE_ROUTE: auth_type,
        AUTOGEN_STUDIO_VERSION_ROUTE: version,
    }
    block = autogen_studio_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = []
    for _, route in autogen_studio_requests():
        assert route in scenario, (
            "le template interroge un chemin qu'AutoGen Studio ne sert pas : "
            f"{route}"
        )
        responses.append(scenario[route])
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_autogen_studio_probe_reads_two_routes_and_never_runs_a_team():
    assert autogen_studio_block().get("req-condition") is True, (
        "le template ne lie pas les réponses : sans req-condition, ni body_N "
        "ni status_code_N n'existent, et /api/version — servie par toute "
        "instance du produit, fermées comprises — conclurait de son côté"
    )

    assert autogen_studio_requests() == [
        ("GET", AUTOGEN_STUDIO_AUTH_TYPE_ROUTE),
        ("GET", AUTOGEN_STUDIO_VERSION_ROUTE),
    ], (
        "les deux requêtes ne sont plus celles que le template documente — "
        f"{autogen_studio_requests()}"
    )

    doc = load(AUTOGEN_STUDIO_TEMPLATE)
    for method, route in sorted(request_routes(doc)):
        assert method == "GET", (
            f"{method} {route} : en mode « none » l'anonyme est accepté sur "
            "tous les routeurs, y compris ceux qui écrivent — aucun n'est "
            "nécessaire pour signaler l'exposition"
        )
        for forbidden, why in (
            ("/api/runs",
             "POST /api/runs crée une exécution, que le WebSocket "
             "/api/ws/runs/{run_id} fait ensuite tourner"),
            ("/api/ws",
             "/api/ws/runs/{run_id} exécute l'équipe : les agents appellent "
             "leurs outils"),
            ("/api/teams",
             "les routes d'équipe rendent les messages système, les outils et "
             "la configuration des clients de modèles, et DELETE "
             "/api/teams/{team_id} en supprime une"),
            ("/api/sessions",
             "les routes de session rendent l'historique des exécutions, donc "
             "ce qui a été soumis aux agents"),
            ("/api/settings",
             "PUT /api/settings réécrit la configuration de l'exploitant"),
            ("/api/gallery",
             "les routes de galerie touchent au catalogue de composants de "
             "l'exploitant"),
            ("/api/mcp",
             "POST /api/mcp/ws/connect enregistre des paramètres de serveur "
             "avant d'ouvrir une session MCP"),
            ("/api/validate",
             "/api/validate fait instancier des composants à partir d'une "
             "définition fournie"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_autogen_studio_matcher_rests_on_the_declared_type_not_on_the_status():
    assert autogen_studio_fires(), (
        "le template ne reconnaît pas la réponse d'une instance laissée à ses "
        "défauts — celle, précisément, dont init_auth_manager() a reposé "
        "« AuthConfig(type=\"none\") »"
    )

    assert not autogen_studio_fires(
        auth_type=(200, AUTOGEN_STUDIO_COMPOSITE_BODY)
    ), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur la clé racine qui dit que l'instance "
        "a répondu d'elle-même"
    )
    assert not autogen_studio_fires(
        auth_type=(200, AUTOGEN_STUDIO_BARE_TYPE_BODY)
    ), (
        "le template conclut sur un service quelconque qui rend « none » sous "
        "la même clé racine : c'est exclude_paths, et les noms de route "
        "qu'authroutes.py déclare, qui nomment le produit"
    )
    assert not autogen_studio_fires(auth_type=(200, GENERIC_VERSION_BODY)), (
        "le template conclut sur un corps qui ne porte pas même la clé « type »"
    )

    # Le statut, seul, ne départage rien : les deux routes figurent dans
    # exclude_paths et rendent donc 200 sur une instance fermée comme sur une
    # instance ouverte.
    assert not autogen_studio_fires(
        auth_type=(200, autogen_studio_auth_type_body(
            exclude_paths=["/", "/api/health", "/api/version"]))
    ), (
        "le template se contente d'un tableau exclude_paths quelconque : ce "
        "sont /api/auth/login-url et /api/auth/callback-handler, déclarées par "
        "authroutes.py, qui désignent AutoGen Studio"
    )


def test_autogen_studio_conclusion_needs_the_type_to_be_none():
    for mode in ("github", "msal", "firebase"):
        assert not autogen_studio_fires(
            auth_type=(200, autogen_studio_auth_type_body(auth_type=mode))
        ), (
            f"le template remonte une instance qui annonce le mode « {mode} » : "
            "le handler transcrit auth_manager.config.type tel quel, et le "
            "constat porte sur le défaut « none », pas sur la présence du "
            "produit"
        )


def test_autogen_studio_matcher_holds_across_spacings_and_extra_paths():
    assert autogen_studio_fires(
        auth_type=(200, autogen_studio_auth_type_body(indent=2)),
        version=(200, autogen_studio_version_body(indent=2)),
    ), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )

    assert autogen_studio_fires(
        auth_type=(200, autogen_studio_auth_type_body(
            extra_paths=("/api/un/chemin/a/venir",)))
    ), (
        "le template exige la liste exacte d'exclude_paths : c'est un champ de "
        "configuration que l'exploitant peut allonger, et qu'une version "
        "future peut compléter"
    )

    assert autogen_studio_fires(
        version=(200, autogen_studio_version_body(version="0.5.0"))
    ), (
        "le template exige un numéro de version précis : autogenstudio/"
        "version.py le change à chaque publication"
    )


def test_autogen_studio_conclusion_needs_the_route_that_names_the_product():
    assert not autogen_studio_fires(
        version=(404, GENERIC_BAD_REQUEST_BODY)
    ), (
        "le template conclut sans corroboration par un chemin de code "
        "disjoint : c'est elle qui écarte un cache ou un proxy statique qui "
        "rejouerait la première réponse"
    )
    assert not autogen_studio_fires(version=(200, GENERIC_VERSION_BODY)), (
        "le template se contente d'un 200 sur la seconde route : un portail "
        "captif ou un proxy peut rendre 200 sur n'importe quel chemin, et "
        "c'est l'enveloppe écrite en clair dans app.py — « status », le "
        "libellé « Version retrieved successfully », puis data.version — qui "
        "dit que la réponse vient bien d'AutoGen Studio"
    )


def test_autogen_studio_conclusion_is_carried_by_the_dsl_alone():
    block = autogen_studio_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les deux réponses par leur numéro"
    )


def test_autogen_studio_extractor_reports_the_version_the_instance_serves():
    extractors = autogen_studio_block().get("extractors") or []
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le "
        "moteur émet un résultat par extracteur qui rend quelque chose, donc "
        "la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la réponse est un document JSON : une expression regex n'a pas à s'en "
        "charger"
    )
    assert extractor.get("part") == "body_2", (
        "l'extracteur n'est pas borné à body_2 — c'est /api/version qui porte "
        "VERSION, /api/auth/type ne rendant aucun numéro"
    )
    assert extractor.get("json") == [".data.version"], (
        "l'extracteur ne lit pas .data.version — c'est pourtant ce qui permet "
        "de dater l'installation et de la confronter aux publications du dépôt"
    )


# --------------------------------------------------------------------------
# Vespa — GET /application/v2/tenant/default (le constat, en un seul message)
# corroboré par GET /state/v1/version (un chemin de code disjoint, sur le même
# port d'administration).

VESPA_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                               "vespa-config-server-exposed.yaml")
VESPA_TENANT_ROUTE = "/application/v2/tenant/default"
VESPA_VERSION_ROUTE = "/state/v1/version"


def vespa_tenant_body(tenant="default", indent=None):
    document = {"message": "Tenant '%s' exists." % tenant}
    if indent is not None:
        return json.dumps(document, indent=indent)
    return json.dumps(document, separators=(",", ":"))


def vespa_version_body(version="8.587.16", indent=None):
    document = {"version": version}
    if indent is not None:
        return json.dumps(document, indent=indent)
    return json.dumps(document, separators=(",", ":"))


VESPA_TENANT_BODY = vespa_tenant_body()
VESPA_VERSION_BODY = vespa_version_body()

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
VESPA_COMPOSITE_BODY = '{"vespa":%s,"checked_at":0}' % VESPA_TENANT_BODY

# Un service quelconque qui rendrait le même statut générique, sans rien de ce
# qui désigne TenantGetResponse.
VESPA_BARE_STATUS_BODY = '{"status":"ok"}'


def vespa_block():
    doc = load(VESPA_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if any(p.endswith(VESPA_TENANT_ROUTE) for p in (b.get("path") or []))]
    assert blocks, (
        f"le template n'interroge pas {VESPA_TENANT_ROUTE} — c'est pourtant la "
        "seule route dont le message transcrive, sans le moindre garde, "
        "l'existence du tenant"
    )
    return blocks[0]


def vespa_requests():
    """
    (méthode, chemin) de chaque requête, dans l'ordre déclaré : c'est cet ordre
    qui donne son numéro à chaque body_N.
    """
    block = vespa_block()
    return [normalise_route(block.get("method"), target)
            for target in (block.get("path") or [])]


def vespa_fires(tenant=(200, VESPA_TENANT_BODY), version=(200, VESPA_VERSION_BODY)):
    scenario = {
        VESPA_TENANT_ROUTE: tenant,
        VESPA_VERSION_ROUTE: version,
    }
    block = vespa_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    responses = []
    for _, route in vespa_requests():
        assert route in scenario, (
            f"le template interroge un chemin que Vespa ne sert pas : {route}"
        )
        responses.append(scenario[route])
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les deux réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_vespa_probe_reads_two_routes_and_never_writes_nor_deletes_a_tenant():
    assert vespa_block().get("req-condition") is True, (
        "le template ne lie pas les réponses : sans req-condition, ni body_N "
        "ni status_code_N n'existent, et /state/v1/version — servie par tout "
        "conteneur Vespa, config server correctement fermé au réseau compris "
        "— conclurait de son côté"
    )

    assert vespa_requests() == [
        ("GET", VESPA_TENANT_ROUTE),
        ("GET", VESPA_VERSION_ROUTE),
    ], (
        "les deux requêtes ne sont plus celles que le template documente — "
        f"{vespa_requests()}"
    )

    doc = load(VESPA_TEMPLATE)
    for method, route in sorted(request_routes(doc)):
        assert method == "GET", (
            f"{method} {route} : TenantHandler répond aussi bien à PUT et "
            "DELETE sur /application/v2/tenant/{tenant} qu'aux routes de "
            "session qui préparent et activent un paquet d'application — "
            "aucun de ces verbes n'est nécessaire pour signaler l'exposition"
        )
        for forbidden, why in (
            ("/session",
             "SessionCreateHandler, SessionPrepareHandler et "
             "SessionActiveHandler préparent et activent un paquet "
             "d'application sur le cluster"),
            ("/prepareandactivate",
             "ApplicationApiHandler active un paquet d'application en une "
             "seule requête"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_vespa_matcher_rests_on_the_tenant_message_not_on_the_status():
    assert vespa_fires(), (
        "le template ne reconnaît pas la réponse d'une instance non "
        "reconfigurée — celle, précisément, dont TenantGetResponse rend "
        "littéralement \"Tenant 'default' exists.\""
    )

    assert not vespa_fires(tenant=(200, VESPA_COMPOSITE_BODY)), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'accolade ouvrante qui dit que "
        "l'instance a répondu d'elle-même"
    )
    assert not vespa_fires(tenant=(200, VESPA_BARE_STATUS_BODY)), (
        "le template conclut sur un corps qui ne porte pas même la clé "
        "« message »"
    )

    # Le statut, seul, ne départage rien : sur une instance qui a fermé
    # /application/v2/tenant/*, la même route rend un 401 ou un 403, jamais un
    # corps portant ce message précis.
    assert not vespa_fires(tenant=(401, VESPA_TENANT_BODY)), (
        "le template ignore le statut : il conclurait même quand la route est "
        "gardée et ne rend plus 200"
    )


def test_vespa_conclusion_needs_the_tenant_to_be_named_default():
    for tenant in ("a", "foo", "acme-prod"):
        assert not vespa_fires(tenant=(200, vespa_tenant_body(tenant=tenant))), (
            f"le template remonte une instance dont le tenant se nomme "
            f"« {tenant} » : la requête porte elle-même le nom sur « default », "
            "et TenantGetResponse transcrit tel quel le nom demandé — le "
            "constat porte sur ce tenant précis, pas sur n'importe quel tenant "
            "existant"
        )


def test_vespa_matcher_holds_across_spacings_and_versions():
    assert vespa_fires(
        tenant=(200, vespa_tenant_body(indent=2)),
        version=(200, vespa_version_body(indent=2)),
    ), (
        "le template exige la sérialisation compacte de Slime : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )

    assert vespa_fires(version=(200, vespa_version_body(version="7.594.36"))), (
        "le template exige un numéro de version précis : Vtag.currentVersion "
        "change à chaque publication du produit"
    )


def test_vespa_conclusion_needs_the_route_that_corroborates_by_a_disjoint_path():
    assert not vespa_fires(version=(404, GENERIC_BAD_REQUEST_BODY)), (
        "le template conclut sans corroboration par un chemin de code "
        "disjoint : c'est elle qui écarte un cache ou un proxy statique qui "
        "rejouerait la première réponse depuis un contenu figé"
    )


def test_vespa_conclusion_is_carried_by_the_dsl_alone():
    block = vespa_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les deux réponses par leur numéro"
    )


def test_vespa_extractor_reports_the_version_the_instance_serves():
    extractors = vespa_block().get("extractors") or []
    assert len(extractors) == 1, (
        "le template porte plusieurs extracteurs sous req-condition : le "
        "moteur émet un résultat par extracteur qui rend quelque chose, donc "
        "la même instance serait signalée plusieurs fois"
    )

    extractor = extractors[0]
    assert extractor.get("type") == "json", (
        "la réponse est un document JSON : une expression regex n'a pas à "
        "s'en charger"
    )
    assert extractor.get("part") == "body_2", (
        "l'extracteur n'est pas borné à body_2 — c'est /state/v1/version qui "
        "porte le numéro, /application/v2/tenant/default ne rendant que le "
        "message"
    )
    assert extractor.get("json") == [".version"], (
        "l'extracteur ne lit pas .version — c'est pourtant ce qui permet de "
        "dater l'installation et de la confronter aux avis du dépôt"
    )


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_vespa_matcher_compiles_and_fires_against_a_live_server():
    """
    `nuclei -validate` ne compile pas les expressions DSL — un motif qui casse
    le lexer (une apostrophe littérale entre guillemets, par exemple) y passe
    sans le moindre avertissement et n'échoue qu'au premier scan réel. C'est
    ce que `dsl_matcher_hits` ne peut pas voir non plus, puisqu'il réévalue le
    motif en Python plutôt qu'avec le lexer de nuclei : seul un scan contre un
    vrai serveur ferme la boucle.
    """
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == VESPA_TENANT_ROUTE:
                body = VESPA_TENANT_BODY.encode()
            elif self.path == VESPA_VERSION_ROUTE:
                body = VESPA_VERSION_BODY.encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = "http://127.0.0.1:%d" % server.server_port
        r = subprocess.run(
            ["nuclei", "-t", VESPA_TEMPLATE, "-u", target,
             "-duc", "-auth=false", "-jsonl", "-silent"],
            capture_output=True, text=True, timeout=60,
        )
    finally:
        server.shutdown()

    assert r.returncode == 0, r.stdout + r.stderr
    lines = [line for line in r.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, (
        "le scan contre un serveur qui rend les deux réponses attendues ne "
        f"produit pas exactement un résultat : {r.stdout + r.stderr}"
    )
    result = json.loads(lines[0])
    assert result.get("template-id") == "vespa-config-server-exposed"
    assert result.get("extracted-results") == ["8.587.16"]


# --------------------------------------------------------------------------
# TensorBoard lie le constat à trois routes du même CorePlugin sans garde : la
# preuve tient sur le couple loading_mechanism + remove_dom de
# /data/plugins_listing, jamais sur le statut HTTP, et /data/environment puis
# /data/runs corroborent par un vocabulaire disjoint.

TENSORBOARD_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure", "tensorboard-exposed.yaml")


def tensorboard_plugins_listing_body(plugins=None):
    """
    Telle que _serve_plugins_listing la construit : quatre clés fixes par
    plugin (disable_reload, enabled, remove_dom, tab_name) puis
    loading_mechanism, un objet typé.
    """
    if plugins is None:
        plugins = {
            "scalars": {
                "disable_reload": False, "enabled": True, "remove_dom": False,
                "tab_name": "scalars",
                "loading_mechanism": {"type": "CUSTOM_ELEMENT",
                                       "element_name": "tf-scalar-dashboard"},
            },
            "graphs": {
                "disable_reload": True, "enabled": True, "remove_dom": True,
                "tab_name": "graphs",
                "loading_mechanism": {"type": "CUSTOM_ELEMENT",
                                       "element_name": "tf-graph-dashboard"},
            },
        }
    return json.dumps(plugins)


TENSORBOARD_PLUGINS_LISTING_BODY = tensorboard_plugins_listing_body()

# Une instance qui ne sert que des plugins Angular natifs et repliés : les
# deux autres branches de loading_mechanism que le backend peut construire.
TENSORBOARD_PLUGINS_LISTING_NG_AND_NONE_BODY = tensorboard_plugins_listing_body({
    "whatif_tool": {
        "disable_reload": False, "enabled": True, "remove_dom": False,
        "tab_name": "whatif_tool",
        "loading_mechanism": {"type": "NG_COMPONENT"},
    },
    "custom_scalars": {
        "disable_reload": False, "enabled": False, "remove_dom": False,
        "tab_name": "custom_scalars",
        "loading_mechanism": {"type": "NONE"},
    },
})

TENSORBOARD_ENVIRONMENT_BODY = json.dumps({
    "version": "2.22.0a0",
    "data_location": "s3://acme-ml-training/logs/run42",
    "window_title": "", "experiment_name": "", "experiment_description": "",
    "creation_time": 0,
})

TENSORBOARD_RUNS_BODY = json.dumps(["train", "eval", "train/2026-08-30_lr0.001"])

# Un panneau quelconque qui répond 200 sur les trois chemins avec un JSON qui
# porte des noms de clé voisins mais aucun des cinq que output_metadata pose,
# et surtout pas de loading_mechanism typé.
OTHER_APP_PLUGINS_LISTING_BODY = json.dumps({"plugins": ["a", "b"], "enabled": True})
OTHER_APP_ENVIRONMENT_BODY = json.dumps({"version": "1.0", "env": "prod"})

# Un inventaire qui reprend enabled et tab_name sans jamais typer sa
# mécanique de chargement : les noms de clé isolés ne suffisent pas.
OTHER_APP_PLUGIN_LIST_WITH_ENABLED_BODY = json.dumps({
    "scalars": {"enabled": True, "tab_name": "scalars"},
    "graphs": {"enabled": True, "tab_name": "graphs"},
})


def tensorboard_block():
    doc = load(TENSORBOARD_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/data/plugins_listing" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /data/plugins_listing — c'est pourtant "
        "la route qui porte le couple loading_mechanism + remove_dom"
    )
    return blocks[0]


def tensorboard_fires(plugins_listing=(200, TENSORBOARD_PLUGINS_LISTING_BODY),
                       environment=(200, TENSORBOARD_ENVIRONMENT_BODY),
                       runs=(200, TENSORBOARD_RUNS_BODY)):
    block = tensorboard_block()
    paths = [p.replace("{{BaseURL}}", "") for p in block.get("path") or []]
    assert paths == ["/data/plugins_listing", "/data/environment", "/data/runs"], (
        "l'ordre des chemins fixe le numéro de body_N que le DSL interroge"
    )
    responses = [plugins_listing, environment, runs]
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    verdicts = [dsl_matcher_hits(m, responses) for m in matchers
                if m.get("type") == "dsl"]
    assert verdicts, "aucun matcher dsl : les trois réponses ne sont pas liées"
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_tensorboard_probe_is_read_only():
    doc = load(TENSORBOARD_TEMPLATE)
    for block in (doc.get("http") or []):
        assert block.get("method", "GET") == "GET", (
            "les trois routes du plugin core sont des lectures : le template "
            "ne doit rien envoyer à une instance qu'il découvre"
        )


def test_tensorboard_matcher_needs_the_req_condition_to_link_the_three_routes():
    block = tensorboard_block()
    assert block.get("req-condition") is True, (
        "sans req-condition, body_2 et body_3 ne seraient jamais peuplés : le "
        "moteur n'accumule les réponses sous ces noms que si ce drapeau est "
        "posé"
    )


def test_tensorboard_fires_on_a_real_plugins_listing():
    assert tensorboard_fires(), (
        "le template ne reconnaît pas une réponse /data/plugins_listing "
        "authentique de TensorBoard"
    )
    assert tensorboard_fires(
        plugins_listing=(200, TENSORBOARD_PLUGINS_LISTING_NG_AND_NONE_BODY)
    ), (
        "le template manque les instances dont les plugins actifs se "
        "chargent en NG_COMPONENT ou en NONE plutôt qu'en CUSTOM_ELEMENT"
    )


def test_tensorboard_matcher_needs_the_typed_loading_mechanism_not_just_the_key_names():
    assert not tensorboard_fires(plugins_listing=(200, OTHER_APP_PLUGINS_LISTING_BODY)), (
        "le template déclenche sur un panneau quelconque qui porte aussi une "
        "clé \"plugins\" et \"enabled\""
    )
    assert not tensorboard_fires(
        plugins_listing=(200, OTHER_APP_PLUGIN_LIST_WITH_ENABLED_BODY)
    ), (
        "le template déclenche sur un inventaire qui reprend enabled et "
        "tab_name sans jamais typer loading_mechanism — c'est pourtant cet "
        "objet typé, pas les noms de clé isolés, qui distingue TensorBoard"
    )


def test_tensorboard_conclusion_needs_all_three_routes_to_corroborate():
    assert not tensorboard_fires(environment=(200, OTHER_APP_ENVIRONMENT_BODY)), (
        "le template conclut sans que /data/environment porte le vocabulaire "
        "de TensorBoard (data_location, window_title, experiment_name, "
        "experiment_description, creation_time)"
    )
    assert not tensorboard_fires(runs=(404, TENSORBOARD_RUNS_BODY)), (
        "le template ignore le statut de /data/runs : il conclurait même "
        "quand un mandataire a coupé cette route précise en laissant passer "
        "les deux premières"
    )


def test_tensorboard_conclusion_is_carried_by_the_dsl_alone():
    block = tensorboard_block()
    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert kinds == {"dsl"}, (
        "le bloc porte un matcher qui n'est pas du DSL : sous req-condition, "
        "seul le DSL peut lier les trois réponses par leur numéro"
    )


def test_tensorboard_extractors_report_the_storage_uri_and_the_run_names():
    extractors = tensorboard_block().get("extractors") or []
    assert len(extractors) == 2, (
        "le template ne porte pas exactement deux extracteurs : data_location "
        "et les noms de run sont les deux renseignements que l'exposition "
        "divulgue"
    )

    by_name = {e.get("name"): e for e in extractors}
    assert by_name.get("data_location", {}).get("part") == "body_2", (
        "data_location n'appartient qu'à /data/environment"
    )
    assert by_name.get("data_location", {}).get("json") == [".data_location"]
    assert by_name.get("runs", {}).get("part") == "body_3", (
        "les noms de run n'appartiennent qu'à /data/runs"
    )
    assert by_name.get("runs", {}).get("json") == [".[]"]


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_tensorboard_matcher_compiles_and_fires_against_a_live_server():
    """
    `nuclei -validate` ne compile pas les expressions DSL, et `dsl_matcher_hits`
    réévalue le motif en Python plutôt qu'avec le lexer de nuclei : seul un
    scan contre un vrai serveur ferme la boucle.
    """
    routes = {
        "/data/plugins_listing": TENSORBOARD_PLUGINS_LISTING_BODY,
        "/data/environment": TENSORBOARD_ENVIRONMENT_BODY,
        "/data/runs": TENSORBOARD_RUNS_BODY,
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in routes:
                body = routes[self.path].encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = "http://127.0.0.1:%d" % server.server_port
        r = subprocess.run(
            ["nuclei", "-t", TENSORBOARD_TEMPLATE, "-u", target,
             "-duc", "-auth=false", "-jsonl", "-silent"],
            capture_output=True, text=True, timeout=60,
        )
    finally:
        server.shutdown()

    assert r.returncode == 0, r.stdout + r.stderr
    lines = [line for line in r.stdout.splitlines() if line.strip()]
    assert len(lines) == 2, (
        "le scan contre un serveur qui rend les trois réponses attendues ne "
        f"produit pas exactement deux résultats — un par extracteur : "
        f"{r.stdout + r.stderr}"
    )
    results = [json.loads(line) for line in lines]
    assert {r.get("template-id") for r in results} == {"tensorboard-exposed"}
    extracted = [value for r in results for value in (r.get("extracted-results") or [])]
    assert sorted(extracted) == sorted([
        "s3://acme-ml-training/logs/run42",
        "train", "eval", "train/2026-08-30_lr0.001",
    ])


# --------------------------------------------------------------------------
# Agno AgentOS pose son authentification en dépendance de routeur —
# « APIRouter(dependencies=[Depends(get_authentication_dependency(settings))]) »
# — et cette dépendance ne garde rien par défaut : « if not settings or not
# settings.os_security_key: return True », sous le commentaire « If no security
# key is set, skip authentication entirely », là où AgnoAPISettings déclare
# « os_security_key: Optional[str] = None » et « authorization_enabled: bool =
# False ».
#
# GET /config rend alors la configuration entière du runtime. Le constat porte
# sur ce que ce document dit — « os_id » en tête, puis l'énumération des
# modèles, des bases, des agents et des interfaces — jamais sur le statut : la
# route n'est pas dispensée de JWT quand l'autorisation est activée, donc une
# instance fermée n'y rend pas la même chose.
#
# Deux écueils propres à ce produit, et ils commandent la forme du matcher :
# le GET /config de Gradio, déjà couvert par le pack, occupe le même chemin
# sans décrire un runtime d'agents ; et GET /info, sur la même instance, ouvre
# lui aussi son document sur « os_id » sans rien énumérer.

AGNO_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                             "agno-agentos-config-exposed.yaml")

# Les champs optionnels renseignés d'une instance réelle, entre les champs
# obligatoires de tête et les collections de queue — c'est l'ordre de
# déclaration de ConfigResponse, celui que pydantic sérialise.
AGNO_OPTIONAL_BLOCKS = {
    "chat": {"quick_prompts": {"marketing-agent": ["What can you do?"]}},
    "session": {"dbs": [{"db_id": "db-0001",
                         "domain_config": {"display_name": "Sessions"}}]},
    "memory": {"dbs": [{"db_id": "db-0001",
                        "domain_config": {"display_name": "Main app user memories"}}]},
}


def agno_config_body(os_id="acme-agentos", available_models=None, databases=None,
                     agents=None, teams=(), workflows=(), interfaces=None,
                     optional=None, drop=(), indent=None):
    """
    Ce que rend GET /config : ConfigResponse sérialisé par pydantic dans
    l'ordre de déclaration de ses champs, response_model_exclude_none ayant
    retiré ceux qui valent None.

    `drop` retire une clé comme le ferait ce filtre sur un champ laissé vide,
    `indent` réécrit le document comme le ferait un intermédiaire qui
    réindente ce qu'il relaie.
    """
    if available_models is None:
        available_models = [{"id": "gpt-4o", "provider": "OpenAI"}]
    if databases is None:
        databases = ["db-0001", "db-0002"]
    if agents is None:
        agents = [{"id": "marketing-agent", "name": "Marketing Agent",
                   "db_id": "db-0001"}]
    if interfaces is None:
        interfaces = [{"type": "agui", "version": "1.0", "route": "/agui"}]

    document = {
        "os_id": os_id,
        "description": "Your AgentOS",
        "available_models": list(available_models),
        "databases": list(databases),
    }
    document.update(AGNO_OPTIONAL_BLOCKS if optional is None else optional)
    document["agents"] = list(agents)
    document["teams"] = list(teams)
    document["workflows"] = list(workflows)
    document["interfaces"] = list(interfaces)
    for key in drop:
        document.pop(key, None)

    if indent is not None:
        return json.dumps(document, indent=indent)
    # La JSONResponse de FastAPI écrit compact.
    return json.dumps(document, separators=(",", ":"))


AGNO_CONFIG_BODY = agno_config_body()

# La 2.x : available_models y vaut « Optional[List[str]] = None », donc des
# chaînes « fournisseur:modèle » — la forme que l'exemple de la documentation
# montre encore — et la clé disparaît quand rien ne la remplit.
AGNO_CONFIG_STRING_MODELS_BODY = agno_config_body(
    available_models=["openai:gpt-4", "anthropic:claude-3-sonnet"])
AGNO_CONFIG_WITHOUT_MODELS_BODY = agno_config_body(drop=("available_models",))

# L'instance qui n'a encore rien d'enregistré : les collections obligatoires
# sont sérialisées vides, elles ne disparaissent pas.
AGNO_CONFIG_EMPTY_INVENTORY_BODY = agno_config_body(
    available_models=[], databases=[], agents=[], interfaces=[], optional={})

# GET /info sur la même instance : InfoResponse déclare « os_id » en premier
# champ lui aussi, mais n'énumère rien.
AGNO_INFO_BODY = json.dumps({
    "os_id": "acme-agentos", "name": "Acme AgentOS", "os_version": "1.0.0",
    "agno_version": "3.0.5", "agent_count": 4, "team_count": 1,
    "workflow_count": 0, "mcp": {"enabled": False, "path": None},
    "auth_mode": "none",
}, separators=(",", ":"))

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
AGNO_COMPOSITE_BODY = '{"agentos":%s,"checked_at":0}' % AGNO_CONFIG_BODY

# Un service quelconque qui rendrait « os_id » sous la même clé racine, sans
# rien de ce que le runtime énumère.
AGNO_BARE_OS_ID_BODY = '{"os_id":"acme-agentos","description":"Your AgentOS"}'

# Le même document, mais amputé des collections qui nomment le produit : c'est
# ce qu'un service homonyme quelconque pourrait servir.
AGNO_WITHOUT_INVENTORY_BODY = agno_config_body(
    drop=("agents", "teams", "workflows", "interfaces"))
AGNO_WITHOUT_INTERFACES_BODY = agno_config_body(drop=("interfaces",))

# Les deux refus que la dépendance sait produire quand OS_SECURITY_KEY est posé.
AGNO_MISSING_HEADER_BODY = '{"detail":"Authorization header required"}'
AGNO_INVALID_TOKEN_BODY = '{"detail":"Invalid authentication token"}'


def agno_block():
    doc = load(AGNO_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/config" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /config — c'est pourtant la seule route "
        "dont la réponse porte la configuration entière du runtime"
    )
    return blocks[0]


def agno_fires(body):
    block = agno_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    verdicts = [body_matcher_hits(m, body) for m in matchers]
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_agno_probe_only_reads_and_never_runs_an_agent():
    doc = load(AGNO_TEMPLATE)
    routes = sorted(request_routes(doc))
    assert routes == [("GET", "/config")], (
        "le template n'interroge plus la seule route de lecture qu'il "
        f"documente — {routes}"
    )
    for _, route in routes:
        for forbidden, why in (
            ("/agents",
             "POST /agents/{agent_id}/runs exécute un agent, et /config vient "
             "précisément de livrer les agent_id à fournir"),
            ("/teams", "les routes d'équipe font tourner une équipe"),
            ("/workflows", "les routes de workflow en déclenchent l'exécution"),
            ("/sessions",
             "les routes de session rendent ce qui a été soumis aux agents"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_agno_matcher_rests_on_the_configuration_not_on_the_status():
    assert agno_fires(AGNO_CONFIG_BODY), (
        "le template ne reconnaît pas la réponse d'une instance laissée à ses "
        "défauts — celle, précisément, dont get_authentication_dependency() "
        "rend True faute d'os_security_key"
    )

    kinds = {m.get("type") for m in (agno_block().get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : /config n'est pas dispensée de "
        "JWT quand l'autorisation est activée, donc c'est le corps — la "
        "configuration elle-même — qui porte la preuve, jamais le code"
    )

    assert not agno_fires(AGNO_MISSING_HEADER_BODY), (
        "le template conclut sur le refus d'une instance dont OS_SECURITY_KEY "
        "est posé : c'est exactement l'instance fermée"
    )
    assert not agno_fires(AGNO_INVALID_TOKEN_BODY), (
        "le template conclut sur le refus de jeton, qui n'apprend rien de "
        "l'ouverture"
    )
    assert not agno_fires(AGNO_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture du corps qui dit que "
        "l'instance a répondu d'elle-même"
    )


def test_agno_conclusion_needs_the_enumeration_not_just_the_os_id():
    assert not agno_fires(AGNO_BARE_OS_ID_BODY), (
        "le template conclut sur un service quelconque qui rend « os_id » "
        "sous la même clé racine : ce sont les collections que /config "
        "énumère qui prouvent l'accès en lecture au déploiement"
    )
    assert not agno_fires(AGNO_INFO_BODY), (
        "le template déclenche sur GET /info, qui ouvre lui aussi son document "
        "sur « os_id » — InfoResponse le déclare en premier champ — sans "
        "énumérer ni les bases, ni les agents, ni les interfaces"
    )
    assert not agno_fires(AGNO_WITHOUT_INVENTORY_BODY), (
        "le template n'exige plus les collections que ConfigResponse déclare "
        "obligatoires : il ne reste alors que des noms de clé qu'une "
        "configuration quelconque porterait aussi"
    )
    assert not agno_fires(AGNO_WITHOUT_INTERFACES_BODY), (
        "le template se contente de « agents » : c'est la présence conjointe "
        "d'agents et d'interfaces qui sépare ce document d'un inventaire "
        "d'agents quelconque"
    )

    # Collision de chemin : Gradio sert lui aussi un /config anonyme, et le
    # pack le couvre déjà. Son document décrit une interface, pas un runtime.
    for other_body, other_name in (
        (GRADIO_CONFIG_BODY, "gradio"),
        (GRADIO_OLD_CONFIG_BODY, "gradio, dans sa forme ancienne"),
    ):
        assert not agno_fires(other_body), (
            f"le template déclenche sur {other_name}, qui sert lui aussi une "
            "configuration anonyme sur /config sans être un runtime d'agents"
        )


def test_agno_matcher_holds_across_the_two_shapes_of_available_models():
    assert agno_fires(AGNO_CONFIG_STRING_MODELS_BODY), (
        "le template exige les objets « {\"id\": ..., \"provider\": ...} » de "
        "la 3.x : la 2.x déclare « available_models: Optional[List[str]] » et "
        "y écrit des chaînes « fournisseur:modèle », la forme que l'exemple "
        "de la documentation montre encore"
    )
    assert agno_fires(AGNO_CONFIG_WITHOUT_MODELS_BODY), (
        "le template exige available_models : en 2.x le champ vaut None par "
        "défaut et response_model_exclude_none le retire du document, alors "
        "que « databases » y reste déclaré obligatoire"
    )
    assert agno_fires(agno_config_body(drop=("databases",))), (
        "le template exige databases alors qu'available_models suffit : les "
        "deux clés sont interchangeables pour ce constat, et une seule des "
        "deux est garantie selon la génération"
    )
    assert not agno_fires(agno_config_body(
        drop=("available_models", "databases"))), (
        "le template conclut sans qu'aucune des deux énumérations ne soit là"
    )


def test_agno_matcher_holds_on_an_idle_instance_and_across_spacings():
    assert agno_fires(AGNO_CONFIG_EMPTY_INVENTORY_BODY), (
        "le template manque l'instance qui n'a encore rien d'enregistré : les "
        "collections obligatoires y sont sérialisées vides, et c'est bien la "
        "même absence de garde qui les rend lisibles"
    )
    assert agno_fires(agno_config_body(indent=2)), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )
    assert agno_fires(agno_config_body(optional={})), (
        "le template dépend d'un champ optionnel renseigné — chat, session, "
        "memory et les autres valent None sur une instance qui ne les "
        "configure pas, et exclude_none les retire alors"
    )


def test_agno_extractors_report_what_the_anonymous_caller_obtains():
    block = agno_block()
    extractors = block.get("extractors") or []

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
            f"charger — {extractor.get('name')!r}"
        )
        assert extractor.get("part") in (None, "body"), (
            "le bloc n'a qu'une requête et un seul corps à lire — "
            f"part={extractor.get('part')!r}"
        )

    found = {e.get("name"): e.get("json") for e in extractors}
    assert found == {
        "os_id": [".os_id"],
        "databases": [".databases[]"],
        "agents": [".agents[]?.id"],
    }, (
        "les trois renseignements du constat ne sont pas remontés tels quels — "
        f"{found}. .os_id rattache l'instance à un déploiement identifiable, "
        ".databases[] nomme la couche de persistance atteinte par la même "
        "absence de garde, et .agents[]?.id livre exactement les agent_id que "
        "POST /agents/{agent_id}/runs attend — le « ? » évitant de fauter "
        "quand un résumé ne porte pas d'identifiant, AgentSummaryResponse.id "
        "étant optionnel"
    )


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_agno_matcher_compiles_and_fires_against_a_live_server():
    """
    `nuclei -validate` ne compile ni les expressions du matcher ni le chemin
    des extracteurs, et `body_matcher_hits` réévalue les motifs avec le module
    `re` de Python plutôt qu'avec RE2 : seul un scan contre un vrai serveur
    ferme la boucle.
    """
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/config":
                body = AGNO_CONFIG_BODY.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = "http://127.0.0.1:%d" % server.server_port
        r = subprocess.run(
            ["nuclei", "-t", AGNO_TEMPLATE, "-u", target,
             "-duc", "-auth=false", "-jsonl", "-silent"],
            capture_output=True, text=True, timeout=60,
        )
    finally:
        server.shutdown()

    assert r.returncode == 0, r.stdout + r.stderr
    lines = [line for line in r.stdout.splitlines() if line.strip()]
    assert len(lines) == 3, (
        "le scan contre un serveur qui rend la configuration attendue ne "
        "produit pas exactement trois résultats — un par extracteur : "
        f"{r.stdout + r.stderr}"
    )
    results = [json.loads(line) for line in lines]
    assert {item.get("template-id") for item in results} == {
        "agno-agentos-config-exposed"}
    extracted = [value for item in results
                 for value in (item.get("extracted-results") or [])]
    assert sorted(extracted) == sorted([
        "acme-agentos", "db-0001", "db-0002", "marketing-agent",
    ])


# --------------------------------------------------------------------------
# ZenML rend GET /api/v1/info sans jeton, et c'est une propriété du code plutôt
# qu'un réglage : dans server_endpoints.py, « def server_info() -> ServerModel:
# return zen_store().get_store_info() » ne porte aucun « _: AuthContext =
# Security(authorize) », là où ses quatre voisins du même fichier — sous
# LOAD_INFO, ONBOARDING_STATE, SERVER_SETTINGS et STATISTICS — en portent un.
#
# Deux conséquences commandent la forme du matcher. La route répond pareil sur
# une instance dont le reste de l'API est correctement gardé, donc le statut ne
# dit rien du produit ni de la divulgation : c'est le ServerModel lui-même qui
# porte le constat. Et ce modèle a grossi — la 0.40.0 ne déclarait que id,
# version, deployment_type, database_type et secrets_store_type — donc seul ce
# noyau peut être exigé, sous peine de manquer les instances anciennes,
# précisément celles qui traînent exposées.

ZENML_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                              "zenml-server-info-exposed.yaml")

ZENML_SERVER_ID = "6f2c6b6a-6d3f-4a0f-8f2b-2f9b0d1c3e4a"


def zenml_info_body(server_id=ZENML_SERVER_ID, version="0.84.1",
                    deployment_type="docker", database_type="mysql",
                    secrets_store_type="sql",
                    auth_scheme="OAUTH2_PASSWORD_BEARER", drop=(), indent=None):
    """
    Ce que rend GET /api/v1/info : ServerModel sérialisé par pydantic dans
    l'ordre de déclaration de ses champs, tel que get_store_info() le remplit —
    BaseZenStore pose deployment_type, auth_scheme, metadata et
    secrets_store_type, SqlZenStore pose ensuite database_type depuis le nom du
    driver SQLAlchemy, puis id, name, active, last_user_activity et
    analytics_enabled depuis les réglages en base.

    `drop` retire une clé comme le ferait une génération qui ne la déclarait
    pas encore, `indent` réécrit le document comme le ferait un intermédiaire
    qui réindente ce qu'il relaie.
    """
    document = {
        "id": server_id,
        "name": "default",
        "version": version,
        "active": True,
        "debug": False,
        "deployment_type": deployment_type,
        "database_type": database_type,
        "secrets_store_type": secrets_store_type,
        "auth_scheme": auth_scheme,
        "server_url": "https://mlops.internal.acme.corp",
        "dashboard_url": "https://mlops.internal.acme.corp",
        "analytics_enabled": True,
        "metadata": {"deployment": "prod"},
        "last_user_activity": "2026-08-30T09:12:44.183000",
        "pro_dashboard_url": None,
        "pro_api_url": None,
        "pro_organization_id": None,
        "pro_organization_name": None,
        "pro_workspace_id": None,
        "pro_workspace_name": None,
    }
    for key in drop:
        document.pop(key, None)

    if indent is not None:
        return json.dumps(document, indent=indent)
    # La JSONResponse de FastAPI écrit compact.
    return json.dumps(document, separators=(",", ":"))


ZENML_INFO_BODY = zenml_info_body()

# La même réponse sur une instance lancée avec ZENML_SERVER_AUTH_SCHEME=NO_AUTH :
# authentication_provider() rend alors no_authentication(), qui appelle
# « authenticate_credentials(user_name_or_id=DEFAULT_USERNAME) », et toute l'API
# résout sur l'utilisateur par défaut. C'est ce que le corps annonce.
ZENML_NO_AUTH_BODY = zenml_info_body(auth_scheme="NO_AUTH")

# La 0.40.0 : ServerModel n'y déclarait que ces cinq champs — ni name, ni
# active, ni debug, ni auth_scheme.
ZENML_OLD_INFO_BODY = json.dumps({
    "id": ZENML_SERVER_ID, "version": "0.40.0", "deployment_type": "other",
    "database_type": "sqlite", "secrets_store_type": "none",
}, separators=(",", ":"))

# Le refus que rend une route gardée, tel qu'error_detail() le formate :
# « [class_name, str(error)] » sous la clé « detail » du modèle ErrorModel.
ZENML_UNAUTHORIZED_BODY = ('{"detail":["CredentialsNotValid",'
                           '"Authentication error: no credentials provided"]}')

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
ZENML_COMPOSITE_BODY = '{"zenml":%s,"checked_at":0}' % ZENML_INFO_BODY

# Un service quelconque qui décrit lui aussi son déploiement — un identifiant,
# une version, le type de déploiement, le type de base — sans être ZenML. Le
# vocabulaire seul ne prouve donc rien : c'est le trio qui nomme le produit.
OTHER_DEPLOYMENT_INFO_BODY = json.dumps({
    "id": "3f1b4d20-0f4e-4a51-9a6c-8d0c2f3b7a11", "version": "2.11.0",
    "deployment_type": "docker", "database_type": "mysql",
    "replicas": 3, "region": "eu-west-3",
}, separators=(",", ":"))


def zenml_block():
    doc = load(ZENML_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/v1/info" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /api/v1/info — c'est pourtant la seule "
        "route du serveur dont le handler ne réclame pas d'AuthContext"
    )
    return blocks[0]


def zenml_fires(body):
    block = zenml_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    verdicts = [body_matcher_hits(m, body) for m in matchers]
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_zenml_probe_reads_the_open_route_and_touches_nothing_guarded():
    doc = load(ZENML_TEMPLATE)
    routes = sorted(request_routes(doc))
    assert routes == [("GET", "/api/v1/info")], (
        "le template n'interroge plus la seule route de lecture qu'il "
        f"documente — {routes}"
    )
    for _, route in routes:
        for forbidden, why in (
            ("/secrets",
             "/api/v1/secrets rend les secrets que le dépôt conserve : sur "
             "NO_AUTH, les lire serait exploiter le constat, pas l'établir"),
            ("/stacks", "les stacks décrivent les infrastructures branchées"),
            ("/components",
             "les composants de stack portent les connexions à ces "
             "infrastructures"),
            ("/service_connectors",
             "les connecteurs de service portent des identifiants de "
             "fournisseur cloud"),
            ("/run_templates",
             "les templates d'exécution permettent de lancer un pipeline"),
        ):
            assert forbidden not in route, f"{route} : {why}"


def test_zenml_matcher_rests_on_the_server_model_not_on_the_status():
    block = zenml_block()
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )
    assert zenml_fires(ZENML_INFO_BODY), (
        "le template ne reconnaît pas la réponse d'un serveur ZenML — celle, "
        "précisément, que server_info() rend sans réclamer d'AuthContext"
    )

    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : cette route rend 200 aussi bien "
        "sur une instance dont le reste de l'API est gardé, et n'importe quel "
        "intermédiaire servant ce chemin en rendrait un — c'est le ServerModel "
        "qui porte le constat, jamais le code"
    )

    assert not zenml_fires(ZENML_UNAUTHORIZED_BODY), (
        "le template conclut sur le refus d'une route gardée, qui n'est pas la "
        "divulgation qu'il rapporte"
    )
    assert not zenml_fires(ZENML_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture du corps qui dit que "
        "l'instance a répondu d'elle-même"
    )
    assert not zenml_fires(zenml_info_body(drop=("id",))), (
        "le template conclut sur un document qui ne s'ouvre plus sur « id », "
        "le premier champ que ServerModel déclare dans toutes les générations"
    )
    assert not zenml_fires(zenml_info_body(server_id="acme-mlops")), (
        "le template accepte n'importe quelle valeur d'« id » : le champ est "
        "typé UUID, et SqlZenStore le remplace par settings.server_id, lui "
        "aussi un UUID"
    )


def test_zenml_conclusion_needs_the_trio_not_a_deployment_document():
    for key in ("deployment_type", "database_type", "secrets_store_type"):
        assert not zenml_fires(zenml_info_body(drop=(key,))), (
            f"le template conclut sans « {key} » : c'est la présence conjointe "
            "des trois clés qui nomme ZenML, aucune ne le fait seule"
        )

    assert not zenml_fires(OTHER_DEPLOYMENT_INFO_BODY), (
        "le template déclenche sur un service quelconque qui décrit son "
        "déploiement et sa base sans ranger de secrets : « deployment_type » "
        "et « database_type » sont des clés banales hors du trio"
    )
    assert not zenml_fires(zenml_info_body(database_type="postgresql")), (
        "le template accepte une valeur hors de ServerDatabaseType, qui tient "
        "en sqlite, mysql et other depuis la 0.40.0"
    )
    assert not zenml_fires(zenml_info_body(secrets_store_type="vault")), (
        "le template accepte une valeur hors de SecretsStoreType, qui tient en "
        "none, sql, rest, aws, gcp, azure, hashicorp et custom"
    )

    # Collisions internes au pack et au voisinage : /info est un nom banal, et
    # deux templates ne doivent pas revendiquer la même instance.
    assert not zenml_fires(TGI_INFO_BODY), (
        "le template déclenche sur le /info du routeur TGI, déjà couvert par "
        "son propre template"
    )
    assert not zenml_fires(ACTUATOR_INFO_BODY), (
        "le template déclenche sur un /info sans rapport avec le MLOps"
    )


def test_zenml_matcher_holds_across_versions_and_spacings():
    assert zenml_fires(ZENML_OLD_INFO_BODY), (
        "le template exige un champ que la 0.40.0 ne déclarait pas — name, "
        "active, debug ou auth_scheme — il raterait les instances anciennes, "
        "celles qui traînent exposées"
    )
    assert zenml_fires(ZENML_NO_AUTH_BODY), (
        "le template manque l'instance en NO_AUTH, celle dont le corps prouve "
        "que l'API entière est joignable sans identifiant"
    )
    assert zenml_fires(zenml_info_body(deployment_type="hf_spaces")), (
        "le template énumère les membres de ServerDeploymentType : l'enum a "
        "gagné hf_spaces, sandbox puis cloud, et le prochain serait manqué"
    )
    assert zenml_fires(zenml_info_body(deployment_type="kubernetes",
                                       database_type="sqlite",
                                       secrets_store_type="hashicorp")), (
        "le template dépend des valeurs d'une instance particulière plutôt que "
        "des énumérations que le produit sérialise"
    )
    assert zenml_fires(zenml_info_body(secrets_store_type="rest")), (
        "le template refuse « rest », que SecretsStoreType héritait de "
        "StoreType sur les versions anciennes"
    )
    assert zenml_fires(zenml_info_body(version="0.91.1.dev0")), (
        "le template exige une version à trois nombres nus : les versions de "
        "développement portent un suffixe"
    )
    assert zenml_fires(zenml_info_body(indent=2)), (
        "le template exige la sérialisation compacte de FastAPI : un "
        "intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )


def test_zenml_extractors_report_what_the_anonymous_caller_obtains():
    block = zenml_block()
    extractors = block.get("extractors") or []

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
            f"charger — {extractor.get('name')!r}"
        )
        assert extractor.get("part") in (None, "body"), (
            "le bloc n'a qu'une requête et un seul corps à lire — "
            f"part={extractor.get('part')!r}"
        )

    found = {e.get("name"): e.get("json") for e in extractors}
    assert found == {
        "version": [".version"],
        "deployment_type": [".deployment_type"],
        "secrets_store_type": [".secrets_store_type"],
        "auth_scheme": [".auth_scheme // empty"],
    }, (
        "les quatre renseignements du constat ne sont pas remontés tels "
        f"quels — {found}. .version dit quels correctifs manquent à "
        "l'instance, .deployment_type où elle tourne, .secrets_store_type où "
        "sont rangés les secrets de l'organisation, et .auth_scheme sépare le "
        "constat medium du constat high — le « // empty » évitant la ligne "
        "vide sur les instances antérieures à l'apparition du champ"
    )


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_zenml_matcher_compiles_and_fires_against_a_live_server():
    """
    `nuclei -validate` ne compile ni les expressions du matcher ni le chemin
    des extracteurs, et `body_matcher_hits` réévalue les motifs avec le module
    `re` de Python plutôt qu'avec RE2 : seul un scan contre un vrai serveur
    ferme la boucle.
    """
    def scan(body):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/v1/info":
                    payload = body.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            r = subprocess.run(
                ["nuclei", "-t", ZENML_TEMPLATE,
                 "-u", "http://127.0.0.1:%d" % server.server_port,
                 "-duc", "-auth=false", "-jsonl", "-silent"],
                capture_output=True, text=True, timeout=60,
            )
        finally:
            server.shutdown()

        assert r.returncode == 0, r.stdout + r.stderr
        results = [json.loads(line) for line in r.stdout.splitlines()
                   if line.strip()]
        assert {item.get("template-id") for item in results} == {
            "zenml-server-info-exposed"}, r.stdout + r.stderr
        return [value for item in results
                for value in (item.get("extracted-results") or [])]

    assert sorted(scan(ZENML_NO_AUTH_BODY)) == sorted([
        "0.84.1", "docker", "sql", "NO_AUTH",
    ]), "le scan ne remonte pas les quatre renseignements du constat"

    assert sorted(scan(ZENML_OLD_INFO_BODY)) == sorted([
        "0.40.0", "other", "none",
    ]), (
        "l'extracteur d'auth_scheme remonte une ligne vide sur une instance "
        "antérieure à l'apparition du champ — c'est « // empty » qui l'évite, "
        "et une ligne vide se lirait comme un renseignement"
    )


# --------------------------------------------------------------------------
# Determined : GET /api/v1/master est exempté d'authentification par le serveur
# lui-même. master/internal/grpcutil/auth.go déclare « unauthenticatedMethods »
# et y inscrit « /determined.api.v1.Determined/GetMaster » aux côtés de Login
# et GetTelemetry ; les intercepteurs consultent cette carte avant de réclamer
# un jeton. La route répond donc en anonyme sur un cluster qui exige par
# ailleurs un compte, et aucun réglage ne la referme.
#
# Deux points commandent la forme du matcher, et ce sont eux que cette section
# amarre.
#
# La casse d'abord. La réponse est sérialisée par un gRPC-gateway, et
# newGRPCGatewayMux() enregistre « &runtime.JSONPb{EmitDefaults: true} » : le
# runtime.JSONPb de grpc-gateway v1 est le jsonpb.Marshaler de
# github.com/golang/protobuf, dont OrigName reste faux — les clés émises sont
# donc les json_name du descripteur, en lowerCamelCase, et non les noms
# déclarés dans le .proto. Le client généré du produit lit exactement
# celles-là : v1GetMasterResponse.from_json() se construit sur obj["masterId"]
# et obj["clusterId"]. Un template écrit sur « master_id » ne déclencherait sur
# rien.
#
# Les générations ensuite. GetMasterResponse a grossi champ par champ —
# rbac_enabled est le 10, user_management_enabled le 13, has_custom_logo le 16 —
# donc seul le noyau des champs 1 à 5 peut être exigé, sous peine de manquer
# les instances anciennes, celles qui traînent exposées.

DETERMINED_TEMPLATE = os.path.join(TEMPLATES_DIR, "exposure",
                                   "determined-master-info-exposed.yaml")

DETERMINED_MASTER_ID = "5c1f7f8e-3c1a-4f6d-9b2e-71f0a4c8d3b5"
DETERMINED_CLUSTER_ID = "0a9e6b41-2d7c-4c88-8f31-6b0d5a2e94c7"


def determined_master_body(version="0.38.0", master_id=DETERMINED_MASTER_ID,
                           cluster_id=DETERMINED_CLUSTER_ID, cluster_name="",
                           branding="determined", rbac_enabled=False,
                           sso_providers=(), drop=(), indent=None,
                           snake_case=False):
    """
    Ce que rend GET /api/v1/master : GetMasterResponse sérialisé par jsonpb
    dans l'ordre de déclaration du descripteur, tel que le handler GetMaster()
    d'api_master.go le remplit — version depuis master/version, masterId depuis
    « uuid.New().String() », clusterId depuis GetOrCreateClusterID(), branding
    valant « determined » ou « hpe » selon license.IsEE(), puis les drapeaux de
    durcissement que config.GetAuthZConfig() rend.

    « EmitDefaults: true » écrit chaque champ même à sa valeur nulle : d'où
    « clusterName »: "" sur le défaut de config.go, « ssoProviders »: [] sans
    SSO et « clusterMessage »: null sans avis actif.

    `drop` retire une clé comme le ferait une génération qui ne déclarait pas
    encore le champ, `indent` réécrit le document comme le ferait un
    intermédiaire qui réindente ce qu'il relaie, et `snake_case` rend les noms
    déclarés dans le .proto — la forme qu'un marshaler « OrigName: true »
    émettrait, et que celui du produit n'émet pas.
    """
    document = {
        "version": version,
        "masterId": master_id,
        "clusterId": cluster_id,
        "clusterName": cluster_name,
        "telemetryEnabled": False,
        "ssoProviders": [dict(p) for p in sso_providers],
        "externalLoginUri": "",
        "externalLogoutUri": "",
        "branding": branding,
        "rbacEnabled": rbac_enabled,
        "product": "PRODUCT_UNSPECIFIED",
        "featureSwitches": [],
        "userManagementEnabled": True,
        "strictJobQueueControl": False,
        "clusterMessage": None,
        "hasCustomLogo": False,
    }
    for key in drop:
        document.pop(key, None)

    if snake_case:
        renamed = {
            "masterId": "master_id", "clusterId": "cluster_id",
            "clusterName": "cluster_name", "telemetryEnabled": "telemetry_enabled",
            "ssoProviders": "sso_providers", "externalLoginUri": "external_login_uri",
            "externalLogoutUri": "external_logout_uri", "rbacEnabled": "rbac_enabled",
            "featureSwitches": "feature_switches",
            "userManagementEnabled": "user_management_enabled",
            "strictJobQueueControl": "strict_job_queue_control",
            "clusterMessage": "cluster_message", "hasCustomLogo": "has_custom_logo",
        }
        document = {renamed.get(k, k): v for k, v in document.items()}

    if indent is not None:
        return json.dumps(document, indent=indent)
    # Le marshaler de la passerelle écrit compact : Indent n'est posé que sur le
    # marshaler « application/json+pretty », que seul le paramètre ?pretty
    # sélectionne.
    return json.dumps(document, separators=(",", ":"))


DETERMINED_MASTER_BODY = determined_master_body()

# Une instance durcie : RBAC actif, SSO déclaré, cluster nommé. Le template doit
# la reconnaître aussi — le constat est l'accès anonyme à la description, pas
# l'absence de durcissement qu'elle peut annoncer.
DETERMINED_HARDENED_BODY = determined_master_body(
    cluster_name="research-eu-west", rbac_enabled=True, branding="hpe",
    sso_providers=[{"name": "okta", "ssoUrl": "https://sso.internal/saml",
                    "type": "SAML", "alwaysRedirect": False}],
)

# Une génération antérieure : ni rbac_enabled (champ 10), ni product (11), ni
# feature_switches (12), ni user_management_enabled (13), ni
# strict_job_queue_control (14), ni cluster_message (15), ni has_custom_logo
# (16). Le template doit toujours la reconnaître.
DETERMINED_OLD_MASTER_BODY = determined_master_body(
    version="0.19.9",
    drop=("rbacEnabled", "product", "featureSwitches", "userManagementEnabled",
          "strictJobQueueControl", "clusterMessage", "hasCustomLogo"),
)

# Le refus que rend une route gardée, tel que l'errorHandler de
# grpcutil/errors.go le formate : errorBody{Error: errorMessage{Code, Reason,
# Message}}, dont les balises json sont « error », « code », « reason » et —
# pour le message — « error » de nouveau. Code 16 est codes.Unauthenticated.
DETERMINED_UNAUTHENTICATED_BODY = ('{"error":{"code":16,'
                                   '"reason":"Unauthenticated",'
                                   '"error":"token missing"}}')

# La charge utile entière au fond d'un document composite qu'une supervision
# agrégerait sous une clé à elle.
DETERMINED_COMPOSITE_BODY = ('{"determined":%s,"checked_at":0}'
                             % DETERMINED_MASTER_BODY)

# Un service quelconque qui décrit lui aussi un cluster — une version, un
# identifiant, un nom — sans être le master de Determined. Ce vocabulaire
# n'appartient à personne.
OTHER_CLUSTER_INFO_BODY = json.dumps({
    "version": "1.29.4",
    "clusterId": "7f3a1c22-4e5b-4a90-b1d6-9c2e8f0a5d34",
    "clusterName": "prod-gpu",
    "telemetryEnabled": True,
    "nodes": 12,
}, separators=(",", ":"))


def determined_block():
    doc = load(DETERMINED_TEMPLATE)
    blocks = [b for b in (doc.get("http") or [])
              if "{{BaseURL}}/api/v1/master" in (b.get("path") or [])]
    assert blocks, (
        "le template ne vise pas GET /api/v1/master — c'est pourtant la seule "
        "route de description que unauthenticatedMethods laisse passer"
    )
    return blocks[0]


def determined_fires(body):
    block = determined_block()
    matchers = block.get("matchers") or []
    assert matchers, "bloc sans matcher"
    verdicts = [body_matcher_hits(m, body) for m in matchers]
    if block.get("matchers-condition") == "or":
        return any(verdicts)
    return all(verdicts)


def test_determined_probe_reads_the_open_route_and_touches_nothing_guarded():
    doc = load(DETERMINED_TEMPLATE)
    routes = sorted(request_routes(doc))
    assert routes == [("GET", "/api/v1/master")], (
        "le template n'interroge plus la seule route que le serveur exempte "
        f"d'authentification — {routes}"
    )
    for _, route in routes:
        for forbidden, why in (
            ("/master/config",
             "GET /api/v1/master/config réclame un utilisateur puis "
             "CanGetMasterConfig : l'appeler ne dirait rien du constat et "
             "sortirait de la route exemptée"),
            ("/auth/login",
             "Login est exempté au même titre, mais le poster serait tenter "
             "une authentification, pas constater une divulgation"),
            ("/experiments", "les expériences portent le travail de l'exploitant"),
            ("/users", "l'énumération des comptes est une autre affaire que celle-ci"),
        ):
            assert forbidden not in route, f"{route} : {why}"

    assert determined_block().get("method") == "GET", (
        "la description du master se lit en GET : le template ne doit rien "
        "envoyer à une instance qu'il découvre"
    )


def test_determined_matcher_rests_on_the_master_response_not_on_the_status():
    block = determined_block()
    assert block.get("matchers-condition") == "and", (
        "les matchers doivent tous devoir passer, sinon la signature produit "
        "peut être court-circuitée"
    )
    assert determined_fires(DETERMINED_MASTER_BODY), (
        "le template ne reconnaît pas la réponse d'un master Determined — "
        "celle, précisément, que GetMaster rend sans réclamer de jeton"
    )

    kinds = {m.get("type") for m in (block.get("matchers") or [])}
    assert "status" not in kinds, (
        "le bloc porte un matcher de statut : cette route rend 200 sur toute "
        "instance vivante, gardée ou non, et n'importe quel intermédiaire "
        "servant ce chemin en rendrait un — c'est GetMasterResponse qui porte "
        "le constat, jamais le code"
    )

    assert not determined_fires(DETERMINED_UNAUTHENTICATED_BODY), (
        "le template conclut sur le refus que l'errorHandler de la passerelle "
        "rend pour une route gardée, qui n'est pas la divulgation qu'il "
        "rapporte"
    )
    assert not determined_fires(DETERMINED_COMPOSITE_BODY), (
        "le template retrouve la charge utile entière au fond d'un document "
        "composite : c'est l'ancrage sur l'ouverture du corps qui dit que "
        "l'instance a répondu d'elle-même"
    )
    assert not determined_fires(determined_master_body(drop=("version",))), (
        "le template conclut sur un document qui ne s'ouvre plus sur "
        "« version », le champ 1 du message — jsonpb sérialise dans l'ordre de "
        "déclaration du descripteur"
    )


def test_determined_matcher_reads_the_casing_the_gateway_emits():
    """
    Le point que la passerelle rendait incertain, et qui se vérifie plutôt
    qu'il ne se devine : « &runtime.JSONPb{EmitDefaults: true} » laisse
    OrigName à faux, donc les clés émises sont les json_name du descripteur.
    """
    assert determined_fires(DETERMINED_MASTER_BODY), (
        "le template ne reconnaît pas la casse lowerCamelCase que le "
        "marshaler de la passerelle émet"
    )
    assert not determined_fires(determined_master_body(snake_case=True)), (
        "le template accepte les noms déclarés dans le .proto — master_id, "
        "cluster_id — qu'aucun marshaler de ce déploiement n'émet : la casse "
        "n'est plus tenue à ce que la source dit, et le prochain qui la "
        "retournerait ne serait plus arrêté"
    )

    for matcher in (determined_block().get("matchers") or []):
        for needle in (matcher.get("regex") or []) + (matcher.get("words") or []):
            for proto_name in ("master_id", "cluster_id", "cluster_name",
                               "rbac_enabled", "telemetry_enabled"):
                assert proto_name not in needle, (
                    f"le matcher porte « {proto_name} », le nom déclaré dans "
                    "le .proto : le gateway émet le json_name, et le client "
                    "généré du produit lit obj[\"masterId\"]"
                )


def test_determined_conclusion_needs_the_master_identity_not_a_cluster_document():
    assert not determined_fires(determined_master_body(drop=("masterId",))), (
        "le template conclut sans « masterId » : c'est lui qui sépare la "
        "réponse du master de n'importe quel document décrivant un cluster"
    )
    assert not determined_fires(determined_master_body(drop=("clusterId",))), (
        "le template conclut sans « clusterId », que le json_schema du message "
        "déclare pourtant obligatoire"
    )
    assert not determined_fires(determined_master_body(drop=("clusterName",))), (
        "le template conclut sans « clusterName », que « EmitDefaults: true » "
        "écrit même vide"
    )
    assert not determined_fires(determined_master_body(master_id="master-01")), (
        "le template accepte n'importe quelle valeur de « masterId » : core.go "
        "n'en écrit qu'une, « uuid.New().String() », et c'est cette forme qui "
        "distingue la réponse d'un document de supervision quelconque"
    )
    assert not determined_fires(OTHER_CLUSTER_INFO_BODY), (
        "le template déclenche sur un service quelconque qui décrit son "
        "cluster : « version », « clusterId » et « clusterName » sont des clés "
        "banales sans l'identifiant du master"
    )
    assert not determined_fires(determined_master_body(
        drop=("telemetryEnabled", "rbacEnabled", "userManagementEnabled"))), (
        "le template conclut sans aucun des drapeaux que la réponse publie : "
        "ce sont eux qui disent que le document décrit le durcissement d'un "
        "cluster, et non seulement son identité"
    )

    # Collisions internes au pack et au voisinage : ces corps décrivent eux
    # aussi une pile de calcul, et deux templates ne doivent pas revendiquer la
    # même instance.
    for other_body, what in (
        (TGI_INFO_BODY, "le /info du routeur TGI"),
        (ACTUATOR_INFO_BODY, "un /info sans rapport avec le calcul distribué"),
        (COMFYUI_SYSTEM_STATS_BODY, "le /system_stats de ComfyUI"),
        (ZENML_INFO_BODY, "le /api/v1/info de ZenML"),
    ):
        assert not determined_fires(other_body), (
            f"le template déclenche sur {what}, déjà couvert par ailleurs"
        )


def test_determined_matcher_holds_across_versions_and_spacings():
    assert determined_fires(DETERMINED_OLD_MASTER_BODY), (
        "le template exige un champ que les générations anciennes ne "
        "déclaraient pas — rbac_enabled, user_management_enabled, "
        "has_custom_logo — il raterait les instances anciennes, celles qui "
        "traînent exposées"
    )
    assert determined_fires(DETERMINED_HARDENED_BODY), (
        "le template manque l'instance durcie : le constat est l'accès anonyme "
        "à la description, pas l'absence de RBAC qu'elle peut annoncer"
    )
    assert determined_fires(determined_master_body(branding="hpe")), (
        "le template dépend du branding open source : license.IsEE() fait "
        "écrire « hpe » sur l'édition entreprise"
    )
    assert determined_fires(determined_master_body(cluster_name="research-eu-west")), (
        "le template dépend du nom de cluster d'une instance particulière"
    )
    assert determined_fires(determined_master_body(version="0.42.0.dev0")), (
        "le template exige une version à trois nombres nus : les versions de "
        "développement portent un suffixe"
    )
    assert determined_fires(determined_master_body(
        master_id=DETERMINED_MASTER_ID.upper())), (
        "le template exige un UUID en minuscules : rien n'oblige un "
        "intermédiaire à conserver la casse d'un identifiant qu'il relaie"
    )
    assert determined_fires(determined_master_body(indent=4)), (
        "le template exige la sérialisation compacte de la passerelle : le "
        "marshaler « application/json+pretty » écrit « Indent: \"    \" », et "
        "un intermédiaire qui réindenterait ce qu'il relaie ferait manquer "
        "l'instance"
    )


def test_determined_extractors_report_what_the_anonymous_caller_obtains():
    block = determined_block()
    extractors = block.get("extractors") or []

    for extractor in extractors:
        assert extractor.get("type") == "json", (
            "la route rend un objet JSON : un extracteur regex n'a pas à s'en "
            f"charger — {extractor.get('name')!r}"
        )
        assert extractor.get("part") in (None, "body"), (
            "le bloc n'a qu'une requête et un seul corps à lire — "
            f"part={extractor.get('part')!r}"
        )

    found = {e.get("name"): e.get("json") for e in extractors}
    assert found == {
        "version": ['.version'],
        "cluster_name": ['.clusterName | select(. != "")'],
        "cluster_id": ['.clusterId'],
        "rbac_enabled": ['.rbacEnabled | select(. != null)'],
        "sso_providers": ['.ssoProviders[]?.type'],
    }, (
        "les cinq renseignements du constat ne sont pas remontés tels "
        f"quels — {found}. .version dit quels correctifs manquent au master, "
        ".clusterName nomme le déploiement — le « select » évitant la ligne "
        "vide sur le défaut « ClusterName: \"\" » de config.go —, .clusterId "
        "le rattache par-delà les redémarrages puisque masterId, lui, est "
        "régénéré à chaque fois, .rbacEnabled dit ce qui garde le reste de "
        "l'API — « select(. != null) » plutôt qu'une alternative jq, qui "
        "écarterait false, précisément le cas intéressant — et .ssoProviders "
        "énumère les fournisseurs déclarés"
    )


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_determined_matcher_compiles_and_fires_against_a_live_server():
    """
    `nuclei -validate` ne compile ni les expressions du matcher ni le chemin
    des extracteurs, et `body_matcher_hits` réévalue les motifs avec le module
    `re` de Python plutôt qu'avec RE2 : seul un scan contre un vrai serveur
    ferme la boucle.
    """
    def scan(body):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/v1/master":
                    payload = body.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            r = subprocess.run(
                ["nuclei", "-t", DETERMINED_TEMPLATE,
                 "-u", "http://127.0.0.1:%d" % server.server_port,
                 "-duc", "-auth=false", "-jsonl", "-silent"],
                capture_output=True, text=True, timeout=60,
            )
        finally:
            server.shutdown()

        assert r.returncode == 0, r.stdout + r.stderr
        results = [json.loads(line) for line in r.stdout.splitlines()
                   if line.strip()]
        assert {item.get("template-id") for item in results} == {
            "determined-master-info-exposed"}, r.stdout + r.stderr
        return [value for item in results
                for value in (item.get("extracted-results") or [])]

    assert sorted(scan(DETERMINED_HARDENED_BODY)) == sorted([
        "0.38.0", "research-eu-west", DETERMINED_CLUSTER_ID, "true", "SAML",
    ]), "le scan ne remonte pas les cinq renseignements du constat"

    assert sorted(scan(DETERMINED_MASTER_BODY)) == sorted([
        "0.38.0", DETERMINED_CLUSTER_ID, "false",
    ]), (
        "l'instance par défaut remonte une ligne vide pour le nom de cluster — "
        "c'est le « select » qui l'évite — ou perd « rbacEnabled: false », que "
        "l'alternative jq écarterait alors qu'il est le cas intéressant"
    )


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_nuclei_validates_the_whole_pack():
    r = subprocess.run(
        ["nuclei", "-validate", "-t", TEMPLATES_DIR, "-duc"],
        capture_output=True, text=True, timeout=300,
    )
    combined = r.stdout + r.stderr
    assert "All templates validated successfully" in combined, combined[-2000:]
