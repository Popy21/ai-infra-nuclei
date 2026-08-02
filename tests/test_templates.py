"""
Porte de qualité du pack.

Un template qui passe ces tests est publiable ; un template qui les échoue ne doit
jamais être commité. C'est cette contrainte qui rend un commit automatique
significatif : sans elle, un commit ne prouve rien.
"""

import ast
import json
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


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_nuclei_validates_the_whole_pack():
    r = subprocess.run(
        ["nuclei", "-validate", "-t", TEMPLATES_DIR, "-duc"],
        capture_output=True, text=True, timeout=300,
    )
    combined = r.stdout + r.stderr
    assert "All templates validated successfully" in combined, combined[-2000:]
