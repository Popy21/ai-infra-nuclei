"""
Porte de qualité du pack.

Un template qui passe ces tests est publiable ; un template qui les échoue ne doit
jamais être commité. C'est cette contrainte qui rend un commit automatique
significatif : sans elle, un commit ne prouve rien.
"""

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


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_nuclei_validates_the_whole_pack():
    r = subprocess.run(
        ["nuclei", "-validate", "-t", TEMPLATES_DIR, "-duc"],
        capture_output=True, text=True, timeout=300,
    )
    combined = r.stdout + r.stderr
    assert "All templates validated successfully" in combined, combined[-2000:]
