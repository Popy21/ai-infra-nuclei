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


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei absent")
def test_nuclei_validates_the_whole_pack():
    r = subprocess.run(
        ["nuclei", "-validate", "-t", TEMPLATES_DIR, "-duc"],
        capture_output=True, text=True, timeout=300,
    )
    combined = r.stdout + r.stderr
    assert "All templates validated successfully" in combined, combined[-2000:]
