# Roadmap

Un item = un template = un commit. Chaque template doit passer `pytest` et
`nuclei -validate` avant d'être commité.

**Règle de rédaction** : le matcher doit prouver que l'API *répond sans
authentification*, avec une signature propre au produit (clé JSON, en-tête,
identifiant de version). Jamais un simple 200, jamais un titre de page seul.
Si l'endpoint annoncé ci-dessous ne correspond pas à la version courante du
produit, vérifie dans la documentation officielle avant d'écrire — mieux vaut un
`SKIP` qu'un template faux.

## Runtimes LLM

- [x] `templates/exposure/vllm-unauthenticated-api.yaml` — vLLM sert une API compatible OpenAI sans clé par défaut ; `GET /v1/models` renvoie `{"object":"list","data":[...]}`. Sévérité high.
- [x] `templates/exposure/text-generation-inference-exposed.yaml` — HuggingFace TGI expose `GET /info` avec `model_id` et `max_concurrent_requests`. Sévérité high.
- [x] `templates/exposure/localai-unauthenticated-api.yaml` — LocalAI, API compatible OpenAI sans authentification par défaut. Sévérité high.
- [x] `templates/exposure/lmstudio-server-exposed.yaml` — serveur local LM Studio, endpoint compatible OpenAI. Sévérité medium.
- [x] `templates/exposure/sglang-server-exposed.yaml` — serveur SGLang, `GET /get_model_info`. Sévérité high.
- [x] `templates/exposure/xinference-exposed.yaml` — Xorbits Inference, API de gestion de modèles. Sévérité high.
- [x] `templates/exposure/ollama-model-pull-abuse.yaml` — au-delà de la lecture : prouver que `/api/pull` est atteignable (sans déclencher de téléchargement). Sévérité high.
- [x] `templates/exposure/llamacpp-server-exposed.yaml` — llama.cpp (`llama-server`) : `GET /props` renvoie `default_generation_settings`, `total_slots`, `model_path`, `chat_template` et `build_info` — le chemin du modèle sur disque et le build prouvent qu'il s'agit bien de llama-server et qu'aucune clé n'est exigée (`--api-key` est facultatif, aucune authentification sans lui). Sévérité high.

## Interfaces & plateformes d'agents

- [x] `templates/exposure/comfyui-unauthenticated.yaml` — ComfyUI, `GET /system_stats` renvoie les informations GPU et la version. Sévérité high.
- [x] `templates/exposure/langserve-exposed-playground.yaml` — LangServe expose `/docs` et les routes `/invoke` sans authentification. Sévérité high.
- [x] `templates/exposure/flowise-unauthenticated-api.yaml` — Flowise, `GET /api/v1/chatflows` sans authentification. Sévérité critical (les identifiants sont lisibles).
- [x] `templates/exposure/langflow-unauthenticated.yaml` — Langflow, API sans authentification. Sévérité critical.
- [x] `templates/exposure/open-webui-signup-enabled.yaml` — Open WebUI avec inscription ouverte : n'importe qui crée un compte. Sévérité medium.
- [x] `templates/exposure/anythingllm-exposed.yaml` — AnythingLLM sans authentification. Sévérité high.
- [x] `templates/exposure/dify-exposed-console.yaml` — console Dify accessible. Sévérité high.
- [x] `templates/exposure/litellm-proxy-no-master-key.yaml` — proxy LiteLLM sans `master_key` : `/v1/models` répond sans clé. Sévérité high.
- [x] `templates/exposure/gradio-app-exposed.yaml` — application Gradio exposée, `GET /config` renvoie la définition de l'interface. Sévérité medium.
- [x] `templates/exposure/automatic1111-api-exposed.yaml` — AUTOMATIC1111 Stable Diffusion WebUI lancé avec `--api` : `GET /sdapi/v1/sd-models` renvoie un tableau JSON d'objets `{"title":...,"model_name":...,"hash":...,"sha256":...,"filename":...,"config":...}` — les chemins de checkpoints sur disque prouvent l'accès à l'API de génération, `--api-auth` valant `None` par défaut (aucune authentification). Sévérité high.
- [ ] `templates/exposure/letta-server-unauthenticated.yaml` — Letta (ex-MemGPT), plateforme d'agents à mémoire persistante : `GET /v1/health/` renvoie `{"version":"<version letta>","status":"ok"}` et `GET /v1/agents/` renvoie la liste des `AgentState` (`id`, `name`, `agent_type`, `llm_config`, `memory`) — le middleware de mot de passe n'est monté que si `LETTA_SERVER_SECURE=true` ou `--secure`, donc rien ne protège l'instance par défaut. Sévérité high.

## Bases vectorielles

- [x] `templates/exposure/chromadb-open-instance.yaml` — ChromaDB, `GET /api/v1/heartbeat` puis énumération des collections. Sévérité high.
- [x] `templates/exposure/qdrant-no-api-key.yaml` — Qdrant sans clé d'API : `GET /collections` répond. Sévérité high.
- [x] `templates/exposure/weaviate-anonymous-access.yaml` — Weaviate : `GET /v1/meta` renvoie `{"hostname":...,"version":"1.x.x","modules":{...}}`. `AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED` vaut `true` par défaut. Confirmer avec `GET /v1/schema`, qui passe, lui, par le contrôle d'accès. Sévérité high.
- [x] `templates/exposure/milvus-exposed.yaml` — ⚠️ Milvus parle surtout **gRPC** (19530) ; seul 9091 sert de l'HTTP (`/healthz`), et l'API RESTful v2 est sous `/v2/vectordb/`. Vérifier qu'une détection HTTP porteuse de sens existe — **si non, rendre `SKIP` immédiatement** plutôt que d'insister. Sévérité high.

## MLOps & suivi d'expériences

- [x] `templates/exposure/mlflow-tracking-server-unauth.yaml` — MLflow, `GET /api/2.0/mlflow/experiments/search` sans authentification. Sévérité critical (lecture d'artefacts arbitraires).
- [x] `templates/exposure/jupyter-no-token.yaml` — Jupyter sans jeton : `GET /api/kernels` répond, donc exécution de code. Sévérité critical.
- [x] `templates/exposure/kubeflow-pipelines-exposed.yaml` — Kubeflow Pipelines : `GET /apis/v1beta1/pipelines` (ou `/pipeline/apis/v1beta1/...` derrière Istio) renvoie la liste JSON des pipelines. Sévérité high.
- [x] `templates/exposure/clearml-server-exposed.yaml` — ClearML : l'API (8008) répond sur `POST /debug.ping` ; le webserver (8080) sert l'app. Chercher la signature de version dans la réponse. Sévérité high.
- [x] `templates/exposure/label-studio-signup-open.yaml` — Label Studio : `GET /user/signup` sert le formulaire quand l'inscription est ouverte ; `GET /version` expose les versions des composants. Sévérité medium.
- [x] `templates/exposure/bentoml-yatai-exposed.yaml` — BentoML : le serveur sert `GET /livez`, `/readyz` et `GET /docs.json` (schéma OpenAPI listant les endpoints d'inférence). Sévérité high.
- [x] `templates/exposure/triton-inference-server-exposed.yaml` — NVIDIA Triton, `GET /v2/health/ready` puis index des modèles. Sévérité high.
- [ ] `templates/exposure/aim-tracking-server-exposed.yaml` — Aim (aimhubio) : l'API est montée sous `/api` et `GET /api/projects/` renvoie `{"name":...,"path":...,"description":...,"telemetry_enabled":...,"warn_index":...,"warn_runs":...}` — le trio `telemetry_enabled` / `warn_index` / `warn_runs` est propre à Aim et le chemin du dépôt `.aim` sur le serveur fuite avec ; aucun routeur de l'app API n'a de dépendance d'authentification. Sévérité medium.

## Observabilité LLM

- [ ] `templates/exposure/arize-phoenix-exposed.yaml` — Arize Phoenix : `GET /arize_phoenix_version` renvoie la version en texte brut sur un chemin propre au produit, à confirmer par `GET /v1/projects` qui renvoie `{"data":[{"id":...,"name":...,"description":...}],"next_cursor":...}` — l'authentification n'est câblée que si `authentication_enabled` est activé, donc les traces LLM (prompts et réponses) sont lisibles par défaut. Sévérité high.

## CVE sans template amont

- [x] `templates/cves/CVE-2026-0770.yaml` — Langflow, présent au catalogue CISA KEV, aucun template amont. Vérifier l'avis avant d'écrire le matcher.
- [x] `templates/cves/CVE-2026-55255.yaml` — Langflow, également au KEV.

## Outillage du dépôt

- [x] Ajouter `scripts/coverage.py` qui compare les identifiants du pack à ceux de `nuclei-templates` et signale les doublons, avec un test associé.
- [x] Ajouter au README un tableau de couverture généré par `scripts/coverage.py`.
- [x] Ajouter un test vérifiant que deux templates ne partagent pas le même couple (endpoint, produit).
