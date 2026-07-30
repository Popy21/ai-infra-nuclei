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

- [ ] `templates/exposure/vllm-unauthenticated-api.yaml` — vLLM sert une API compatible OpenAI sans clé par défaut ; `GET /v1/models` renvoie `{"object":"list","data":[...]}`. Sévérité high.
- [ ] `templates/exposure/text-generation-inference-exposed.yaml` — HuggingFace TGI expose `GET /info` avec `model_id` et `max_concurrent_requests`. Sévérité high.
- [ ] `templates/exposure/localai-unauthenticated-api.yaml` — LocalAI, API compatible OpenAI sans authentification par défaut. Sévérité high.
- [ ] `templates/exposure/lmstudio-server-exposed.yaml` — serveur local LM Studio, endpoint compatible OpenAI. Sévérité medium.
- [ ] `templates/exposure/sglang-server-exposed.yaml` — serveur SGLang, `GET /get_model_info`. Sévérité high.
- [ ] `templates/exposure/xinference-exposed.yaml` — Xorbits Inference, API de gestion de modèles. Sévérité high.
- [ ] `templates/exposure/ollama-model-pull-abuse.yaml` — au-delà de la lecture : prouver que `/api/pull` est atteignable (sans déclencher de téléchargement). Sévérité high.

## Interfaces & plateformes d'agents

- [ ] `templates/exposure/comfyui-unauthenticated.yaml` — ComfyUI, `GET /system_stats` renvoie les informations GPU et la version. Sévérité high.
- [ ] `templates/exposure/langserve-exposed-playground.yaml` — LangServe expose `/docs` et les routes `/invoke` sans authentification. Sévérité high.
- [ ] `templates/exposure/flowise-unauthenticated-api.yaml` — Flowise, `GET /api/v1/chatflows` sans authentification. Sévérité critical (les identifiants sont lisibles).
- [ ] `templates/exposure/langflow-unauthenticated.yaml` — Langflow, API sans authentification. Sévérité critical.
- [ ] `templates/exposure/open-webui-signup-enabled.yaml` — Open WebUI avec inscription ouverte : n'importe qui crée un compte. Sévérité medium.
- [ ] `templates/exposure/anythingllm-exposed.yaml` — AnythingLLM sans authentification. Sévérité high.
- [ ] `templates/exposure/dify-exposed-console.yaml` — console Dify accessible. Sévérité high.
- [ ] `templates/exposure/litellm-proxy-no-master-key.yaml` — proxy LiteLLM sans `master_key` : `/v1/models` répond sans clé. Sévérité high.
- [ ] `templates/exposure/gradio-app-exposed.yaml` — application Gradio exposée, `GET /config` renvoie la définition de l'interface. Sévérité medium.

## Bases vectorielles

- [ ] `templates/exposure/chromadb-open-instance.yaml` — ChromaDB, `GET /api/v1/heartbeat` puis énumération des collections. Sévérité high.
- [ ] `templates/exposure/qdrant-no-api-key.yaml` — Qdrant sans clé d'API : `GET /collections` répond. Sévérité high.
- [ ] `templates/exposure/weaviate-anonymous-access.yaml` — Weaviate avec accès anonyme activé, `GET /v1/meta`. Sévérité high.
- [ ] `templates/exposure/milvus-exposed.yaml` — Milvus atteignable sans authentification. Sévérité high.

## MLOps & suivi d'expériences

- [ ] `templates/exposure/mlflow-tracking-server-unauth.yaml` — MLflow, `GET /api/2.0/mlflow/experiments/search` sans authentification. Sévérité critical (lecture d'artefacts arbitraires).
- [ ] `templates/exposure/jupyter-no-token.yaml` — Jupyter sans jeton : `GET /api/kernels` répond, donc exécution de code. Sévérité critical.
- [ ] `templates/exposure/kubeflow-pipelines-exposed.yaml` — API Kubeflow Pipelines exposée. Sévérité high.
- [ ] `templates/exposure/clearml-server-exposed.yaml` — serveur ClearML atteignable. Sévérité high.
- [ ] `templates/exposure/label-studio-signup-open.yaml` — Label Studio avec inscription ouverte. Sévérité medium.
- [ ] `templates/exposure/bentoml-yatai-exposed.yaml` — BentoML/Yatai exposé. Sévérité high.
- [ ] `templates/exposure/triton-inference-server-exposed.yaml` — NVIDIA Triton, `GET /v2/health/ready` puis index des modèles. Sévérité high.

## CVE sans template amont

- [ ] `templates/cves/CVE-2026-0770.yaml` — Langflow, présent au catalogue CISA KEV, aucun template amont. Vérifier l'avis avant d'écrire le matcher.
- [ ] `templates/cves/CVE-2026-55255.yaml` — Langflow, également au KEV.

## Outillage du dépôt

- [ ] Ajouter `scripts/coverage.py` qui compare les identifiants du pack à ceux de `nuclei-templates` et signale les doublons, avec un test associé.
- [ ] Ajouter au README un tableau de couverture généré par `scripts/coverage.py`.
- [ ] Ajouter un test vérifiant que deux templates ne partagent pas le même couple (endpoint, produit).
