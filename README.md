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

<!-- couverture -->
47 templates, 44 produits.

| Produit | Template | Sévérité |
| --- | --- | --- |
| aim | [`aim-tracking-server-exposed`](templates/exposure/aim-tracking-server-exposed.yaml) | medium |
| anythingllm | [`anythingllm-exposed`](templates/exposure/anythingllm-exposed.yaml) | high |
| automatic1111-stable-diffusion-webui | [`automatic1111-api-exposed`](templates/exposure/automatic1111-api-exposed.yaml) | high |
| bentoml | [`bentoml-yatai-exposed`](templates/exposure/bentoml-yatai-exposed.yaml) | high |
| chroma | [`chromadb-open-instance`](templates/exposure/chromadb-open-instance.yaml) | high |
| clearml-server | [`clearml-server-exposed`](templates/exposure/clearml-server-exposed.yaml) | high |
| comfyui | [`comfyui-unauthenticated`](templates/exposure/comfyui-unauthenticated.yaml) | high |
| dagster-webserver | [`dagster-webserver-exposed`](templates/exposure/dagster-webserver-exposed.yaml) | high |
| dify | [`dify-exposed-console`](templates/exposure/dify-exposed-console.yaml) | high |
| feast | [`feast-vector-stores-exposed`](templates/exposure/feast-vector-stores-exposed.yaml) | high |
| flowise | [`flowise-unauthenticated-api`](templates/exposure/flowise-unauthenticated-api.yaml) | critical |
| gradio | [`gradio-app-exposed`](templates/exposure/gradio-app-exposed.yaml) | medium |
| hayhooks | [`hayhooks-status-exposed`](templates/exposure/hayhooks-status-exposed.yaml) | high |
| infinity | [`infinity-embedding-server-exposed`](templates/exposure/infinity-embedding-server-exposed.yaml) | medium |
| jupyter_server | [`jupyter-no-token`](templates/exposure/jupyter-no-token.yaml) | critical |
| kubeflow-pipelines | [`kubeflow-pipelines-exposed`](templates/exposure/kubeflow-pipelines-exposed.yaml) | high |
| label-studio | [`label-studio-signup-open`](templates/exposure/label-studio-signup-open.yaml) | medium |
| langflow | [`CVE-2026-0770`](templates/cves/CVE-2026-0770.yaml) | critical |
| langflow | [`CVE-2026-55255`](templates/cves/CVE-2026-55255.yaml) | high |
| langflow | [`langflow-unauthenticated`](templates/exposure/langflow-unauthenticated.yaml) | critical |
| langfuse | [`langfuse-health-exposed`](templates/exposure/langfuse-health-exposed.yaml) | medium |
| langserve | [`langserve-exposed-playground`](templates/exposure/langserve-exposed-playground.yaml) | high |
| letta | [`letta-server-unauthenticated`](templates/exposure/letta-server-unauthenticated.yaml) | high |
| librechat | [`librechat-open-registration`](templates/exposure/librechat-open-registration.yaml) | medium |
| litellm | [`litellm-proxy-no-master-key`](templates/exposure/litellm-proxy-no-master-key.yaml) | high |
| llama.cpp | [`llamacpp-server-exposed`](templates/exposure/llamacpp-server-exposed.yaml) | high |
| lm-studio | [`lmstudio-server-exposed`](templates/exposure/lmstudio-server-exposed.yaml) | medium |
| localai | [`localai-unauthenticated-api`](templates/exposure/localai-unauthenticated-api.yaml) | high |
| marqo | [`marqo-unauthenticated`](templates/exposure/marqo-unauthenticated.yaml) | high |
| milvus | [`milvus-exposed`](templates/exposure/milvus-exposed.yaml) | high |
| mlflow | [`mlflow-tracking-server-unauth`](templates/exposure/mlflow-tracking-server-unauth.yaml) | critical |
| nemo-guardrails | [`nemo-guardrails-server-exposed`](templates/exposure/nemo-guardrails-server-exposed.yaml) | high |
| ollama | [`ollama-model-pull-abuse`](templates/exposure/ollama-model-pull-abuse.yaml) | high |
| ollama | [`ollama-unauthenticated-api`](templates/exposure/ollama-unauthenticated-api.yaml) | high |
| open-webui | [`open-webui-signup-enabled`](templates/exposure/open-webui-signup-enabled.yaml) | medium |
| phoenix | [`arize-phoenix-exposed`](templates/exposure/arize-phoenix-exposed.yaml) | high |
| prefect | [`prefect-server-admin-exposed`](templates/exposure/prefect-server-admin-exposed.yaml) | high |
| qdrant | [`qdrant-no-api-key`](templates/exposure/qdrant-no-api-key.yaml) | high |
| ray | [`ray-dashboard-job-submission`](templates/exposure/ray-dashboard-job-submission.yaml) | critical |
| sglang | [`sglang-server-exposed`](templates/exposure/sglang-server-exposed.yaml) | high |
| text-embeddings-inference | [`text-embeddings-inference-exposed`](templates/exposure/text-embeddings-inference-exposed.yaml) | medium |
| text-generation-inference | [`text-generation-inference-exposed`](templates/exposure/text-generation-inference-exposed.yaml) | high |
| torchserve | [`torchserve-management-api-open`](templates/exposure/torchserve-management-api-open.yaml) | critical |
| triton-inference-server | [`triton-inference-server-exposed`](templates/exposure/triton-inference-server-exposed.yaml) | high |
| vllm | [`vllm-unauthenticated-api`](templates/exposure/vllm-unauthenticated-api.yaml) | high |
| weaviate | [`weaviate-anonymous-access`](templates/exposure/weaviate-anonymous-access.yaml) | high |
| xinference | [`xinference-exposed`](templates/exposure/xinference-exposed.yaml) | high |
<!-- /couverture -->

Tableau écrit par `python3 scripts/coverage.py --readme` ; la suite de tests
refuse qu'il diverge du contenu de `templates/`.

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
