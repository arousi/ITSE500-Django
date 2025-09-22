# Manual Model Pricing

Source-of-truth for providers that do not return pricing via API (OpenAI basic list, Gemini, HuggingFace, LM Studio/local).

Format: pipe table. Prices expressed in USD per 1K tokens (prompt & completion). Use `-` when unknown or N/A.

| provider | model_id | prompt_per_1k | completion_per_1k | notes | effective_date |
|----------|----------|---------------|-------------------|-------|----------------|
| openai | gpt-4o | 0.005 | 0.015 | public list May 2025 | 2025-05-15 |
| openai | gpt-4o-mini | 0.0015 | 0.002 |  | 2025-05-15 |
| openai | gpt-4.1 | 0.006 | 0.018 | assumed near 4o | 2025-05-15 |
| openai | gpt-4.1-mini | 0.0018 | 0.0024 | est. | 2025-05-15 |
| openai | o3-mini | 0.004 | 0.012 | reasoning | 2025-05-15 |
| openai | o1-mini | 0.003 | 0.009 | reasoning | 2025-05-15 |
| openai | text-embedding-3-small | 0.00002 | 0.00002 | embedding same in/out | 2025-05-15 |
| openai | text-embedding-3-large | 0.00013 | 0.00013 |  | 2025-05-15 |
| openai | whisper-1 | 0.0015 | - | per minute equiv; placeholder | 2025-05-15 |
| openai | dall-e-3 | 0.040 | - | per image normalized approx | 2025-05-15 |
| gemini | gemini-1.5-pro | 0.004 | 0.012 | approximate; older public list | 2025-05-15 |
| gemini | gemini-1.5-flash | 0.00125 | 0.004 |  | 2025-05-15 |
| gemini | gemini-1.0-pro | 0.0025 | 0.0075 | legacy | 2025-05-15 |
| gemini | text-embedding-004 | 0.00005 | 0.00005 | embedding | 2025-05-15 |
| gemini | gemini-2.5-pro | 0.0025 | 0.015 | Google: $2.50 per 1M input / $15.00 per 1M output → converted to per-1k. | 2025-08-18 |
| gemini | gemini-2.5-pro-preview-06-05 | 0.0025 | 0.015 | preview; same per-1k conversion applied | 2025-08-18 |
| gemini | gemini-2.5-pro-preview-05-06 | 0.0025 | 0.015 | preview; same per-1k conversion applied | 2025-08-18 |
| gemini | gemini-2.5-flash | 0.00010 | 0.00040 | Google: $0.10 per 1M input / $0.40 per 1M output → per-1k. (Flash family) | 2025-08-18 |
| gemini | gemini-2.5-flash-lite | 0.00010 | 0.00040 | Flash-Lite (GA) — same per-1k conversion applied | 2025-08-18 |
| gemini | gemini-2.5-flash-lite-preview-06-17 | 0.00010 | 0.00040 | preview; converted | 2025-08-18 |
| gemini | gemini-2.5-flash-preview-05-20 | 0.00010 | 0.00040 | preview; converted | 2025-08-18 |
| gemini | gemini-2.0-flash | 0.00010 | 0.00040 | stable 2.0 flash (converted to per-1k) | 2025-08-18 |
| gemini | gemini-2.0-flash-001 | 0.00010 | 0.00040 | stable 2.0 flash rev 001 | 2025-08-18 |
| gemini | gemini-2.0-flash-exp | 0.00010 | 0.00040 | experimental (use provider page to confirm) | 2025-08-18 |
| gemini | gemini-2.0-flash-exp-image-generation | 0.00010 | 0.00040 | experimental image generation (confirm per-image pricing separately) | 2025-08-18 |
| gemini | gemini-2.0-flash-lite | 0.00010 | 0.00040 | stable 2.0 flash-lite | 2025-08-18 |
| gemini | gemini-2.0-flash-lite-001 | 0.00010 | 0.00040 | stable 2.0 flash-lite rev 001 | 2025-08-18 |
| gemini | gemini-2.0-flash-lite-preview-02-05 | 0.00010 | 0.00040 | preview flash-lite (Feb 05 2025) | 2025-08-18 |
| gemini | gemini-2.0-flash-lite-preview | 0.00010 | 0.00040 | preview flash-lite (Feb 05 2025 alt) | 2025-08-18 |
| gemini | gemini-2.0-flash-preview-image-generation | 0.00010 | 0.00040 | preview image generation | 2025-08-18 |
| gemini | gemini-2.5-pro-preview-06-05 | 0.0025 | 0.015 | duplicate preview row (kept same pricing) | 2025-08-18 |
| gemini | gemini-1.5-pro-latest | 0.004 | 0.012 | alias latest pro | 2025-08-18 |
| gemini | gemini-1.5-pro-002 | 0.004 | 0.012 | stable 002 | 2025-08-18 |
| gemini | gemini-1.5-flash-latest | 0.00125 | 0.004 | alias latest flash | 2025-08-18 |
| gemini | gemini-1.5-flash-002 | 0.00125 | 0.004 | stable 002 | 2025-08-18 |
| gemini | gemini-1.5-flash-8b | - | - | small flash 8B — provider pages show varying prices; leave for per-host lookup | 2025-08-18 |
| gemini | gemini-1.5-flash-8b-001 | - | - | 8B rev 001 | 2025-08-18 |
| gemini | gemini-1.5-flash-8b-latest | - | - | alias latest 8B | 2025-08-18 |
| gemini | gemini-2.0-flash-thinking-exp | - | - | experimental thinking — see Google docs | 2025-08-18 |
| gemini | gemini-2.0-flash-thinking-exp-1219 | - | - | experimental thinking 1219 | 2025-08-18 |
| gemini | gemini-2.5-flash-preview-tts | - | - | TTS preview pricing often quoted separately (per-audio/min or per-character). Check provider docs. | 2025-08-18 |
| gemini | gemini-2.5-pro-preview-tts | - | - | TTS preview; leave for TTS-specific rates | 2025-08-18 |
| gemini | learnlm-2.0-flash-experimental | - | - | learnLM experimental | 2025-08-18 |
| gemini | gemma-3-1b-it | - | - | gemma family — pricing varies by host | 2025-08-18 |
| gemini | gemma-3-4b-it | - | - |  | 2025-08-18 |
| gemini | gemma-3-12b-it | - | - |  | 2025-08-18 |
| gemini | gemma-3-27b-it | - | - |  | 2025-08-18 |
| gemini | gemma-3n-e4b-it | - | - | gemma 3n e4b | 2025-08-18 |
| gemini | gemma-3n-e2b-it | - | - | gemma 3n e2b | 2025-08-18 |
| gemini | embedding-001 | - | - | legacy embedding | 2025-08-18 |
| gemini | gemini-embedding-exp-03-07 | - | - | embedding experimental 03-07 | 2025-08-18 |
| gemini | gemini-embedding-exp | - | - | embedding experimental | 2025-08-18 |
| gemini | gemini-embedding-001 | - | - | embedding 001 | 2025-08-18 |
| gemini | aqa | - | - | answer quality assistant | 2025-08-18 |
| gemini | imagen-3.0-generate-002 | - | - | image generation | 2025-08-18 |
| gemini | imagen-4.0-generate-preview-06-06 | - | - | image generation preview | 2025-08-18 |
| huggingface | meta-llama/Llama-3.1-8B-Instruct | 0.0006 | 0.0006 | inference hosted sample (varies by provider & hardware) | 2025-05-15 |
| huggingface | mistralai/Mistral-7B-Instruct-v0.3 | 0.0005 | 0.0005 | example hosted inference pricing; actual HF Inference bills by compute time/hardware. | 2025-05-15 |
| huggingface | nvidia/Llama-3.1-Nemotron-70B-Instruct | 0.0012 | 0.0012 |  | 2025-05-15 |
| lmstudio | TheBloke/Mistral-7B-Instruct-GGUF | 0 | 0 | local free | 2025-05-15 |
| lmstudio | Qwen/Qwen2.5-7B-Instruct-GGUF | 0 | 0 | local free | 2025-05-15 |
| lmstudio | nomic-ai/nomic-embed-text-v1.5 | 0 | 0 | local free | 2025-05-15 |

| provider | model_id | prompt_per_1k | completion_per_1k | notes | effective_date |
|----------|----------|---------------|-------------------|-------|----------------|
| openrouter | mistralai/mistral-medium-3.1 | - | - | imported from OpenRouter GET /models — OpenRouter passes through provider pricing; fetch via OpenRouter API for exact per-model pricing. | 2025-08-18 |
| openrouter | baidu/ernie-4.5-21b-a3b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | baidu/ernie-4.5-vl-28b-a3b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | z-ai/glm-4.5v | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | ai21/jamba-mini-1.7 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | ai21/jamba-large-1.7 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-5-chat | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-5 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-5-mini | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-5-nano | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-oss-120b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-oss-20b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-oss-20b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | anthropic/claude-opus-4.1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/codestral-2508 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-30b-a3b-instruct-2507 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | z-ai/glm-4.5 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | z-ai/glm-4.5-air:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | z-ai/glm-4.5-air | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-235b-a22b-thinking-2507 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | z-ai/glm-4-32b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-coder:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-coder | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | bytedance/ui-tars-1.5-7b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.5-flash-lite | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-235b-a22b-2507 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | switchpoint/router | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | moonshotai/kimi-k2:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | moonshotai/kimi-k2 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | thudm/glm-4.1v-9b-thinking | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/devstral-medium | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/devstral-small | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | cognitivecomputations/dolphin-mistral-24b-venice-edition:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | x-ai/grok-4 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3n-e2b-it:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | tencent/hunyuan-a13b-instruct:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | tencent/hunyuan-a13b-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | tngtech/deepseek-r1t2-chimera:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | morph/morph-v3-large | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | morph/morph-v3-fast | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | baidu/ernie-4.5-vl-424b-a47b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | baidu/ernie-4.5-300b-a47b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | thedrummer/anubis-70b-v1.1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | inception/mercury | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-small-3.2-24b-instruct:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-small-3.2-24b-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | minimax/minimax-m1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.5-flash-light-preview-06-17 | - | - | imported from OpenRouter GET /models (possible typo) | 2025-08-18 |
| openrouter | google/gemini-2.5-flash | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.5-pro | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | moonshotai/kimi-dev-72b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o3-pro | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | x-ai/grok-3-mini | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | x-ai/grok-3 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/magistral-small-2506 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/magistral-medium-2506 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/magistral-medium-2506:thinking | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.5-pro-preview | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-0528-qwen3-8b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-0528-qwen3-8b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-0528:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-0528 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | sarvamai/sarvam-m:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | anthropic/claude-opus-4 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | anthropic/claude-sonnet-4 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/devstral-small-2505:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/devstral-small-2505 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3n-e4b-it:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3n-e4b-it | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/codex-mini | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | nousresearch/deephermes-3-mistral-24b-preview | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-medium-3 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.5-pro-preview-05-06 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | arcee-ai/spotlight | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | arcee-ai/maestro-reasoning | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | arcee-ai/virtuoso-large | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | arcee-ai/coder-large | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | microsoft/phi-4-reasoning-plus | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | inception/mercury-coder | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-4b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | opengvlab/internvl3-14b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-prover-v2 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | meta-llama/llama-guard-4-12b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-30b-a3b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-30b-a3b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-8b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-8b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-14b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-14b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-32b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-235b-a22b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen3-235b-a22b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | tngtech/deepseek-r1t-chimera:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | tngtech/deepseek-r1t-chimera | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | microsoft/mai-ds-r1:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | microsoft/mai-ds-r1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | thudm/glm-z1-32b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | thudm/glm-4-32b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o4-mini-high | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o3 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o4-mini | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | shisa-ai/shisa-v2-llama3.3-70b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | shisa-ai/shisa-v2-llama3.3-70b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-4.1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-4.1-mini | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-4.1-nano | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | eleutherai/llemma_7b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | alfredpros/codellama-7b-instruct-solidity | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | arliai/qwq-32b-arliai-rpr-v1:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | arliai/qwq-32b-arliai-rpr-v1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | agentica-org/deepcoder-14b-preview:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | agentica-org/deepcoder-14b-preview | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | moonshotai/kimi-vl-a3b-thinking:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | moonshotai/kimi-vl-a3b-thinking | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | x-ai/grok-3-mini-beta | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | x-ai/grok-3-beta | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | nvidia/llama-3.3-nemotron-super-49b-v1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | nvidia/llama-3.1-nemotron-ultra-253b-v1:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | nvidia/llama-3.1-nemotron-ultra-253b-v1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | meta-llama/llama-4-maverick | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | meta-llama/llama-4-scout | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-v3-base | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | scb10x/llama3.1-typhoon2-70b-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.5-pro-exp-03-25 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen2.5-vl-32b-instruct:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen2.5-vl-32b-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-chat-v3-0324:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-chat-v3-0324 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | featherless/qwerky-72b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o1-pro | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-small-3.1-24b-instruct:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-small-3.1-24b-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3-4b-it:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3-4b-it | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3-12b-it:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3-12b-it | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | cohere/command-a | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-4o-mini-search-preview | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/gpt-4o-search-preview | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | rekaai/reka-flash-3:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3-27b-it:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemma-3-27b-it | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | thedrummer/anubis-pro-105b-v1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | thedrummer/skyfall-36b-v2 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | microsoft/phi-4-multimodal-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | perplexity/sonar-reasoning-pro | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | perplexity/sonar-pro | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | perplexity/sonar-deep-research | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwq-32b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwq-32b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | nousresearch/deephermes-3-llama-3-8b-preview:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.0-flash-lite-001 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | anthropic/claude-3.7-sonnet | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | anthropic/claude-3.7-sonnet:thinking | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | perplexity/r1-1776 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-saba | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | cognitivecomputations/dolphin3.0-r1-mistral-24b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | cognitivecomputations/dolphin3.0-r1-mistral-24b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | cognitivecomputations/dolphin3.0-mistral-24b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | cognitivecomputations/dolphin3.0-mistral-24b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | meta-llama/llama-guard-3-8b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o3-mini-high | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-distill-llama-8b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.0-flash-001 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen-vl-plus | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | aion-labs/aion-1.0 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | aion-labs/aion-1.0-mini | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | aion-labs/aion-rp-llama-3.1-8b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen-vl-max | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen-turbo | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen2.5-vl-72b-instruct:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen2.5-vl-72b-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen-plus | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | qwen/qwen-max | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o3-mini | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-distill-qwen-1.5b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-small-24b-instruct-2501:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/mistral-small-24b-instruct-2501 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-distill-qwen-32b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-distill-qwen-14b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-distill-qwen-14b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | perplexity/sonar-reasoning | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | perplexity/sonar | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | liquid/lfm-7b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | liquid/lfm-3b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-distill-llama-70b:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1-distill-llama-70b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-r1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | minimax/minimax-01 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | mistralai/codestral-2501 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | microsoft/phi-4 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | deepseek/deepseek-chat | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | sao10k/l3.3-euryale-70b | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | openai/o1 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | x-ai/grok-2-vision-1212 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | x-ai/grok-2-1212 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | cohere/command-r7b-12-2024 | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | google/gemini-2.0-flash-exp:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | meta-llama/llama-3.3-70b-instruct:free | - | - | imported from OpenRouter GET /models | 2025-08-18 |
| openrouter | meta-llama/llama-3.3-70b-instruct | - | - | imported from OpenRouter GET /models | 2025-08-18 |

Disclaimer: Values may be outdated. Update effective_date when modifying.
