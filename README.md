# Hellas

Hellas runs AI jobs on GPUs you don't own, and on your own GPU for people you
trust. Your machine renders each job, for example a Whisper transcription or a
Qwen chat turn, into an exact program with content-addressed inputs. The
provider runs that program and signs the result. Your machine checks the
signature and decodes the result. You pay a provider with devnet coins, run
under access someone shared with you, or run the job yourself.

## Install

```sh
curl -fsSL https://github.com/hellas-ai/hellas/releases/latest/download/install.sh | sh
```

This installs the portable client. GPU machines run the `ghcr.io/hellas-ai/hellas:hip`
or `:cuda` image, or the [NixOS module](docs/nix.md).

Hellas does not host model weights. Every machine converts the same pinned
checkpoint, and a pinned commit converts to the same bytes on every machine.
That is how your job names the provider's weights by hash. Fetch Whisper tiny,
a small Qwen3 and a sample recording:

```sh
hellas convert-whisper openai/whisper-tiny@169d4a4341b33bc18d8881c4b69c2e104e1cc0af -o whisper-tiny
curl -fLo qwen3.gguf https://huggingface.co/unsloth/Qwen3-0.6B-GGUF/resolve/50968a4468ef4233ed78cd7c3de230dd1d61a56b/Qwen3-0.6B-BF16.gguf
curl -fLo speech.wav https://raw.githubusercontent.com/ggml-org/whisper.cpp/b0a11594aec50892a02cd8d129eee2dfe93a8bb8/samples/jfk.wav
```

## 1. Start an HTTP endpoint

On a GPU machine, one command serves both packages. Qwen uses GGUF; Whisper
and Flux use the directories produced by their converters. Hellas detects the
kind and prints each model, API path and backend at startup.

```sh
hellas gateway --model ./qwen3.gguf --model ./whisper-tiny --wrap claude
```

`--wrap` gives the child its OpenAI and Anthropic URLs and a private bearer,
then drains the gateway when the child exits. Without `--wrap`, the gateway
runs in the foreground and prints its URL and bearer to the terminal. For
headless use, `--bearer-file PATH` writes the bearer atomically with mode 0600;
without a wrapper, file or terminal, startup fails. Routing configuration is
not saved, and each start creates a new bearer.

An upstream works without a GPU. The key file is read at startup:

```sh
hellas gateway \
  --upstream openrouter=https://openrouter.ai/api,key-file="$HOME/or.key" \
  --model gpt-5@openrouter --wrap claude
```

Repeat `--model NAME@a --model NAME@b` to specify failover order. Several
models and backends can serve requests concurrently. A request can change
backends only before a proposal; an accepted job is never replayed on another
backend. See the [HTTP gateway guide](docs/http-gateway.md).

## 2. Share your GPU

Start the persistent daemon on the GPU machine:

```sh
hellas serve
```

A new node prints one `hellas-invite:` line and waits for its owner. In another
shell on that machine, claim it and add the packages already stored there:

```sh
hellas pair hellas-invite:… --name mine
hellas route add "$PWD/whisper-tiny"
hellas route add "$PWD/qwen3.gguf"
hellas routes
```

Each edit is one atomic configuration change. The daemon restores the saved
configuration after restart. It publishes bounded resources for the packages;
sharing uses the existing authority and allowance commands.

Your friend runs `hellas contact` and sends you their contact. Give that
contact ten requests for a day and send them the resulting access bundle:

```sh
hellas share --to hellas-contact:… --limit requests:total:10 --expires 1d --out friend.access
```

Your friend imports it under a contact name and renders requests from their
own copy of the same package or a [metadata-only descriptor](docs/http-gateway.md#model-packages-and-descriptors):

```sh
hellas pair friend.access --name alice
hellas gateway --model ./qwen3.gguf@alice --wrap claude
```

Each native job runs in its own process group. This contains crashes and
execution timeouts; it is not a security sandbox. Programs can access the
provider user's files and devices. Only grant execution to people whose
programs you trust. See [node administration](docs/admin.md).

## 3. Run a single job

The same packages work with the job commands. On your GPU:

```sh
hellas transcribe --model whisper-tiny --audio speech.wav --local
```

Or use a friend's access bundle and their GPU evaluator:

```sh
hellas transcribe --model whisper-tiny --audio speech.wav --access friend.access \
  --backend hellas/catena-dfad87438018-hip
```

A paid job uses devnet coins and checks the quoted price before signing:

```sh
hellas faucet
hellas transcribe --model whisper-tiny --audio speech.wav --pay 20 \
  --provider "$DEVNET_PROVIDER" --backend hellas/catena-dfad87438018-hip
```

`--local` is available in GPU builds. NVIDIA providers use the CUDA evaluator.
See [jobs](docs/jobs.md) for text, image, Fetch and prepared-program commands.

## More

- [HTTP gateway](docs/http-gateway.md): models, upstreams, sessions and cancellation.
- [Node administration](docs/admin.md): sharing, renewal, revocation and authority.
- [Selling on the devnet](docs/paid-gateway.md): paid terms, stake and channels.
- [Chain](docs/chain.md): querying the devnet and running validators.
- [Nix, Docker and NixOS](docs/nix.md): builds, modules, images and development checks.
