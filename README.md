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

A pinned Hub reference lets the client read the model metadata and the provider
acquire the matching weights. This walkthrough uses a published Qwen GGUF and the original Whisper tiny weights. Download the sample recording.

```sh
curl -fLo speech.wav https://raw.githubusercontent.com/ggml-org/whisper.cpp/b0a11594aec50892a02cd8d129eee2dfe93a8bb8/samples/jfk.wav
```

## 1. Start an HTTP endpoint

On a GPU machine, one command serves both models. Hellas prints each model, API path and backend at startup.

```sh
hellas gateway --model hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf --model hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e --wrap claude
```

`--wrap` gives the child its OpenAI and Anthropic URLs and a private bearer,
then drains the gateway when the child exits. Without `--wrap`, the gateway
runs in the foreground on `127.0.0.1:8080` and admits local callers without a
bearer; browser cross-site and DNS-rebinding requests are refused. Add
`--require-auth` (implied by any non-loopback `--bind`) to require a bearer,
which is printed to the terminal or, with `--bearer-file PATH`, written
atomically with mode 0600. Routing configuration is
not saved, and each start creates a new bearer. Repeatable service deployments
use the shared [`--config` TOML](docs/http-gateway.md#shared-toml-configuration)
with `gateway` or `serve`; [NixOS settings](docs/nix.md) generate the same file.

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
shell on that machine, set `INVITE` to that full line, claim the node and add
the models it will serve:

```sh
hellas pair "$INVITE" --name mine
hellas route add hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e
hellas route add hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf
hellas routes
```

Each edit is one atomic configuration change. The daemon restores the saved
configuration after restart. It publishes bounded resources for the packages;
sharing uses the existing authority and allowance commands.

Your friend runs `hellas contact` and sends you their contact. Set
`FRIEND_CONTACT` to that full contact string. Give that
contact ten requests to the `Qwen3-0.6B-BF16` resource for a day and send them the
resulting access bundle. Select the resource explicitly when the node serves
several packages; `hellas routes` lists their names:

```sh
hellas share --to "$FRIEND_CONTACT" --resource Qwen3-0.6B-BF16 --limit requests:total:10 --expires 1d --out friend.access
```

Your friend imports it under a contact name and renders requests from their
[pinned model reference](docs/http-gateway.md#model-sources).

```sh
hellas pair friend.access --name alice
hellas gateway --model hf://ggml-org/Qwen3-0.6B-GGUF@afe8ad3577aa22500b3cd1c880f153b3b0e1cae8/Qwen3-0.6B-BF16.gguf@alice --wrap claude
```

Each native job runs in its own process group. This contains crashes and
execution timeouts; it is not a security sandbox. Programs can access the
provider user's files and devices. Only grant execution to people whose
programs you trust. See [node administration](docs/admin.md).

## 3. Run a single job

The same packages work with the job commands. On your GPU:

```sh
hellas transcribe --model hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e --audio speech.wav --local
```

For remote transcription, ask the provider to share its `whisper-tiny` resource. Use that access bundle and the provider's GPU evaluator.

```sh
hellas transcribe --model hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e --audio speech.wav --access whisper.access \
  --backend hellas/catena-dfad87438018-hip-gfx1151
```

A paid job uses devnet coins and checks the quoted price before signing:

```sh
hellas faucet
hellas transcribe --model hf://unsloth/whisper-tiny@34457cb234c8624f23ac716000773b367000df6e --audio speech.wav --pay 20 \
  --provider "$DEVNET_PROVIDER" --backend hellas/catena-dfad87438018-hip-gfx1151
```

`--local` is available in GPU builds. A provider's evaluator names its GPU runtime and architecture, such as `-cuda-sm_120` for an RTX 5090.
See [jobs](docs/jobs.md) for text, image, decision, Fetch and prepared-program commands.

## More

- [HTTP gateway](docs/http-gateway.md): models, upstreams, sessions and cancellation.
- [Node administration](docs/admin.md): sharing, renewal, revocation and authority.
- [Selling on the devnet](docs/paid-gateway.md): paid terms, stake and channels.
- [Chain](docs/chain.md): querying the devnet and running validators.
- [Nix, Docker and NixOS](docs/nix.md): builds, modules, images and development checks.
