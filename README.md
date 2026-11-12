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

## 1. Try it: no GPU, no account

Get devnet coins, then pay the public devnet provider to transcribe the
recording. `DEVNET_PROVIDER` is that provider's address. It runs only the
programs it was configured with, and it quotes its price before you sign
anything. `--pay 20` is the most you accept per job. Your client renders the
program for the provider's GPU before it asks for a quote: `--backend` names
that renderer, the evaluator id the provider's GPU runtime registers (here an
AMD GPU's):

```sh
hellas faucet
hellas transcribe --model whisper-tiny --audio speech.wav --pay 20 --provider "$DEVNET_PROVIDER" \
  --backend hellas/catena-dfad87438018-hip
```

It prints the transcript, "And so my fellow Americans, ask not what your
country can do for you…". Your first command creates your identity under
`~/.hellas`. Your first paid job opens a payment channel, and later jobs reuse
it.

## 2. Share your GPU with a friend

On your GPU machine, start a node that serves the converted weights and admits
the two programs that read them. `hellas program` prints a program's ID for a
renderer:

```sh
docker run -d --name hellas --network host --device /dev/kfd --device /dev/dri \
  -v hellas:/var/lib/hellas -v "$PWD:/models:ro" ghcr.io/hellas-ai/hellas:hip \
  --content /models/whisper-tiny --program "$(hellas program --backend hellas/catena-dfad87438018-hip whisper-tiny)" \
  --content /models/qwen3.gguf --program "$(hellas program --backend hellas/catena-dfad87438018-hip qwen3.gguf)"
docker logs hellas
```

A new node has no owner yet. It prints one `hellas-invite:` line and waits.
Claim it with that line. NVIDIA hosts use the `:cuda` image with
`--device nvidia.com/gpu=all` and the `hellas/catena-dfad87438018-cuda` renderer
instead.

```sh
hellas pair hellas-invite:…
```

Your friend prints their contact and sends it to you:

```sh
hellas contact
```

Give that contact ten requests for a day, and send them `friend.access`:

```sh
hellas share --to hellas-contact:… --limit requests:total:10 --expires 1d --out friend.access
```

Your friend runs jobs on your GPU with it, rendered for your GPU's runtime:

```sh
hellas transcribe --model whisper-tiny --audio speech.wav --access friend.access \
  --backend hellas/catena-dfad87438018-hip
```

The node runs one job at a time and refuses programs it was not configured
with, including programs rendered for a GPU runtime it does not run. Each job runs in its own process group, which contains crashes and
timeouts. This is not a sandbox: a program can reach whatever the node's user
can reach, and nothing meters GPU memory. Compiling a new program has no time
limit; a node's first job of each program pays for it. A grant or paid-terms
configuration can admit any program instead. That hands anyone who can submit
jobs roughly root on your machine, so `serve` refuses it unless you also pass
`--knowingly-unsafe`.

## 3. Run it yourself

The GPU image runs the same job on your own GPU, with no network:

```sh
docker run --rm --device /dev/kfd --device /dev/dri -v "$PWD:/work" -w /work \
  --entrypoint hellas ghcr.io/hellas-ai/hellas:hip \
  transcribe --model whisper-tiny --audio speech.wav --local
```

`--local` exists only in GPU builds; it renders for this machine's GPU runtime,
so it takes no `--backend`. `hellas text --model qwen3.gguf --prompt …` and
`hellas run` take the same `--pay`, `--access`, `--backend` and `--local`. See
[jobs](docs/jobs.md).

## 4. An OpenAI-compatible endpoint

`hellas gateway` serves OpenAI and Anthropic routes on localhost. It renders
every request into a job and runs it the way you choose, here on your
friend's GPU:

```sh
hellas gateway --model qwen3.gguf --access friend.access --backend hellas/catena-dfad87438018-hip &
curl -s localhost:8080/v1/chat/completions -H "authorization: Bearer $(cat ~/.hellas/gateway/bearer)" \
  -H 'content-type: application/json' -d '{"model":"qwen3","messages":[{"role":"user","content":"Hi"}]}'
```

The gateway keeps its own bearer in `~/.hellas/gateway/bearer`, so a web page
you visit cannot spend your access. `--pay MAX --provider ID` and `--local`
work here too; models render for `--backend`, or locally for this machine. See the [HTTP gateway guide](docs/http-gateway.md).

## 5. Drive a coding agent

A home runs one gateway at a time, so stop the one from the previous section
first (Ctrl-C). `--wrap` starts the agent with its OpenAI and Anthropic base URLs
and token pointed at the gateway, and stops the gateway when the agent exits:

```sh
hellas gateway --model qwen3.gguf --access friend.access --backend hellas/catena-dfad87438018-hip --wrap claude
```

## More

- [Jobs](docs/jobs.md): job folders, `run`, `transact`, signed HTTPS Fetch and
  what each application proves.
- [Node administration](docs/admin.md): sharing, renewal, revocation and the
  owner's authority.
- [Selling on the devnet](docs/paid-gateway.md): paid terms, stake and
  channels.
- [Chain](docs/chain.md): querying the devnet and running validators.
- [Nix, Docker and NixOS](docs/nix.md): builds, the module, images, metrics
  and development checks.
