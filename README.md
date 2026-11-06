# Hellas

Hellas runs GPU programs and HTTPS requests through signed jobs. Share access
with someone you trust, or pay a provider for work.

## Install

Static CLI binaries for [Linux](https://hydra.hellas.ai/job/hellas/hellas-cli/x86_64-linux.artifacts.portable-x86_64) and [macOS](https://hydra.hellas.ai/job/hellas/hellas-cli/aarch64-darwin.artifacts.portable-aarch64) are built as our [Hydra channel](https://hydra.hellas.ai/jobset/hellas/hellas-cli) advances. Install like so:

```sh
curl -fsSL https://github.com/hellas-ai/hellas/releases/latest/download/install.sh | sh
```

Add `~/.local/bin` to your PATH if prompted. Check the installed version:

```sh
hellas --version
```

## Prepare Whisper

Download Whisper Tiny, convert its weights and get a short audio sample:

```sh
mkdir -p whisper-tiny-original
base=https://huggingface.co/openai/whisper-tiny/resolve/169d4a4341b33bc18d8881c4b69c2e104e1cc0af
curl -fL --output-dir whisper-tiny-original --remote-name-all \
  "$base/config.json" "$base/generation_config.json" \
  "$base/tokenizer.json" "$base/model.safetensors"
hellas convert-whisper --checkpoint ./whisper-tiny-original --output ./whisper-tiny
curl -fL https://raw.githubusercontent.com/ggml-org/whisper.cpp/b0a11594aec50892a02cd8d129eee2dfe93a8bb8/samples/jfk.wav -o speech.wav
```

## Share a transcription

On an NVIDIA GPU machine with Docker and NVIDIA Container Toolkit CDI, prepare the model above and run the provider in another window (or have a friend run it):

```sh
mkdir -p worker
docker run --rm --network host --device nvidia.com/gpu=all \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/worker:/var/lib/hellas" \
  -v "$PWD/whisper-tiny:/models/whisper-tiny:ro" \
  ghcr.io/hellas-ai/hellas:cuda \
  --identity ./identity --software-root --await-owner ./node \
  --audio-model /models/whisper-tiny --store-dir ./store
```

Create the owner identity and pair through the provider's private invitation (copy `worker/node/invitation.json` securely from your friend if needed):

```sh
mkdir -p owner guest
hellas --identity ./owner/identity --software-root identity init --passkey-out ./owner/owner.passkey
hellas --identity ./owner/identity --passkey ./owner/owner.passkey admin bootstrap-remote \
  --invitation ./worker/node/invitation.json --profile-out ./owner/operator
```

Create a guest identity and export its public contact and holder:

```sh
hellas --identity ./guest/identity --software-root identity init --passkey-out ./guest/guest.passkey
hellas --passkey ./guest/guest.passkey contact export --display-name guest --out ./guest/guest.contact
hellas --identity ./guest/identity identity show-holder > ./guest/guest.holder
```

As the owner, share one transcription with the guest:

```sh
hellas --identity ./owner/identity --passkey ./owner/owner.passkey admin \
  --profile ./owner/operator/profile.json share \
  --contact ./guest/guest.contact --holder ./guest/guest.holder --resource whisper-tiny \
  --limit requests:total:1 --max-job 15m --expires 1h --out ./guest/guest.access
```

As the guest, import that access and transcribe the sample:

```sh
hellas --identity ./guest/identity --passkey ./guest/guest.passkey \
  offer import-bundle ./guest/guest.access --name box
hellas --identity ./guest/identity --passkey ./guest/guest.passkey transcribe \
  --offer box.whisper-tiny --model ./whisper-tiny --audio speech.wav \
  --language en --output ./guest/result
```

```text
And so my fellow Americans ask not what your country can do for you, ask what you can do for your country.
```

Coming next: paid work, Fetch, text and image generation, and gateway setup.

See the [documentation](https://docs.hellas.ai) and [administration](docs/admin.md).
