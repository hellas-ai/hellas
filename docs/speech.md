# Speech

## Synthesize a WAV locally

With a GPU build, use a pinned checkpoint for MMS English, OmniVoice or Phonon. Set `PHONON_ORG` to the publisher of the Phonon model.

```sh
hellas speak --model hf://k2-fsa/OmniVoice@3fc979d1cd72492cd679c5ac2611e0d7ac047ba1 --text 'Hello from Hellas.' -o omni.wav --local
hellas speak --model "hf://${PHONON_ORG}/phonon-31m-en@8f7a37c94a4c58b04c8287300c53f11d2e208eae" --text 'Hello from Hellas.' --voice Easton -o phonon.wav --local
hellas speak --model hf://whatever0705/mms-tts-eng-with-discriminator@3975d411eef6e0a05ab701ce981a93dc3a2cfdae --text 'Hello from Hellas.' -o mms.wav --local
```

Omit `--text` to read from standard input.

## Speech on one gateway

`POST /v1/audio/speech` accepts JSON and returns audio bytes. The request's
`model` selects either a hosted audio interface through Fetch or a native
model through Compute (MMS English, OmniVoice or Phonon). All use the existing listener
and its bearer.

```sh
curl -H "Authorization: Bearer $(cat "$HOME/gateway.bearer")" \
  -H 'Content-Type: application/json' \
  -d '{"model":"hosted","input":"Hello","voice":"default","response_format":"wav"}' \
  http://127.0.0.1:8080/v1/audio/speech -o speech.wav
```

Change only `model` to `mms` to use the native route in the example below.
The hosted service must support the requested voice and configured format;
its voice identifiers remain its own. MMS has one voice, named `default`. Phonon serves the configured catalog voices. Its default is Easton. OmniVoice supports the default voice and speed 1.

MMS accepts `response_format: "wav"` and finite `speed` between 0.25 and 4
(default 1). The result is mono 16 kHz, signed 16-bit PCM WAV. Text uses the
pinned MMS English tokenizer and must fit its 512-token limit after blank
insertion. Invalid durations or audio longer than the model's 30-second
capacity fail explicitly. Hosted speech accepts only the configured `wav`
and/or `mp3` mappings and speed 1. Omitting `response_format` selects `mp3`,
which therefore requires a hosted mp3 mapping; native callers must request wav.

Phonon accepts `response_format: "wav"` and speed 1. The result is mono 24 kHz,
signed 16-bit PCM WAV. Text longer than 50 tokens is split at sentence, clause
or word boundaries into at most 32 utterances, joined by 120 ms pauses. Sampling
uses a fixed seed, so the same request renders the same job.
Unknown fields, unsupported settings and query parameters receive 400 before
execution. Both targets return a complete response after verified completion. Hosted audio
retains its content type and encoding; upstream error statuses and bodies are
preserved. Signed evidence accompanies successful and failed completions.

## MMS English

The following revision contains the original MMS English inference tensors and tokenizer. Both clients and providers accept the pinned repository or a local checkpoint directory containing `model.safetensors`, `config.json`, `vocab.json`, `tokenizer_config.json` and `special_tokens_map.json`.

```sh
hellas program hf://whatever0705/mms-tts-eng-with-discriminator@3975d411eef6e0a05ab701ce981a93dc3a2cfdae --backend hellas/catena-dfad87438018-hip
```

The client renders from metadata. The provider verifies the safetensors file and prepares the required weights on its GPU. The speech decoder checks the status and sample count and encodes the valid finite waveform samples. Configure Compute admission for the program printed by `hellas program` and allow 1,920,000 bytes for the waveform plus 16 bytes for its status and sample count.

## Original speech checkpoints

OmniVoice keeps its model weights and audio tokenizer in one repository.
Phonon defaults to the codec and voice-catalog revisions exported by Catena. On
`speak` and `program`, use `--codec REF` and `--voices REF` to select either
companion independently. Each accepts a Hub repository, a ref with a branch,
tag or exact commit, or a local path. You can select a codec safetensors file
or a JSONL voice catalog directly. The model commits to the codec, the
catalog and every voice checkpoint the catalog lists. A repository grant
must cover the origins of all these assets.
All voices share one program per evaluator. For a speech request, the client
reads the selected voice’s tensor header and puts its byte range in the plan.

```sh
hellas program "hf://${PHONON_ORG}/phonon-31m-en@8f7a37c94a4c58b04c8287300c53f11d2e208eae" --backend hellas/catena-dfad87438018-hip
```

A local OmniVoice snapshot has the same files as its Hub repository. An offline
Phonon directory contains the original `model/`, `codec/` and `voices/`
snapshots, including `voices/voices.jsonl` and the voice files named by the
catalog. With separate local directories, specify the companions explicitly.
For omitted companions of a standalone local checkpoint, Hellas looks for
Catena’s pinned revisions in the local Hub cache. Local inputs stay offline.

```sh
hellas program --model-id ./phonon-model --codec ./codec --voices ./voices/voices.jsonl
hellas speak --model ./phonon-model --codec ./codec --voices ./voices --voice Easton --text 'Hello.' -o speech.wav --local
```

## Gateway configuration

These entries belong in the shared daemon TOML document described in
[HTTP gateway](http-gateway.md#shared-toml-configuration). Replace enrollment
and node IDs with the providers' published identities and set accepted prices.
Choose execution placement with each route's `backends` list. The example uses
remote paid providers. A native target can also use a local Compute backend or a
remote grant backend. A hosted target can use a local `kind = "fetch"` backend
with the same service, method and upstream policy, or a remote grant backend.
Use the backend's `trust` settings for remote Apple App Attest. Native speech also
requires a provider that supports the package's evaluator.

```toml
[listeners.api]
kind = "http"
bind = "127.0.0.1:8080"

[backends.hosted]
kind = "paid"
max_in_flight = 1
provider = "ENROLLMENT_ID@NODE_ID"
max_price = 20

[backends.native]
kind = "paid"
max_in_flight = 1
provider = "NATIVE_ENROLLMENT_ID@NATIVE_NODE_ID"
max_price = 20
evaluator = "hellas/catena-dfad87438018-hip"

[[routes]]
kind = "speech"
backends = ["hosted"]
model = "hosted"
[routes.target]
kind = "hosted"
service = "audio"
method = "speech"
[routes.target.adaptor]
url = "https://audio.example/v1/text-to-speech/{segment}"
model_id = "upstream-model"
[routes.target.adaptor.formats]
wav = "UPSTREAM_WAV_FORMAT"
mp3 = "UPSTREAM_MP3_FORMAT"

[[routes]]
kind = "speech"
backends = ["native"]
model = "mms"
[routes.target]
kind = "native"
package = "hf://whatever0705/mms-tts-eng-with-discriminator@3975d411eef6e0a05ab701ce981a93dc3a2cfdae"
```

For Phonon, `package` can name the model by itself or specify its codec and voice catalog. Each source accepts a local path or a Hub reference. This native gateway target serves two voices from a local catalog.

```toml
[routes.target]
kind = "native"
package = { model = "/srv/phonon/model", codec = "/srv/phonon/codec", voices = "/srv/phonon/voices" }
voices = ["Easton", "Zoey"]
```

Omitting the target's voice list serves Easton. The model resource covers the entire catalog. Each speech job selects its voice by its checkpoint byte range.

The adaptor maps `input` to upstream `text`, uses the configured upstream
`model_id`, encodes `voice` as one path segment, and puts the mapped format in
`output_format`. It prepares only the translated JSON and its content type; caller headers,
including the gateway bearer, are not forwarded. JSON gzip/zstd bodies are
decoded once before model selection.
The seller injects its key through the ordinary Fetch credential machinery.

For a hosted grant, provision an HTTPS resource for the exact translated path of
each granted voice and an explicit list of permitted serialized queries per path.
For example, an HTTPS resource can contain these fields:

```toml
paths = ["/v1/text-to-speech/default"]
queries = { "/v1/text-to-speech/default" = ["output_format=UPSTREAM_WAV_FORMAT"] }
```

Use the exact encoded query produced by the configured format mapping. Entries
with a query list require one entire listed query. Other paths remain query-free.
Set the resource's TLS, response cap and account backing to agree with the
upstream configuration. Add the speech route explicitly when using a grant.

## Seller scope

The seller's Fetch backend uses the same service/method as the hosted target:

```toml
[backends.audio]
kind = "fetch"
max_in_flight = 1
service = "audio"
method = "speech"
[backends.audio.upstream]
kind = "http"
allowed_hosts = ["audio.example"]
[[backends.audio.upstream.credentials]]
allowed_origins = ["https://audio.example"]
allowed_paths = ["/v1/text-to-speech/{segment}"]
allowed_methods = ["POST"]
header_name = "x-hosted-key"
secret = "SELLER_SECRET"
```

Supply the real secret through the seller's private configuration. It is
redacted from the daemon's configuration echo and stays out of buyer requests
and transcripts. Approve the seller's HTTP Fetch admission and per-request
paid terms as described in [paid work](paid-gateway.md).

A scope permits one complete `{segment}` segment, with exact surrounding path
segments, origin, method and trust roots. It does not cover `/stream` or another
suffix. A second explicit scope is required for those paths. Slashes,
backslashes, percent signs, query/fragment delimiters, dot segments and
noncanonical percent encodings cannot be used as voices. Overlapping template
and exact credential scopes are rejected at configuration time.

The integration test uses local TLS, a paid seller and buyer, and one HTTP
listener/bearer. The same client switches only `model` between hosted speech
and a test evaluator returning the MMS output ABI. The hosted alias also runs
through local Fetch on that listener. The test checks the real MMS rendered
job, decoder and WAV encoder, upstream URL/body/key translation, rejection,
provenance and paid completion. GPU synthesis is a separate hardware check.
