# Speech

## Synthesize a WAV locally

With a converted package and a GPU build, use the package directory as the model.
Choose a voice included in the Phonon package, or use the default MMS voice.

```sh
hellas speak --model ./phonon --text 'Hello from Hellas.' --voice Easton -o phonon.wav --local
hellas speak --model ./mms --text 'Hello from Hellas.' -o mms.wav --local
```

Omit `--text` to read from standard input.

## Speech on one gateway

`POST /v1/audio/speech` accepts JSON and returns audio bytes. The request's
`model` selects either a hosted audio interface through Fetch or a native
package, MMS English or Phonon, through Compute. All use the existing listener
and its bearer.

```sh
curl -H "Authorization: Bearer $(cat "$HOME/gateway.bearer")" \
  -H 'Content-Type: application/json' \
  -d '{"model":"hosted","input":"Hello","voice":"default","response_format":"wav"}' \
  http://127.0.0.1:8080/v1/audio/speech -o speech.wav
```

Change only `model` to `mms` to use the native route in the example below.
The hosted service must support the requested voice and configured format;
its voice identifiers remain its own. MMS has one voice, named `default`. A
Phonon package serves the voices converted into it, under their catalog names.

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

## Prepare the MMS package

Convert a published checkpoint at an immutable 40-hex revision:

```sh
hellas convert-speech facebook/mms-tts-eng@COMMIT -o ./mms
hellas model describe ./mms -o ./mms-remote
hellas program ./mms --backend hellas/catena-dfad87438018-hip
```

Conversion applies the pinned catena-models weight normalization, transpose and
BF16 preparation once. The package contains `weights.bf16`, `config.json`,
`vocab.json`, `tokenizer_config.json` and `special_tokens_map.json`. A descriptor
replaces the weights with their content reference in `descriptor.json`.
HIP and CUDA use the existing Catena evaluators; conversion, describing and
rendering a program do not run synthesis or open a GPU.

The provider indexes the full package's weights. The gateway can render from
its descriptor. The native model validates the two output artifacts, checks
status and sample count, and encodes only the valid finite waveform prefix.
Configure provider Compute admission for the program printed by `hellas program`
and enough output for the 1,920,000-byte waveform plus 16-byte descriptor.

## Prepare a Phonon package

A Phonon package combines a model checkpoint, the codec it names and one or
more voices from the voice catalog, each at an immutable 40-hex revision:

```sh
hellas convert-phonon MODEL@MODEL_COMMIT --voice Easton --voice Zoey -o ./phonon
hellas program ./phonon --backend hellas/catena-dfad87438018-hip
```

`MODEL` is the checkpoint's repository, such as the English `phonon-31m-en`
or a 40M language checkpoint. The codec and voice catalog repositories are
pinned by the model family. Voice names are
those of the catalog's `voices.jsonl`, and must be plain file names.

The package contains `weights.bin` (model weights as BF16, codec weights as
F32), one `voices/NAME.bf16` per voice, the model and codec configuration and
tokenizer, and `assets.json`, which names each of those files' content. A
client that only renders jobs needs the JSON files, not the weights or voices.
The provider indexes the full package. One job runs `phonon.setup` for the
voice and `phonon.synthesize` per utterance. Each utterance returns a 16-byte
descriptor and a waveform of up to `ceil((tokens + 6) * 25 / 6)` frames of
7,680 bytes, about 1.8 MB for 50 tokens; configure provider Compute admission
for the program printed by `hellas program` and that much output per utterance.

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
provider = "ENROLLMENT_ID@NODE_ID"
max_price = 20

[backends.native]
kind = "paid"
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
package = "/srv/models/mms-remote"
```

A Phonon package uses the same `kind = "native"` target with its package
directory. Each model alias has one speech target in the existing route table. Both target
kinds share request parsing, response delivery and provenance. Generic HTTP
passthrough has no speech configuration.

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
