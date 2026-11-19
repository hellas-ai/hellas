# Speech on one gateway

`POST /v1/audio/speech` accepts JSON and returns audio bytes. The request's
`model` selects either a hosted audio interface through paid Fetch or an MMS
English package through Compute. Both use the existing listener and its bearer.

```sh
curl -H "Authorization: Bearer $(cat "$HOME/gateway.bearer")" \
  -H 'Content-Type: application/json' \
  -d '{"model":"hosted","input":"Hello","voice":"default","response_format":"wav"}' \
  http://127.0.0.1:8080/v1/audio/speech -o speech.wav
```

Change only `model` to `mms` to use the native route in the example below.
The hosted service must support the requested voice and configured format;
its voice identifiers remain its own. MMS has one voice, named `default`.

MMS accepts `response_format: "wav"` and finite `speed` between 0.25 and 4
(default 1). The result is mono 16 kHz, signed 16-bit PCM WAV. Text uses the
pinned MMS English tokenizer and must fit its 512-token limit after blank
insertion. Invalid durations or audio longer than the model's 30-second
capacity fail explicitly. Hosted speech accepts only the configured `wav`
and/or `mp3` mappings and speed 1. Omitting `response_format` selects `mp3`,
which therefore requires a hosted mp3 mapping; MMS callers must request wav.
Unknown fields, unsupported settings and query parameters receive 400 before
execution. Audio bytes from the hosted service retain its content type.

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

## Gateway configuration

These entries belong in the shared daemon TOML document described in
[HTTP gateway](http-gateway.md#shared-toml-configuration). Replace enrollment
and node IDs with the providers' published identities and set accepted prices.
A native provider may instead be an existing local or Grant backend.

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
kind = "http"
backends = ["hosted"]
[routes.targets.hosted]
service = "audio"
method = "speech"
[routes.targets.hosted.route]
path = "/v1/audio/speech"
method = "POST"
url = "https://audio.example/v1/text-to-speech/{voice_id}"
models = ["hosted"]
[routes.targets.hosted.route.hosted_speech]
model_id = "upstream-model"
[routes.targets.hosted.route.hosted_speech.formats]
wav = "UPSTREAM_WAV_FORMAT"
mp3 = "UPSTREAM_MP3_FORMAT"

[[routes]]
kind = "model"
backends = ["native"]
modality = "speech"
model = "mms"
package = "/srv/models/mms-remote"
```

The adaptor maps `input` to upstream `text`, uses the configured upstream
`model_id`, encodes `voice` as one path segment, and puts the mapped format in
`output_format`. It forwards neither the gateway bearer nor a buyer-supplied
upstream credential. JSON gzip/zstd bodies are decoded before translation.
The seller injects its key through the ordinary Fetch credential machinery.

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
allowed_paths = ["/v1/text-to-speech/{voice_id}"]
allowed_methods = ["POST"]
header_name = "x-hosted-key"
secret = "SELLER_SECRET"
```

Supply the real secret through the seller's private configuration. It is
redacted from the daemon's configuration echo and stays out of buyer requests
and transcripts. Approve the seller's HTTP Fetch admission and per-request
paid terms as described in [paid work](paid-gateway.md).

A scope permits one complete `{voice_id}` segment, with exact surrounding path
segments, origin, method and trust roots. It does not cover `/stream` or another
suffix. A second explicit scope is required for those paths. Slashes,
backslashes, percent signs, query/fragment delimiters, dot segments and
noncanonical percent encodings cannot be used as voices. Overlapping template
and exact credential scopes are rejected at configuration time.

The integration test uses local TLS, a paid seller and buyer, and one HTTP
listener/bearer. The same client switches only `model` between hosted speech
and a test evaluator returning the MMS output ABI. It checks the real MMS
rendered job, decoder and WAV encoder, upstream URL/body/key translation,
explicit rejection, and paid completion. Actual GPU synthesis is a separate
hardware validation step.
