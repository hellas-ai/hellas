# Machine provider configuration

The provider selector and provider-specific configuration are illustrated in
[machine-provider.json](machine-provider.json). Pass the whole file to
`--provider-config`; its `provider` selects the typed provider configuration in
`config`. Replace the example template id with your own. For list or destroy,
`config` may be an empty object; creation requires a template.

The RunPod template must use the same digest-pinned image requested by the
machine spec, mount persistent data at `/var/lib/hellas`, and provide nonzero
container and volume disks. Templates are provider configuration; the generic
machine spec contains only `name`, `image`, `accelerator`, `accelerator_count`
and `interruptible`.

The credential-source file uses the shared HTTP credential source format, for
example `{"secret_file":"/private/accounts/provider.json","secret_field":"token"}`.
The referenced private JSON file is maintained by your login tool and contains
the provider API token. Explicit `secret_env` or the existing file refresh
command may be used instead; there is no implicit environment fallback.

Creation returns public resource metadata only. Bootstrap the resulting node
through its normal HostControl using the invitation printed by `serve
--await-owner` in the provider's authenticated console. If creation cannot be
confirmed, reconcile by the requested name before retrying; a failed response
can still correspond to an allocated, billable resource.

The ordinary image does not enable bootstrap by default. Its entrypoint is
`serve --port 31145`; configure the provider template's additional arguments as
`--await-owner /var/lib/hellas/authority` to opt in. Preserve the persistent mount.

RunPod does not expose inbound UDP ([port documentation](https://docs.runpod.io/pods/configuration/expose-ports)).
Do not request `31145/udp` or substitute a TCP mapping into a QUIC invitation.
Hellas uses the normal N0 address lookup and relay configuration, so keep outbound
relay connectivity available. The console's addresses are container-local hints;
the independently verified node pin remains authoritative. Test bootstrap and an
actual job from outside the Pod before considering the deployment usable.

## Images and template updates

For NVIDIA Pods, use `ghcr.io/hellas-ai/hellas:cuda`. The publisher advances
`cuda`, `hip`, and `network` only after the matching CLI and GPU Hydra builds
succeed. `latest` is an alias for **network**, which cannot execute GPU jobs.
The old `ghcr.io/hellas-ai/node:*` images and their `--execute-policy` /
`--download-policy` flags are not this CLI.

RunPod also lists AMD MI300X (`AMD Instinct MI300X OAM` in the machine spec).
AMD workers need the `hip` image and access to `/dev/kfd` and their `/dev/dri`
render devices. Image/backend selection alone does not establish model support:
MI300X is `gfx942`, while the pinned Catena packed BF16 dot implementation
requires `gfx11`. The Qwen BF16 path uses that operation. Before renting, compile
the intended kernels for the actual target using the image's compiler; a passing
Strix (`gfx1151`) test does not establish MI300X compatibility. A scalar HIP
kernel can compile for `gfx942` even when the model's BF16 kernel cannot.

Floating tags help discover a release; `machines create` requires an immutable
`ghcr.io/hellas-ai/hellas@sha256:...` in both the template and machine spec.
Take the matching backend's digest from the selected [release](https://github.com/hellas-ai/hellas/releases),
and use that release's CLI. The immutable tags are `sha-FULL_COMMIT_SHA-cuda`
and `sha-FULL_COMMIT_SHA-hip`.
Updating a tag or template does not upgrade an already running Pod. Review the
new release's state compatibility before replacing a persistent worker.

Preserve the image's Docker entrypoint: it already selects `serve`, port 31145,
and its matching backend, including CUDA driver-library setup where needed. In RunPod's
`dockerStartCmd`, pass only additional arguments, for example:

```json
["--identity", "/var/lib/hellas/worker.identity", "--software-root",
 "--await-owner", "/var/lib/hellas/authority",
 "--grant-config", "/var/lib/hellas/resources.json",
 "--content-config", "/var/lib/hellas/content.toml"]
```

Prepare `resources.json`, a `[content]` declaration with lower directories and
Jobs pins, and the weights on the persistent volume before using
that command; a template does not create an allowance or download models.
Use the [node configuration and bootstrap procedure](admin.md#explicit-offline-initialization-and-recovery),
then issue/import access and run a job as in the
[owner walkthrough](../README.md#own-a-worker-and-share-access). `admin share`
requires a release containing that command on both client and worker.
The state filesystem must preserve private files owned by the daemon user
(mode `0600` on Unix). If startup reports `file must be private`, inspect the
reported path's owner and permissions on the actual mounted filesystem; do not
relax the check or advertise the worker as ready. RunPod's volume disk can be
[network-backed](https://github.com/runpod/runpod-plugins-official/blob/main/plugins/runpod/skills/runpod-usage/reference/storage.md),
so verify its semantics rather than assuming it behaves like the container disk.
Keep the identity and journal together on persistent storage across restarts.

Keep the owner passkey on the client. An unowned worker's invitation expires
15 minutes after startup; obtain it promptly through the authenticated console.

## Provision through the CLI

With `credential-source.json` and `machine-provider.json` prepared as above,
write a machine spec (replace the digest and accelerator with your selection):

```json
{
  "name": "hellas-demo",
  "image": "ghcr.io/hellas-ai/hellas@sha256:CUDA_MANIFEST_DIGEST",
  "accelerator": "NVIDIA L4",
  "accelerator_count": 1,
  "interruptible": false
}
```

```sh
hellas machines --credential-source credential-source.json \
  --provider-config machine-provider.json list
hellas machines --credential-source credential-source.json \
  --provider-config machine-provider.json create --spec machine.json
# After closing paid channels and retaining any needed results:
hellas machines --credential-source credential-source.json \
  --provider-config machine-provider.json destroy POD_ID
```

Creation allocates a billable GPU Pod; it does not wait for the image to pull,
bootstrap its owner, or verify inference. Retain the returned Pod ID for cleanup.
The CLI currently creates, lists and destroys Pods; template editing remains a
RunPod console/API operation. Review the template before allocating, and use
`list` to reconcile an uncertain creation result rather than blindly retrying.

An OS store reference uses the same credential source:
`{"secret_store":{"backend":"native","service":"hellas-gate","key":"provider-token"}}`.
The native store is macOS Keychain, Windows Credential Manager or Linux Secret
Service. Missing, locked or unavailable stores fail; they never fall back to a
file or an environment variable. The credential must contain nonempty UTF-8.
The existing `prefix` field applies after resolution, and rotation is observed
on the next request. `secret_store` is exclusive with env, file and refresh
settings.

Headless operators may explicitly select
`{"secret_store":{"backend":"headless_files","directory":"/private/secrets","service":"hellas-node","key":"provider-token"}}`.
This uses `hellas-private`'s opaque-secret store, not a JSON credential file.
Service and key names contain 1–128 ASCII letters, digits, hyphens or underscores.
`SecretStore::set/get/delete` are blocking APIs; async applications use a blocking
worker. The common bound is 64 KiB per secret; Windows Credential Manager's
native limit is 2,560 bytes. Oversize values fail rather than being split or
written elsewhere. Linux stores base64 internally to preserve arbitrary bytes
with Secret Service implementations that accept only UTF-8.

The RunPod API endpoint defaults to `https://rest.runpod.io/v1`. Set
`config.base_url` in the provider configuration or `RUNPOD_BASE_URL` in the
process environment to use another HTTP(S) endpoint, including its API path
prefix. An explicit configuration value takes precedence over the environment.
URLs containing credentials, query strings or fragments are rejected; redirects
are not followed. The configured provider credential is sent to this endpoint.
