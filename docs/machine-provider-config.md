# Machine provider configuration

The provider selector and provider-specific configuration are illustrated in
[machine-provider.json](machine-provider.json). Pass its `provider` value with `--provider`, and save the `config` object as the file supplied to
`--provider-config`. Replace the example template id with your own.

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
