# Node permissions

The provider's grant journal records users and their permissions. Each user is
identified by a verified contact enrollment. The node identity is the implicit
owner and cannot be removed or demoted. Admin permission allows editing this
registry; Work permission consists of zero or more independently limited grants.
Neither permission implies the other.

Run a provider with its resource configuration (`hellas serve --grant-config
resources.json`). User commands use that provider's private control socket;
`--control-socket` selects a non-default path.

```sh
hellas admin users list
hellas admin users add operator.contact --admin
hellas admin users add consumer.contact --policy glm --limit output-tokens=200000/day --max-in-flight 2 --expires 7d
hellas admin users show USER
hellas admin users update USER --admin
hellas admin users update USER --no-admin
hellas admin users update USER --grant GRANT --limit requests=2000/day
hellas admin users update USER --grant GRANT --pause
hellas admin users update USER --grant GRANT --resume
hellas admin users update USER --grant GRANT --revoke
hellas admin users update USER --new-grant --policy another-resource
hellas admin users show USER --grant GRANT
hellas admin users offer USER --grant GRANT --out provider.offer
hellas admin users remove USER
```

`USER` is the principal id printed by add/list. With one current grant, `--grant`
can be omitted. Multiple grants require explicit selection. Terms omitted from
update keep their existing values, including the absolute expiry. `--clear-limits`
and `--no-expiry` explicitly remove those bounds; `--no-account-backed` removes
account-backed resource consent. The resource must also permit the resulting
terms. Grant creation defaults to one in-flight job and a 90-second job deadline.
Adding an admin alone creates no Work grant.

Pausing blocks new jobs but lets an already-open result stream complete.
Revoking a grant also stops its open result streams.

Every user edit is atomic, including all affected grants. Removing a user
revokes admin and Work permissions, releases queued jobs, and keeps all quota
counters. Already running jobs finish under their original deadlines and settle
usage, but cannot deliver output after revocation. An explicit add can reactivate
the same removed principal; its old grants remain revoked and their counters
remain visible. New work permission requires a new grant.

Remote administrators pin the node using its verified software contact, then
use their own identity. `--contact` selects the verified node contact;
`--address` supplies direct UDP address hints (repeat or use commas).
Alternatively, `--control-socket` selects a local node. These options belong
to `hellas admin` and apply to its user and resource operations. The transport
proves possession of the pinned node key and the caller's registered key;
headers cannot supply either identity.

```sh
hellas admin --contact node.contact --address 192.0.2.10:9000 users list
```

Authorization is checked on every RPC and again when the writer applies a
command. Revocation therefore applies to existing connections. Public Work
methods never confer administrative authority. Platform-attested providers can
bind a software owner contact for their own producer/transport keys; node
administration through a provider contact currently requires a software-rooted
node contact. Grant/paid Work retain their own provider assurance policies.

For a lost Work client journal, `admin users update USER --grant GRANT
--new-generation` obtains a fresh channel generation without resetting counters;
export its Offer afterwards. `admin repair-resource POLICY` explicitly clears
an upstream accounting quarantine after the upstream issue has been corrected.

`hellas admin serve --socket PATH` serves the local application management RPC.
It uses the selected existing identity and the same machine-management service
as `hellas machines`; the machines commands and grantee-side `contact export`,
`contact import` and `offer import` retain their behavior. Embedded providers
record contact membership in the same permission journal when configuring grants.
