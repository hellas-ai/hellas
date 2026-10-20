# Node administration

A principal is a person or bot, identified by one P-256 passkey. A node holds
only machine keys: an iroh transport key for QUIC and a secp256k1 node key. The
CLI acts for the principal of a software passkey file given with `--passkey`
(32 raw bytes or 64 hex digits); `--identity` names the node's own keys.

Node administration requires a scoped application credential and explicit
operation grants. A credential is issued to a principal and held by a device: it
records the node key of the device that holds it. Each session proves the
credential's secret plus one of two keys over a digest bound to the live
connection:

- a **passkey session**: the subject's passkey asserts the digest;
- a **daily session**: the holder's node key signs it.

Step-up operations require a passkey session and refuse a daily one: issuing or
revoking credentials, issuing grants that name another principal or carry
administrative rights, and binding a provider. The same HostControl service
checks local TLS and remote QUIC calls. Socket ownership only limits admission.
It grants no application rights. The node writer rechecks current credentials and
grants before each effect.

Online commands take a private `--profile` file. With `--passkey` the session is a
passkey session; without it, the node key of `--identity` opens a daily session:

```sh
hellas-cli --identity node.identity admin --profile operator.json status
hellas-cli --identity node.identity admin --profile operator.json set-capacity --expected-revision 1 --max-in-flight 4 --limits machine-limits.json
hellas-cli --identity node.identity --passkey operator.passkey admin --profile operator.json grant change.json
hellas-cli --identity node.identity --passkey operator.passkey admin --profile operator.json issue-credential --scope friend-scope.json --holder friend-holder.json --credential-out friend.credential
hellas-cli --identity node.identity --passkey operator.passkey admin --profile operator.json revoke-credential --credential-id ID --expected-revision 1
hellas-cli --identity node.identity --passkey operator.passkey admin --profile operator.json bind-provider --enrollment provider.enrollment
hellas-cli --identity node.identity admin --profile operator.json work allowance.json
hellas-cli --identity node.identity admin --profile operator.json work export.json --offer-out friend.offer
hellas-cli --identity laptop.identity admin --profile remote.json --node node.enrollment --address 192.0.2.10:9000 status
```

`status` requires `host.status` on this authority's host resource. `set-capacity`
requires `work.capacity.configure` on its machine resource and the current machine
revision returned by status. `--limits` supplies the complete budget configuration,
for example `[{"meter":"Requests","window":"Day","amount":100}]`; an explicit `[]`
removes budget limits. Changes preserve counters, reservations and outstanding work,
so removing and restoring a limit cannot reset usage. Revision zero initializes a
provider whose machine has not been configured. `status` includes the current limits.
`grant` accepts the
Auth crate's `GrantCommand` JSON, including its explicit authorization grant and
any required revision. Grant issuance and credential scope both bound the action;
there is no blanket admin boolean. Possessing a passkey alone is insufficient.
Each command prints its record; the record's `caller.before` revision plus one is
the new revision of the grant it changed, and revisions are never reused. Only node grants issue or revise grants; delegated rights cascade with their
parent instead. An administrator cannot assign itself administrative rights, and its
own execution grants cannot outlive its authorization. The bootstrap grant changes
only through offline recovery. Revoked and expired grants are reclaimed when the
table is full.

`issue-credential` takes an Auth `GrantSpec` scope, bounded by the issuer's explicit
credential-issuance ceiling, and a `--holder` file: the JSON `CredentialHolder` of
the device that will hold it. `hellas-cli --identity node.identity identity
show-holder` prints that device's holder, `{"Node":[1,[...]]}`, its node key with
the secp256k1 curve tag. Issuing creates no grant: the recipient also needs current
grants for the requested operations. The client prepares the credential using the
authenticated session generation and saves its secret in a new private file before
submitting the verifier and ID. The secret never crosses the issuance RPC. After
the node confirms the durable record, the CLI prints its ID, revision,
path, authority ID, subject key and subject fingerprint. Transfer that file securely
to the holding device; a session also requires the subject's passkey or that
device's node key. The holder `"Bearer"` issues a `gateway.invoke`-only credential
for local HTTP clients: its secret alone authenticates it, and it opens no session.
The server stores only the verifier.

`revoke-credential` requires the separate credential-revocation permission and the
credential's current revision (one for a newly issued credential). Revocation applies
to live sessions and survives restart. Rotate by issuing a replacement to the same
subject, installing it, and explicitly revoking the previous credential. This does
not change the subject or reset accounting. A lost reply can follow a durable issue;
do not retry issuance automatically. A refused request or lost reply leaves the
local file pending confirmation, not evidence of usable access. The error reports
its exact ID and path. Inspect that ID and compare its scope, holder and generation
with the intended credential before using it; no scope-matching guess is needed.
If private file publication fails, no issuance request is sent.

`bind-provider` requires `host.provider.bind` on the host resource. It binds the
provider enrollment of an authority bootstrapped without one, such as an embedded
host that initialized before its provider enrolled. The node verifies the canonical
enrollment offline: a software root signature, or an App Attest credential
registered against its own RP-ID hash and CDHash at the enrollment's validation
time. This is not requester trust; callers still pin the genesis and Apple policy
independently. The binding is journaled and survives restart and offline recovery.
Repeating it with the identical enrollment succeeds, so a lost reply can be retried.
Any other enrollment is refused with `FailedPrecondition` (`provider already bound`),
and a malformed or unverifiable one with `InvalidArgument`. There is no unbind. The
command prints the bound enrollment's content ID.

`work` accepts [WorkControlCommand](../crates/work/src/model/grant/admin.rs) JSON. It selects resources from
the daemon's validated catalogue and uses the profile's authorization grant.
These operations require distinct rights on this authority's Work machine resource:

`List`, `Inspect`, `InspectResource`, `InspectBudget` and `Catalogue` use
`work.allowance.read`. `Create` and `Revise` use
`work.allowance.configure`. The remaining Work commands use their corresponding
budget, resource, offer, generation or repair operation. The mounted operation
table below is checked against the implementation by the Work tests.

<!-- operations:start -->
| Required operation | Resource | Mounted service |
| --- | --- | --- |
| `host.status` | Host | Host |
| `host.provider.configure` | Host | Host |
| `host.provider.bind` | Host | Host |
| `host.gateway.configure` | Host | Host |
| `host.gateway.access` | Host | Host |
| `gateway.invoke` | Host | Host |
| `work.capacity.configure` | Work machine | Machine or provider |
| `work.allowance.read` | Work machine | Provider |
| `work.allowance.configure` | Work machine | Provider |
| `work.budget.configure` | Work machine | Provider |
| `work.offer.export` | Work machine | Provider |
| `work.generation.reset` | Work machine | Provider |
| `work.resource.configure` | Work machine | Provider |
| `work.resource.repair` | Work machine | Provider |
| `work.execute` | Selected allowance | Provider |
<!-- operations:end -->

Configure machine capacity first, then explicit account, pool and subject budgets
with `ConfigureBudget`. Its [BudgetDef](../crates/work/src/model/grant/budget.rs)
names a node, its parent, the new revision, limits and maximum concurrent jobs.
An account is an Auth resource ID and has the machine as parent. A pool has a stable
16-byte ID and an account parent. A subject node is the pair `(pool, principal)`;
its parent is that pool or another subject in the same pool. At most eight subject
levels are permitted. Parentage is immutable, and revisions start at one and increase
by exactly one. Configuration returns the changed node and revision; `InspectBudget`
requires the read permission and returns the current definition and accounting.

Register each resource with `{"ConfigureResource":{"policy":"name"}}` after configuring
its account budget. The command selects a validated policy from the host's resource
file and commits it to the catalogue; startup does not register it. Every policy has
an explicit `resource` ID, `account` ID and positive `revision`. Both IDs use Auth's
32-byte ResourceId. A resource's account is immutable; policy revisions increase by
exactly one. `Catalogue` returns the durable configuration through checked inspection.
Configuration returns only the changed resource ID and revision.

Each Fetch policy carries a required `contract` descriptor alongside its exact
`allowed_environment` manifest ID. The descriptor selects a compiled request/result
schema and commits the adapter, driver and egress terms. For example, the current
reseller Responses contract is:

```json
{"adaptor":"openai-responses-0.0.3","schema":"stateless_responses_v1","driver":"openai-responses-driver-0.0.2","egress":{"fixed_https":"https://api.openai.com/v1/responses"}}
```

Its manifest ID is `9f9737112657bdad2a126ed2926f01f1c59ab36399750fde43a8ae4c1ab2cc65`.
The supported schema names are `http_v1`, `stateless_responses_v1` and
`responses_items_v1`; unsupported schemas deny. The HTTP contract uses
`"egress":"request_https"` for the signed request's URL/TLS terms. A contract hash
never substitutes for independently configured provider/build trust. This Responses
driver uses bundled public roots and disables proxy inheritance, redirects and automatic
HTTP retries. Adapter 0.0.3 also removes input-derived error diagnostics. Its new
manifest requires explicit caller approval and a new resource revision; approvals of
older adapter or driver versions do not carry forward.

The current Codex contract uses adapter `codex-responses-0.0.2`, schema
`responses_items_v1`, driver `codex-responses-driver-0.0.2` and fixed HTTPS egress
`https://chatgpt.com/backend-api/codex/responses`. Its manifest ID is
`a4e12aa2a03d6649a5f3864272c203baaa902c386327336a15c7058ba1f2dfa6`.
Its request and authentication clients share the same proxy/CA/redirect policy;
refresh errors discard upstream descriptions before logging or persistence. These
path protections do not establish signed-platform privacy or vendor retention policy.

`work prepare-fetch --contract FILE` reads this JSON descriptor and includes its
canonical bytes with the signed request. Provider policy and input must commit the
same descriptor. The gateway's `--responses-fetch-execution-environment` accepts the
exact manifest ID. Ordinary clients select descriptors from resource policy, without
linking the reseller implementation. Missing descriptors and old bundle shapes deny.

Every resource also requires a `pricing` block. For example, this fragment rates a
request at two USD micro-units plus three micro-units per four output tokens:

```json
{"pricing":{"revision":1,"rates":[{"meter":"Requests","usd_micros":2,"units":1},{"meter":"OutputTokens","usd_micros":3,"units":4}]}}
```

These are operator-defined Hellas rates, not a promise to match an upstream invoice.
Each rate has positive `units`; `usd_micros` is a nonnegative integer. Each component
rounds up once per job for both reservation and settlement. Unlisted usage meters cost
zero. `rates: []` explicitly declares free usage; `rates: null` declares an unpriced
resource, which cannot be selected by a grant whose budget path contains money limits.
Rates must name distinct supported usage meters; pricing `UsdMicros` itself is invalid.
Sealed Responses currently supports `Requests` and `OutputTokens`, not input rates.
A `UsdMicros` budget limit uses the ordinary Hour/Day/Week/Total windows.

Prices start at revision one. Changing or removing a rate table increments its revision
by exactly one along with the enclosing resource policy revision. An unrelated policy
change may retain the same pricing block. Revise allowances to select the new policy;
accepted running jobs retain their signed price revision. Unrepresentable maximum
charges are refused before admission. Unknown final usage or dispatched crash recovery
keeps the full money reserve; verified overruns charge actual usage and quarantine.
An unrepresentable verified overrun exhausts the money counter without wrapping or
refunding it. Counter growth, price changes and restart never reset prior spending.

`Create` and `Revise` select policies by name from the durable catalogue and name the
configured subject budget in their terms. Every selected resource must belong to that budget's pool/account hierarchy. Names select configuration; jobs sign the resource ID, exact policy and pricing
revisions as well as their Work input commitments. Changing a resource releases queued
jobs, ends active execution/delivery authority and discards cached bodies. Removing it
from an allowance has the same effect. Running work retains its original policy for
settlement; policy changes and renamed resources retain quarantine and usage. Revise
allowances explicitly before admitting work under a new resource revision.

The corresponding subject budget must already exist. Limits and concurrency belong to budgets, and
all allowances attached to that budget share them, regardless of the authenticated caller. Budget changes preserve used and
reserved amounts; lowering a cap can deny new jobs while accepted jobs retain their
settlement duties. Each job charges machine, account, pool and every subject ancestor
atomically. Budget administration and allowance administration are separate rights.

`Revise` supplies complete Work terms, including `enabled`; the budget attachment
is immutable. Set `enabled` false to pause new acceptance, queued dispatch and new
delivery requests. Already dispatched work and established delivery retain their Auth
checks and job deadlines. Auth owns identity, expiry and revocation; Work has no
separate revocation state. Revisions require the current allowance revision. Generation reset and
resource repair require their own expected versions, so retrying an old request
cannot silently reset another generation or clear newer faults. Mutations return
the changed versions; private usage is returned only by authorized inspection.
`Offers` with one explicit allowance ID can write `--offer-out` for `offer import`.
Offer export and import print the provider's enrollment content ID to stderr.

A contact is a person. `contact export --display-name NAME` signs a contact card
with `--passkey`: the principal's passkey public key and display name, with the
passkey's assertion over both. `contact import CARD --name ALIAS` verifies the card
and saves it under the importing principal; it prints the card's principal, display
name and fingerprint. The exporter sees the same fingerprint on stderr. A
fingerprint has 12 base32 characters in three groups, derived from a hash of the
complete curve-tagged key. Compare it with the other person over an independent
channel before granting the imported principal. The credential subject fingerprint
matches that subject's contact card. These displays do not approve provider trust;
the full keys remain authoritative.

Work terms confer no authorization, and Work administration cannot issue Auth grants
or credentials without their separate permissions. Allowances require explicit
policies and an existing subject budget. Auth may authorize other callers to use that
sponsored budget. Standing returns only that budget's counters and the minimum
remaining allowance across ancestors; ancestor usage requires checked inspection.
Offers have no recipient and confer no permission. A channel serves one principal on
one device: it is keyed by the principal and the node key its credential is bound
to, so two devices of one principal never share a channel or its job nonces. Each
device signs its jobs with its node key. Channels are created on first accepted work;
standing and delivery require the same principal and device, including after Auth
grant revisions. A bearer credential has no channel. Work audience IDs are the same
validated principals used by Auth. Provider trust still pins the provider enrollment.
CLI contact, offer and access state is stored per principal, under
`p256-<compressed key>` in the grant data directory.

The profile has these fields. Unknown fields are refused.

| Field | Value |
| --- | --- |
| `authority` | This node's provisioned `AuthorityId`, serialized as a 32-byte JSON array. |
| `authorization` | The selected `GrantId`, serialized as a 16-byte JSON array. |
| `credential` | Path to the private application credential file. |
| `local` | For local connections, an object with `certificate` (DER certificate path) and `server_name` (certificate DNS name). Omit for remote-only profiles. |

Paths in a profile resolve relative to that profile. A credential file contains its
16-byte ID followed by its 32-byte secret. Profiles, credentials, certificates and
private keys must be regular private files. Files are bounded to 64 KiB; credentials
must be exactly 48 bytes. Provision trust independently: a local profile pins the
server certificate, and a remote command pins the node's transport key with `--node`,
that node's enrollment (`identity export-enrollment`), verified out of band. The
expected authority always comes from the profile. The client never learns trust or
permission from the server's authentication challenge.

The default local path is the `--passkey` principal's `control.sock`; use
`--control-socket` when administering a different local daemon or without a passkey.
The directory must be private (0700 on Unix); the listener creates a 0600 socket and
checks peer ownership. Both carriers require the application credential and a
passkey or node-key proof bound to the live connection. Revocation applies to an
existing authenticated connection too.

Remote control is off by default. To enable it, set `remote_control_peers` in the
grant configuration to the operator-approved client endpoint keys (at most 128
distinct iroh endpoint IDs). The client uses its node's transport key
(`identity show-node-id`); compare it out of band. Admission is checked during the
QUIC handshake and again before application authentication. An admitted endpoint
still needs its application credential, session proof and operation grant. Unlisted
peers cannot enroll through this listener. Use local control when the CLI and the
running node share the same transport identity.

Local and remote control each have 16 connection slots. Authentication must finish
within five seconds; authenticated sessions close after 30 seconds without another
request. Filling the remote pool does not prevent local administration.

The shared node and grant Work services emit `hellas_authority_audit` events through
the host's tracing sink. Keep that target at INFO to retain allowed private reads and
authority checks as well as WARN denials, unavailable decisions and cancelled requests.
Configure log storage/rotation for the retention you need. These events do not append
to the authority journal; successful mutations retain their atomic journal records.
Events contain fixed decision codes and IDs, never request content or credential
secrets. `credential_claimed` is an unverified locator; only `verified=true` supplies
an actor validated by this node. A revoked credential or wrong session binding cannot
attribute a request to that actor.

## Access bundles

An access bundle shares allowances with one contact device: one signed offer per
allowance, the authority ID, the contact's Auth grant ID, the credential subject,
the node key of the contact's device, the credential ID and secret, the expiry and
an optional provider label of at most 64 bytes. It contains no provider trust; the
contact still approves a trust policy with `hellas-cli trust` before running work.

```sh
hellas-cli --identity node.identity --passkey operator.passkey admin --profile operator.json export-bundle --allowance ALLOWANCE_A --allowance ALLOWANCE_B --grant-id GRANT --credential-scope friend-scope.json --holder friend-holder.json --label "Alice's node" --out friend.access
hellas-cli --identity friend.identity --passkey friend.passkey offer import-bundle friend.access --name alice
```

`export-bundle` takes `--allowance` once per shared allowance, at most 16. The
credential scope must grant `work.execute` on each of them; `--grant-id` names the
contact's existing grant with those permissions, not an allowance ID. It exports
each allowance's offer (`work.offer.export`), then prepares one credential bounded
by the scope, held by the contact device named by `--holder`. It saves the bundle
before submitting the verifier, exactly as `issue-credential` does. The bundle is canonical DAG-CBOR tagged
`hellas.access-bundle.v2`. Its subject and holder carry their curve tags. It is
written as a new private file that never replaces an existing one. A failed or
unconfirmed issuance leaves that bundle pending; inspect its reported credential
ID before sharing it. The secret is never printed.

`offer import-bundle` accepts the received bundle file as it is; delete it after
importing, since it holds the credential. It refuses a bundle whose subject is not
the `--passkey` principal or whose holder is not this device's node key, and verifies
each offer's provider signature. It saves each offer as `NAME.POLICY`, after the
offer's first policy, as `offer import` does, and installs one remote-only Work
profile (`profile.json` and a private `credential`) under `accesses/NAME` in the
principal's data directory, refusing a non-empty directory. It prints each saved
offer name with its grant ID, and the profile path; use that path as
`--work-profile` together with `--offer NAME.POLICY`.

## Explicit offline initialization and recovery

Stop the daemon before initializing or recovering its exclusively locked journal.
Prepare `administrator.json` and `application-scope.json` as Auth `GrantSpec`
values: the authority, the administrator principal as subject, exact
operation/resource pairs, validity, delegation depth and issuance ceiling. The
application scope cannot exceed the administrator's rights. `--holder` names the
device that will hold the initial credential. The administrator's `--passkey` must
be given: it asserts the ownership digest, which commits to the root grant or
expected revision, both specs and the holder, so nobody can initialize or recover an
authority administered by someone else's passkey. Initialization requires an empty
journal and a new output file; ordinary daemon startup never creates authority or
issues credentials.

Verify system UTC before starting the node. While running, the node refuses authority
times more than one minute ahead of startup UTC plus monotonic elapsed time, so a
forward clock spike cannot become a permanent journal high-water mark. Correct a bad
clock; after a legitimate large adjustment or long suspend, verify UTC and restart.
Work inspection and standing queries calculate current windows without writing clock
ticks. Existing spending and reservations are preserved.

```sh
hellas-cli --identity node.identity --passkey operator.passkey admin bootstrap --journal state/provider --root-grant 01010101010101010101010101010101 --administrator administrator.json --credential-scope application-scope.json --holder holder.json --credential-out operator.credential
hellas-cli --identity node.identity --passkey operator.passkey admin recover --journal state/provider --expected-revision REVISION --administrator administrator.json --credential-scope application-scope.json --holder holder.json --credential-out recovered.credential
```

Bootstrap can also issue a bearer for an HTTP gateway: `--bearer-scope` names its
`gateway.invoke` GrantSpec and `--bearer-out` a new private file. The
administrator's passkey session on the new authority issues it, after the initial
credential, as a separate credential.

The credential output is private and published without overwriting an existing file,
only after the authority commit is durable. If publication fails, the command reports
that the authority committed; inspect/recover the state explicitly before retrying.
Recovery preserves accounting and advances the generation, invalidating prior
credentials and sessions. The CLI prints the credential ID, file path, authority and
subject fingerprint, never the secret. Build the caller profile using the initialized
authority and grant values.

For local service startup, independently provision `control.cert.der` and its
PKCS#8 `control.key.der` under the node state root. The grant configuration can
select absolute `control_certificate` and `control_private_key` paths alongside
`journal_root` and `control_socket`. The daemon validates TLS identity before
opening the provider and binding listeners. Startup does not generate trust files.
Resource configuration also cannot issue allowances or set budgets. After explicit
initialization, start the daemon with `--grant-config` to mount its listeners and
available resources. Use `set-capacity --expected-revision 0` to configure the first
machine budget, configure account/pool/subject budgets, register each resource, then
use `work` with `Create` to assign an allowance. Resource files contain `max_job_millis`, `resources` and optional listener/state paths;
`machine_limits` and `max_in_flight` are not resource-file fields. Each resource also
requires its explicit IDs and revision. Editing this file or restarting cannot change
the durable catalogue or revise, revoke or renew an existing allowance. Such changes
require their corresponding checked administration command.

The SDK Fetch provider follows the same sequence: initialize offline, start, then
use its checked administration service. Its options describe available policies and
maximum job duration; there is no contact list that silently grants execution.

Embedding hosts now use `hellas_reseller::start_openai_provider` for the OpenAI
Responses adapter. Its explicit account/resource configuration uses SDK's same
checked service; no resources or allowances are created at startup. The core CLI's
`openai-responses` serving destination is removed. Ordinary Fetch clients and gateways
continue to consume the protocol independently of this hosting library.

OpenAI grant resources require a `responses` block, also supplied by the reseller host
options. For example, this resource fragment permits text requests for one exact model:

```json
{"responses":{"model":"configured-model","max_output_tokens":1024,"settings":{}}}
```

Each signed request must include that model and a positive integer `max_output_tokens`
no larger than the ceiling. Missing or excessive caps are rejected before reservation;
they are never silently inserted or reduced. Settings default to text output with
sampling parameters, tools, parallel calls and automatic truncation disabled. Enable
explicit fields through `temperature`, `top_p`, `tools`, `parallel_tool_calls` and
`automatic_truncation`. `output_formats` selects `text`, `json_object` or `json_schema`.
Nonempty `reasoning_efforts` and `reasoning_summaries` sets require an explicit supported
choice in every request; empty sets forbid explicit values. Configure revised limits
through the normal resource revision command, then revise the allowance's selection.
Work reserves each signed `max_output_tokens` against the output-token meter at every
shared budget ancestor. After complete transcript verification, it charges the final
output count and releases the unused reservation. Missing or invalid usage keeps the
full bound, as does crash recovery of dispatched work. A verified output overrun is
charged in full and immediately quarantines that resource; three consecutive unknown
usage results also quarantine it. Spending and quarantine survive restart and resource
policy revisions. The OpenAI `0.0.2` contract preserves verified overruns for settlement;
the old contract identity is rejected. Input-token budgets remain unsupported for
these resources until a conservative input bound exists.

Local evaluation uses `gateway --local --local-grant ID` to select an already
configured allowance with a `local` policy. It never creates an owner grant or
changes the selected allowance's policy while opening the gateway.

Provisioning uses the client-side `machines --provider NAME --credential-source FILE
--provider-config FILE create --spec FILE` command, with matching `list` and
`destroy ID` commands. The provider settings and credential-source formats are
shown in [machine provider configuration](machine-provider-config.md). Provisioning
passes no owner credential or transport secret to the provider.

The ordinary node image runs `serve --await-owner STATE_DIRECTORY`. An unowned
node prints a pairing document containing its public transport pin, direct
addresses, expiry and a fresh random secret. Obtain that document through the
provider's authenticated console/output and keep it private. Before ownership,
only the bounded one-shot bootstrap exchange is available. Eight refused attempts
invalidate the invitation; restarting generates a different secret.

The owner uses `admin bootstrap-remote --invitation FILE --root-grant ID
--administrator FILE --credential-scope FILE --profile-out DIRECTORY` with their
passkey. The CLI saves the prepared credential and pinned remote profile before
sending the owner approval. A lost acknowledgement does not require issuing a
second credential: use the saved profile to inspect the node. The authority store
is published atomically and refuses another bootstrap after success.

The normal host keeps that endpoint and authority alive across provider restarts.
Use the saved `admin --profile DIRECTORY/profile.json` for status, capacity, authority and Work
administration. `admin configure-provider FILE` applies a typed, revision-checked
upstream mutation. Adding a new key requires a daily application session; replacing
or removing a key and changing endpoints require a passkey session. Status exposes
endpoint metadata and key names, never key material. Failed configuration/startup
restores the prior configuration and keys and reports the provider as failed;
`admin set-provider-state --enabled true` explicitly starts it again.

Share execution through a signed allowance offer, import it, then select
`gateway --offer ALIAS` with the caller's approved trust policy and Work profile.


## Embedded host lifecycle

`sdk::node_control::host::HostHandle::start` owns an existing `NodeCoordinator`,
an authenticated local control listener and a bounded lifecycle supervisor. Provider startup is selected with `start_provider`; the gateway begins stopped. Supply `OpenAiProviderOptions::into_factory()` from the
core reseller crate for Gate's vendor relay, preserving its injected App Attest
prover and enrollment. Other providers prepare the shared SDK provider options
and select `on_host(control)` before startup. That attaches the existing writer;
it cannot open a second journal. Responses gateway options must use the same
writer and the SDK `responses::start_fetch` composition.

`SetProviderState` and `SetGatewayState` carry an `authorization` grant and require
`host.provider.configure` and `host.gateway.configure`, respectively. Their
bounded enqueue is checked under the authority writer. The host owns completion
if the requesting RPC disappears; revocation does not undo an already accepted
command. Replies recheck current rights. A full eight-command queue refuses
further commands, and service errors require an explicit subsequent request.

A host can start on an authority with no bound provider. It serves control,
grants and credentials; its provider status reads `provider is not bound`, and
`SetProviderState` refuses to start the provider with `FailedPrecondition` until
`bind-provider` succeeds. No restart is needed after binding.

`GetHostStatus` reports the bound provider's identity, provider/gateway states and
the running provider endpoint. Stop drains accepted Work; local control and its writer
remain alive. Work administration remains available after the provider stops.
Full host shutdown joins its local listener and both services.
`GetGatewayAccess` separately requires `host.gateway.access`; it returns an address
and the current scoped HTTP Auth credential only while the gateway is running.
Remote control is disabled by default. Explicit credential-gated ingress permits
application authentication from any transport key; a configured endpoint allowlist
restricts it further. `--await-owner` opts into credential-gated ingress.
A standalone `NodeControl` without a host supervisor leaves lifecycle operations
unmounted; constructing the composed host supplies their implementation.


Caller trust for paid and grant execution is configured separately with `hellas-cli trust`.
`approve` requires a reviewed policy file, expected revision (zero for creation) and
reason; `show` reports current pins and latest approval. Paid requests and grant gateways (`--offer` or `--local`) select
`--trust-store` and `--trust-policy`; imported offers cannot replace the approved pins.
See [paid gateway trust configuration](paid-gateway.md) for the file format and
replacement procedure. This does not grant provider administration rights.

Approved manifest IDs remain attached to the client session. Refreshed standing may
change a resource's current policy, but every new job must still use an approved
execution manifest before its proposal or payload is sent. Review and approve a new
contract explicitly, then restart the gateway to use the updated caller policy.
Nix gateway services use `trustStore`, `trustPolicy`, `workProfile` and the
principal's `passkey` file, plus `offer` or `local`/`localGrant`.
Provision these private files for the service user before startup; Nix declarations
do not approve trust or create grants.

## HTTP gateway authority

A standalone gateway requires `--gateway-profile FILE`, a private JSON file with
`journal`, `authority`, `authorization`, and `credential` fields. `journal` names
an explicitly bootstrapped local NodeStore; `authority` and `authorization` are its
Auth AuthorityId and selected GrantId in their usual JSON forms. `credential` names
the private 48-byte bearer credential file written by `issue-credential --holder`
with the `"Bearer"` holder, or by bootstrap's `--bearer-out`.
An optional `control` object with `socket`, `certificate` and `private_key` serves
local HostControl on that writer. Credential issuance and revocation then work while
the gateway runs, using the same `admin --profile ... --control-socket` commands
and checks as a daemon. Omit it to serve no administration.
Relative paths are resolved from the profile directory. The journal has one writer;
an embedded gateway receives its host's existing NodeCoordinator instead of opening
that journal again. Missing, mismatched or corrupt state fails startup.

Provision a grant for `gateway.invoke` on the authority's host resource. Issue a
bearer credential scoped only to that permission, with no issuance ceiling or
delegation. The selected grant must name the same subject and remain current.
Device-held and administrator credentials are rejected as HTTP credentials; the
bootstrap credential is never the bearer. The profile's `authorization` names the grant that
authorizes the gateway's own bearer. An HTTP request may present a bearer that grant
authorizes, or one whose subject holds its own current grant of `gateway.invoke`
alone on this authority, so each principal using the gateway can have its own grant
and credential.
Existing offline bootstrap and checked `issue-credential` commands own provisioning;
starting a listener does not create authority or credentials.

Clients send the credential's 16-byte ID followed by its 32-byte secret, encoded as
96 lowercase hex characters, in one `Authorization: Bearer` header. The gateway
shows it on the controlling terminal and supplies it to explicitly wrapped children.
It strips the local authorization header before forwarding. Query parameters,
cookies, duplicate authorization headers and old 64-character static tokens are
refused. Every new HTTP request authenticates against current Auth state; revoking
its credential or grant, or reaching expiry, refuses subsequent requests. Accepted
Work keeps its separate application authority and recovery/settlement obligations.

### Inspecting and reconciling administration

`admin inspect QUERY.json` reads authority metadata through the selected profile.
Queries are `{"Grants":{"after":null}}`, `{"Credentials":{"after":null}}`,
`{"Grant":{"id":ID}}`, or `{"Credential":{"id":ID}}`. IDs use the same JSON
representation as grant commands (16-byte arrays). A page contains at most eight
records; pass its `next` ID as `after` for the next page. Stop when `next` is null.
Every reply includes the authority revision, generation and root grant. If the
revision changes between pages, restart enumeration before making decisions from
that combined view.

Both the selected live grant and the credential must carry `grant.administer`
and an issuance ceiling covering each returned record. Enumeration omits records
outside either ceiling; singular queries do not distinguish missing from hidden
records. Revoked and expired records remain inspectable until normal capacity
reclamation. Credential metadata contains its ID, scope, holder, generation,
revision and revocation flag, never its secret or verifier.

After a lost grant update reply, compare the inspected grant spec with the intended
change as well as its revision before deciding to retry. After a lost credential
issuance reply, use the singular `Credential` query with the retained 16-byte ID
and compare the returned scope, holder, generation and revocation state with the
intended issuance. The client retains the exact ID and secret before submission,
so identical concurrent issuances remain distinguishable.

With the daemon stopped, `admin inspect-offline --journal PATH QUERY.json` reads
these same bounded views without an identity, credential or passkey. It takes the
writer's exclusive identity lock and replays a private temporary copy of the database
and any crash-left WAL inside the data directory. The temporary copy is removed
after inspection; the source database and sidecars remain unchanged. Inspection
does not create authority state, run startup recovery, change clocks or migrate the
database. Use
its revision for `admin recover --expected-revision`, including after a recovery
whose reply or credential file was lost. Successful bootstrap and recovery print
the committed revision; credential publication failures report it too.

An authorized stale revision returns `FailedPrecondition`, requiring inspection
before retrying. Invalid authority records and invalid Work limits return
`InvalidArgument`; authorization failures remain non-disclosing.
