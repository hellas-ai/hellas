# Node administration

Node administration requires a portable identity, a scoped application credential,
and explicit operation grants. The same HostControl service checks local TLS and
remote QUIC calls. Socket ownership only limits admission. It grants no application
rights. The node writer rechecks current credentials and grants before each effect.

Online commands take a private `--profile` file:

```sh
hellas-cli --identity operator.identity admin --profile operator.json status
hellas-cli --identity operator.identity admin --profile operator.json set-capacity --expected-revision 1 --max-in-flight 4 --limits machine-limits.json
hellas-cli --identity operator.identity admin --profile operator.json grant change.json
hellas-cli --identity operator.identity admin --profile operator.json issue-credential --scope friend-scope.json --credential-out friend.credential
hellas-cli --identity operator.identity admin --profile operator.json revoke-credential --credential-id ID --expected-revision 1
hellas-cli --identity operator.identity admin --profile operator.json work allowance.json
hellas-cli --identity operator.identity admin --profile operator.json work export.json --offer-out friend.offer
hellas-cli --identity operator.identity admin --profile remote.json --contact node.contact --address 192.0.2.10:9000 status
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
there is no blanket admin boolean. Identity possession alone is insufficient.
Each command prints its record; the record's `caller.before` revision plus one is
the new revision of the grant it changed, and revisions are never reused. Only node grants issue or revise grants; delegated rights cascade with their
parent instead. An administrator cannot assign itself administrative rights, and its
own execution grants cannot outlive its authorization. The bootstrap grant changes
only through offline recovery. Revoked and expired grants are reclaimed when the
table is full.

`issue-credential` takes an Auth `GrantSpec` scope, bounded by the issuer's explicit
credential-issuance ceiling. It creates no grant: the recipient also needs current
grants for the requested operations. The node commits the verifier and audit before
returning the secret once over the authenticated connection. The CLI writes a private
credential file without overwriting an existing file and prints its ID, revision,
path, authority ID, subject key and subject fingerprint. Transfer that file securely
to its subject; RPC use also requires the subject's identity key. Only a credential
issued to its issuer's own subject
authenticates by its secret alone. The server does not retain a recoverable copy of the secret.

`revoke-credential` requires the separate credential-revocation permission and the
credential's current revision (one for a newly issued credential). Revocation applies
to live sessions and survives restart. Rotate by issuing a replacement to the same
subject, installing it, and explicitly revoking the previous credential. This does
not change the subject or reset accounting. A lost reply can follow a durable issue;
do not retry issuance automatically. If local file publication fails after receipt,
the CLI reports the issued ID so it can be revoked before retrying.

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
16-byte ID and an account parent. A subject node is the pair `(pool, identity key)`;
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
Contact export and import print the identity fingerprint to stderr; offer export and
import print the provider fingerprint. Each fingerprint has 12 base32
characters in three groups, derived from a hash of the complete identity key. Compare
them with the other person over an independent channel before using the imported
record. The credential subject fingerprint matches that subject's contact fingerprint.
These displays do not approve provider trust; the full keys remain authoritative.
Work terms confer no authorization, and Work administration
cannot issue Auth grants or credentials without their separate permissions.
Allowances require explicit policies and an existing subject budget. Auth may authorize
other callers to use that sponsored budget. Standing returns only that budget's counters
and the minimum remaining allowance across ancestors; ancestor usage requires checked
inspection. Offers have no recipient and confer no permission. Channels are created on
first accepted work and bind the authenticated actor; standing and delivery require the
same actor, including after Auth grant revisions.
Work audience IDs are the same validated identity keys used
by Auth. Provider trust still pins the provider enrollment. CLI contact/offer state
is stored under the hex-encoded identity key, and old enrollment-hash directories
are not imported or migrated. Application sessions and configured shared budgets are
implemented, including durable resource/account binding, signed Responses model/settings
limits and operator-rated money budgets. Other schema profiles and vendor-derived
percentage allowances remain part of the execution cutover described in the plan.

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
server certificate, and a remote command uses a verified node contact to pin its
transport key. The expected authority always comes from the profile. The client
never learns trust or permission from the server's authentication challenge.

The default local path is this identity's `control.sock`; use `--control-socket`
when administering a different local daemon. The directory must be private (0700
on Unix); the listener creates a 0600 socket and checks peer ownership. Both
carriers require the application credential and an identity signature bound to the
live connection. Revocation applies to an existing authenticated connection too.

Remote control is off by default. To enable it, set `remote_control_peers` in the
grant configuration to the operator-approved client endpoint keys (at most 128
distinct iroh endpoint IDs). The client uses its existing identity's transport key;
compare that key with its contact record out of band. Admission is checked during
the QUIC handshake and again before application authentication. An admitted endpoint
still needs its application credential, identity signature and operation grant.
Unlisted peers cannot enroll through this listener. Use local control when the CLI
and the running node share the same transport identity.

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

## Explicit offline initialization and recovery

Stop the daemon before initializing or recovering its exclusively locked journal.
Prepare `administrator.json` and `application-scope.json` as Auth `GrantSpec`
values: the authority, identity subject, exact operation/resource pairs, validity,
delegation depth and issuance ceiling. The application scope cannot exceed the
administrator's rights. Initialization requires an empty journal and a new output
file; ordinary daemon startup never creates authority or issues credentials.

Verify system UTC before starting the node. While running, the node refuses authority
times more than one minute ahead of startup UTC plus monotonic elapsed time, so a
forward clock spike cannot become a permanent journal high-water mark. Correct a bad
clock; after a legitimate large adjustment or long suspend, verify UTC and restart.
Work inspection and standing queries calculate current windows without writing clock
ticks. Existing spending and reservations are preserved.

```sh
hellas-cli --identity node.identity admin bootstrap --journal state/provider --root-grant 01010101010101010101010101010101 --administrator administrator.json --credential-scope application-scope.json --credential-out operator.credential
hellas-cli --identity node.identity admin recover --journal state/provider --expected-revision REVISION --administrator administrator.json --credential-scope application-scope.json --credential-out recovered.credential
```

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

The core CLI's `openai-responses` serving destination is removed.

OpenAI grant resources require a `responses` block. For example, this resource
fragment permits text requests for one exact model:

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

Cloud readiness uses `control-profile.json` in its private configuration directory
through this same CLI path; that profile must also be explicitly provisioned.

The daemon serves status, machine capacity, authority grants, credential
issuance/revocation and Work allowance administration. Composed SDK hosts also
serve provider/gateway lifecycle and gateway credential retrieval.


## Embedded host lifecycle

`sdk::node_control::host::HostHandle::start` owns an existing `NodeCoordinator`,
an authenticated local control listener and a bounded lifecycle supervisor. Both
services begin stopped. Providers prepare the shared SDK provider options
and select `on_host(control)` before startup. That attaches the existing writer;
it cannot open a second journal. Responses gateway options must use the same
writer and the SDK `responses::start_fetch` composition.

`SetProviderState` and `SetGatewayState` carry an `authorization` grant and require
`host.provider.configure` and `host.gateway.configure`, respectively. Their
bounded enqueue is checked under the authority writer. The host owns completion
if the requesting RPC disappears; revocation does not undo an already accepted
command. Replies recheck current rights. A full eight-command queue refuses
further commands, and service errors require an explicit subsequent request.

`GetHostStatus` reports the configured identity, provider/gateway states and the
running provider endpoint. Stop drains accepted Work; local control and its writer
remain alive. Work administration remains available after the provider stops.
Full host shutdown joins its local listener and both services.
`GetGatewayAccess` separately requires `host.gateway.access`; it returns an address
and the current scoped HTTP Auth credential only while the gateway is running.
Remote control retains its explicit endpoint allowlist in addition to these rights.
A standalone `NodeControl` without a host supervisor leaves lifecycle operations
unmounted; constructing the composed host supplies their implementation.


Caller trust for paid and grant execution is configured separately with `hellas-cli trust`.
`approve` requires a reviewed policy file, expected revision (zero for creation) and
reason; `show` reports current pins and latest approval. Paid requests and grant gateways (`--offer`, `--machine` or `--local`) select
`--trust-store` and `--trust-policy`; imported offers cannot replace the approved pins.
See [paid gateway trust configuration](paid-gateway.md) for the file format and
replacement procedure. This does not grant provider administration rights.

Approved manifest IDs remain attached to the client session. Refreshed standing may
change a resource's current policy, but every new job must still use an approved
execution manifest before its proposal or payload is sent. Review and approve a new
contract explicitly, then restart the gateway to use the updated caller policy.
Nix gateway services use `trustStore`, `trustPolicy` and `workProfile`, plus `offer`,
`machine` or `local`/`localGrant`. Provision these private files for the service user
before startup; Nix declarations do not approve trust or create grants.

## HTTP gateway authority

A standalone gateway requires `--gateway-profile FILE`, a private JSON file with
`journal`, `authority`, `authorization`, and `credential` fields. `journal` names
an explicitly bootstrapped local NodeStore; `authority` and `authorization` are its
Auth AuthorityId and selected GrantId in their usual JSON forms. `credential` names
the private 48-byte credential file written by `issue-credential` or bootstrap.
Relative paths are resolved from the profile directory. The journal has one writer;
an embedded gateway receives its host's existing NodeCoordinator instead of opening
that journal again. Missing, mismatched or corrupt state fails startup.

Provision a grant for `gateway.invoke` on the authority's host resource. Issue a
credential to the issuer's own subject, scoped only to that permission, with no
issuance ceiling or delegation. The selected grant must name the same subject and
remain current. Administrator credentials are rejected as HTTP credentials.
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
