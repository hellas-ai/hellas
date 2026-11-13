# Node administration

A principal is a person or bot, identified by one P-256 key. A node holds
only machine keys: an iroh transport key for QUIC and a secp256k1 node key.
`--home` (default `HELLAS_HOME` or `~/.hellas`) selects the directory holding
the node's keys and state (`<home>/identity`). The CLI acts for the home's
principal key, `<home>/principal.key`, a private software key created on first
use by every command that acts for a principal. `--passkey FILE` (32 raw bytes
or 64 hex digits) points at a key held outside the home instead, as services do
with secrets under `/run`.

Start the daemon with `hellas serve`, pair its invite, then configure packages
with `hellas route add PATH`. Fetch upstreams use `hellas backend add NAME URL
--key-file FILE` and `hellas route add MODEL@NAME`. The verbs build one complete
document and send one atomic `Configure`; `hellas routes` reads `Watch`.
Each configured package or upstream publishes bounded resources that allowances
can select. A program executes with the provider user's permissions; process
isolation contains failures but is not a sandbox. Sharing a resource that admits
arbitrary Compute requires `share --knowingly-unsafe`.

A node with no owner prints one `hellas-invite:` line and
waits. `hellas pair INVITE [--name NAME]` claims it with the home principal key.
The pairing owner receives one year of full node administration, and the
profile, kept at `<home>/nodes/NAME/profile.json` (`NAME` defaults to
`default`), retains the node pin from the authenticated invite. `admin` and
`share` use the only paired node unless `--profile` names another; an explicit
different `--node` is rejected. See the
[sharing section](../README.md#2-share-your-gpu).

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

Online commands take a private `--profile` file, by default the only paired
node's. With a principal key (the home's `principal.key`, or `--passkey`) the
session is a passkey session; without one, the node key in `<home>/identity`
opens a daily session:

```sh
hellas admin status
hellas admin grant change.json
hellas admin issue-credential --scope recipient-scope.json --holder recipient-holder.json --credential-out recipient.credential
hellas admin revoke-credential --credential-id ID --expected-revision 1
hellas admin bind-provider --enrollment provider.enrollment
hellas admin work allowance.json
hellas admin work export.json --offer-out recipient.offer
hellas admin --profile remote.json --node node.enrollment --address 192.0.2.10:9000 status
```

`status` requires `host.status` on this authority's host resource. It includes the
machine budget the node's grant configuration applies (see below).
`work` also accepts `SetPaidPolicy { expected_revision, policy }` to set the
provider's price, execution limits and automatic-offer bounds. It requires the
authority owner's passkey session and `work.paid.configure` on the machine
resource. The node generates the policy salt and retains the original terms
with each signed offer; changing the standing policy does not alter open channels.
Use `admin set-paid-policy --terms FILE --expected-revision REVISION` to approve
paid terms; see the [paid work guide](paid-gateway.md). The provider runs each Catena job in a
separate worker process. That isolation is crash/timeout containment, not a
sandbox, and there is no memory metering. Requesters pay only for a result
signed by this provider that matches their job; Hellas does not re-run it.

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
the device that will hold it, `{"Node":[1,[...]]}`: that device's node key with
the secp256k1 curve tag. (`hellas share` takes the holder from the contact string
instead.) Issuing creates no grant: the recipient also needs current
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

`work` accepts [WorkControlCommand](../crates/authority/src/model/grant/admin.rs) JSON. It selects resources from
the authority's current resource policies and uses the profile's authorization grant.
These operations require distinct rights on this authority's Work machine resource:

`List`, `Inspect`, `InspectResource`, `InspectBudget` and `Catalogue` use
`work.allowance.read`. `Create` and `Revise` use
`work.allowance.configure`. The remaining Work commands use their corresponding
budget, resource, offer, generation or repair operation. The mounted operation
table below is checked against the implementation by the Work tests.

<!-- operations:start -->
| Required operation | Resource | Mounted service |
| --- | --- | --- |
| `content.read` | Exact content pin; Host for owner | Host |
| `content.upload` | Host | Host |
| `content.acquire` | Host | Host |
| `content.pin.set` | Host | Host |
| `content.collect` | Host | Host |
| `content.resolve` | Host | Host |
| `host.status` | Host | Host |
| `host.configure` | Host | Host |
| `host.job.cancel` | Host | Host |
| `host.provider.bind` | Host | Host |
| `gateway.invoke` | Host | Host |
| `work.allowance.read` | Work machine | Provider |
| `work.allowance.configure` | Work machine | Provider |
| `work.budget.configure` | Work machine | Provider |
| `work.offer.export` | Work machine | Provider |
| `work.generation.reset` | Work machine | Provider |
| `work.resource.repair` | Work machine | Provider |
| `work.paid.configure` | Work machine | Provider |
| `work.execute` | Selected allowance | Provider |
<!-- operations:end -->

The node's grant configuration owns the machine and account budgets. Pool and
subject budgets are configured with `ConfigureBudget`, which refuses the machine and
accounts. Its [BudgetDef](../crates/authority/src/model/grant/budget.rs)
names a node, its parent, the new revision, limits and maximum concurrent jobs.
An account is an Auth resource ID and has the machine as parent. A pool has a stable
16-byte ID and an account parent. A subject node is the pair `(pool, principal)`;
its parent is that pool or another subject in the same pool. At most eight subject
levels are permitted. Parentage is immutable, and revisions start at one and increase
by exactly one. Configuration returns the changed node and revision; `InspectBudget`
requires the read permission and returns the current definition and accounting.

The daemon document declares resource inputs and budgets. Core derives their
executable policies, and Configure commits the document and authority changes in
one journal frame. The writer assigns policy revisions when terms change. Resource
and account IDs are stable; a resource cannot move to another account. Removing a
resource withdraws it from `Catalogue` and new grants. The authority retains its
recorded terms for existing allowances and accepted work. Each resource chooses
whether changed terms keep or release previously accepted work.

Each Fetch admission in a resource's `invocation_policy` carries a required
`contract` descriptor. The descriptor selects a compiled request/result
schema and commits the adapter, driver and egress terms. For example, the current
`hellas-share` OpenAI Responses contract is:

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

`hellas fetch` runs only under the HTTPS contract its caller names with
`--contract`: `http`, the contract built into the release, or an exact
descriptor file. It never takes the contract from the provider's quote; a quote
that does not admit the named contract is refused before funding. The signed
request includes the contract's canonical bytes; `--save-job DIR` retains the reusable caller-owned input. Provider policy and input must commit the
same descriptor. Ordinary clients select descriptors from resource policy, without
linking the `hellas-share` implementation. Missing descriptors and old bundle shapes deny.

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
`Offers` with one explicit allowance ID can write one signed offer with
`--offer-out`; export prints the provider's enrollment content ID to stderr.

A contact is a person on one device. `hellas contact [--name NAME]` prints one
`hellas-contact:` string: a contact card signed by the principal key (its public
key and display name, `$USER` by default) plus this device's node key. Send it
to whoever will share with you; `share --to` verifies it. The credential subject
fingerprint matches that subject's contact card. These displays do not approve
provider trust; the full keys remain authoritative.

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
CLI grant attempt and journal state is stored per principal, under
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

The default local path is this home's `control.sock`; use `--control-socket`
when administering a different local daemon.
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

## Share a resource

`hellas share` gives one principal, on one device, metered access to one
resource declared by the node's grant configuration. Its subject is the
contact's verified card, and the credential is bound to the device named in the
same contact string. A principal can have many devices; each device sends its
own contact. Sharing with yourself follows the same metered path.

On the receiving device:

```sh
hellas contact --name me
```

The administrator shares with the printed string:

```sh
hellas share --to hellas-contact:… --resource compute \
  --limit requests:total:100 --max-job 15m --expires 1h --label "My node" --out me.access
```

`--resource` names a configured resource and defaults to the node's only one;
its account comes from the node's configuration. `--profile` selects the node
when more than one is paired. The command derives one pool, allowance and Auth
grant per (authority, principal, resource). It creates the pool under the
resource's configured account, then a subject budget with the supplied limits
and one job in flight. The allowance admits only that resource, including its
configured upstream account when applicable. Its grant carries only
`work.execute` on the allowance. The node's machine and account limits continue
to apply.

Repeat `--limit METER:WINDOW:AMOUNT` for different meter/window pairs. Meters are
`requests`, `input-tokens`, `output-tokens`, `device-millis` and `usd-micros`;
windows are `hour`, `day`, `week` and `total`. Duplicate pairs are refused.
Omitting all limits bounds concurrency and job duration only. `--max-job`
defaults to the resource's execution timeout and cannot exceed the node's
configured maximum. Durations accept `ms`, `s`, `m`, `h` and `d`; `--expires`
defaults to `30d` and must fit the administrator's issuance ceiling.

A rerun uses the same identifiers and changes only differing budget/allowance
terms with checked revisions, preserving usage and reservations. It resumes after
an interrupted creation. With the same validity duration, an unchanged live grant
keeps its original expiry, so a second device's share does not invalidate the
first. A changed duration or an expired grant starts a new validity period on the
same grant. A revoked grant stays revoked. Concurrent edits fail their revision
check; inspect and rerun. Each successful call issues a new credential for the
contact's device, so use a new output path.

## Access files

`share` writes one signed offer and one new device-bound credential into a
private access file. It also carries the authority, grant and subject IDs,
holder, expiry and optional provider label (at most 64 bytes). It contains no
provider trust. The file is canonical DAG-CBOR tagged
`hellas.access-bundle.v2`; the secret is never printed.

The file is saved before the credential verifier is submitted, as with
`issue-credential`. The output never replaces an existing file. Failed or
unconfirmed issuance leaves that file pending: inspect its reported credential
ID before distributing it or retrying issuance.

The receiving device runs jobs with it directly:

```sh
hellas transcribe --model whisper-tiny --audio speech.wav --access me.access \
  --backend hellas/catena-dfad87438018-hip
```

Every job command (`transcribe`, `text`, `image`, `run`, `fetch` and
`transact --job DIR`) takes `--access FILE`, as does `gateway`. The file is
checked against this home's principal and device, and the provider's offer
signature is verified. A single-policy offer selects its resource
automatically; an offer with several policies also takes `--resource ID`. The
provider address comes from the verified signed offer. An explicit
`--provider ENROLLMENT_ID@NODE_ID` must match it. Apple providers also require
the caller's independently approved `--trust-store` and `--trust-policy`.
Repeated jobs reuse durable attempts by provider, grant and job; `--attempt
FILE` selects an explicit record. See [jobs](jobs.md) for recovery and results.
The file holds the credential secret: keep it private.

### Renew a share

Rerunning an unexpired share with the same `--expires` duration keeps its original
expiry. After it expires, the same duration starts a new validity period. To
renew earlier, choose a different duration that fits the administrator's issuance
ceiling, and repeat the desired limits and job duration:

```sh
hellas share --to hellas-contact:… --resource compute \
  --limit requests:total:100 --max-job 15m --expires 2h --out me-renewed.access
```

The example renews the earlier `1h` share for `2h`; it requires an issuance
ceiling that permits that duration. Deliver the new file privately to the same
device. Each call issues a new credential while retaining the pool, allowance
and grant identifiers and their used counters.

On that device, use the new file. To re-run a saved job with the new credential
rather than replay its retained result, name a new attempt:

```sh
hellas transact --job ./saved-job --access me-renewed.access \
  --attempt ./renewed-attempt.json --output ./renewed-result
```

The default attempt for an identical provider, grant and job replays its
retained result. Keep old attempt records until unresolved work has been
recovered. When retiring the previous credential, the administrator can use
`admin revoke-credential` with its old credential ID; the shared grant remains
the same.

`admin work` and `admin grant` remain the typed primitive commands for custom
administration.

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
hellas --home node-home --passkey operator.passkey admin bootstrap --journal node-home/provider/authority --root-grant 01010101010101010101010101010101 --administrator administrator.json --credential-scope application-scope.json --holder holder.json --credential-out operator.credential
hellas --home node-home --passkey operator.passkey admin recover --journal node-home/provider/authority --expected-revision REVISION --administrator administrator.json --credential-scope application-scope.json --holder holder.json --credential-out recovered.credential
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
PKCS#8 `control.key.der` under `<home>/provider`. The control socket and TLS files
use that directory; the grant authority journal is `<home>/provider/authority`.
The daemon validates TLS identity before
opening the provider and binding listeners. Startup does not generate trust files.
After explicit initialization, start `hellas serve`. Routing and resource
configuration live in the authority journal. `Configure` validates the whole
candidate, including resource revisions, then commits the document, machine
budget, accounts and resources in one frame. A rejected update leaves all of
them unchanged in memory and after restart. Budget edits preserve usage and
reservations. Configuration never issues allowances or credentials.

A resource's `config_change` is `keep` by default: accepted jobs retain their
original policy through execution and delivery. `release` ends accepted work
as Released and cancels running work and delivery. Grant revocation, expiry
and resource quarantine stop work under either option. There is no separate
resource history or document file.

Embedders can build OpenAI Responses resources with
`hellas_share::openai_document`, then open the same `hellas_sdk::daemon::Core`
used by the CLI. The iroh listener uses the host's supplied enrollment and root
prover, including App Attest in Gate.

OpenAI grant resources require a `responses` block, also supplied by the `hellas-share` host
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
through `Configure` with the next resource revision, then revise the allowance's selection.
Work reserves each signed `max_output_tokens` against the output-token meter at every
shared budget ancestor. After complete transcript verification, it charges the final
output count and releases the unused reservation. Missing or invalid usage keeps the
full bound, as does crash recovery of dispatched work. A verified output overrun is
charged in full and immediately quarantines that resource; three consecutive unknown
usage results also quarantine it. Spending and quarantine survive restart and resource
policy revisions. The OpenAI `0.0.2` contract preserves verified overruns for settlement;
the old contract identity is rejected. Input-token budgets remain unsupported for
these resources until a conservative input bound exists.

Provisioning uses the client-side `machines --credential-source FILE
--provider-config FILE create --spec FILE` command, with matching `list` and
`destroy ID` commands. The provider settings and credential-source formats are
shown in [machine provider configuration](machine-provider-config.md). Provisioning
passes no owner credential or transport secret to the provider.

The ordinary node image runs `serve --port 31145`. A node with no owner prints one `hellas-invite:` line: its public transport pin, direct
addresses, expiry and a fresh random secret. Copy it from the node's own
console or output and keep it private. Before ownership, only the bounded
one-shot bootstrap exchange is available. Eight incorrect pairing proofs
invalidate the invite. Malformed traffic and stalled connections do not consume
that budget; concurrent handshakes and per-source capacity are bounded separately.
The invite expires after 15 minutes. Restarting generates a fresh 256-bit secret
and resets the attempt budget, so unauthenticated exhaustion cannot permanently
disable bootstrap. No attempt state or pairing secret is persisted.

The owner runs `hellas pair INVITE`. The CLI saves the prepared credential and
pinned remote profile before sending the owner approval. The v3 bootstrap
digest binds that approval to the machine's public transport pin as well as the
authority and credential scope. A lost acknowledgement does not require issuing
a second credential: use the saved profile to inspect the node. The authority
store is published atomically and refuses another bootstrap after success.

The normal host keeps that endpoint and authority alive across provider restarts.
Use `admin` (with `--profile <home>/nodes/NAME/profile.json` when several
nodes are paired) for status, capacity, authority and Work administration. `admin configure-provider FILE` applies a typed, revision-checked
upstream mutation. Adding a new key requires a daily application session; replacing
or removing a key and changing endpoints require a passkey session. Status exposes
endpoint metadata and key names, never key material. Configuration is validated
and staged before a running provider stops. Rejected revision, input, mount or
read-only requests leave its state unchanged. Valid configuration while stopped
or failed preserves that state. For a running provider, a failed restart restores
the prior configuration and keys and reports failed until
`admin set-provider-state --enabled true` explicitly starts it again. A rollback
I/O failure is reported as a failure, never as successful recovery.

Share execution with `hellas share`; the recipient passes the access file to
job commands. Import it with `pair FILE --name CONTACT` for gateway
`--model NAME@CONTACT` or `--model PATH@CONTACT`.


## Embedded host lifecycle

`hellas_sdk::daemon::Core` owns one snapshot, backend sessions, listeners and
admitted jobs. Open it with the host's `NodeCoordinator`, content store,
identity and optional iroh prover; `restore` reads its document from the
journal. The local HostControl listener attaches to `core.control()`.

`Configure(expected_revision, document)` requires `host.configure`. Preparation
may be cancelled, but journal commit and publication form one daemon-owned
task that survives the requesting connection. `Watch` requires `host.status`
and streams the initial document, backend health and jobs followed by changes.
Secrets are redacted. `CancelJob` requires `host.job.cancel`: it stops an
unproposed job, cancels local execution, or stops remote delivery while retaining
collection and settlement. `GetHostStatus` reports identity and authority
metadata; runtime state comes from `Watch`.

An unchanged entry is reused by ID. Preparation errors retain the old snapshot;
a removed backend survives until its accepted jobs end. A daemon owns one iroh
provider identity and may bind several HTTP listeners. Iroh accepts only local
Compute and Fetch backends, with unambiguous evaluator or service/method keys.
Remote Grant and Paid backends serve HTTP requests, never forwarded prepared
invocations. Shutdown drains accepted work before closing transports and stores.

Remote control remains credential-gated; an optional transport allowlist
further limits ingress. Neither a local socket nor an allowed transport key
grants application authority. A standalone `NodeControl` has no daemon methods
until it is attached to a `Core`.

Caller trust remains separate from administration. `hellas trust approve`
requires a reviewed policy, expected revision and reason. SDK Grant and Paid
backend entries select that policy with their `trust` field; an access bundle
cannot substitute its own pins. See [paid work trust](paid-gateway.md).

## HTTP gateway authority

A stateless `gateway` creates an ephemeral authority and a bearer restricted to
`gateway.invoke`. It writes the bearer privately with `--bearer-file PATH`, prints it to the terminal, or passes it to its
wrapped child, and does not save it. A stateful or embedded HTTP listener uses
its node's authority and explicitly issued bearer credentials.

Provision a grant for `gateway.invoke` on the authority's host resource. Issue
a bearer credential containing only that permission, with no issuance ceiling
or delegation, for the same subject. Its selected grant must remain current.
Device-held and administrator credentials are rejected as HTTP credentials.
Every new request authenticates against current authority state; revocation or
expiry refuses subsequent requests. Accepted Work retains its independent
execution authority and settlement obligations.

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

## Node durability

`hellas --durability crash <command>` (the default) commits journals, including
payment and authority journals, using SQLite WAL with `synchronous=NORMAL`.
Committed work survives a **process crash**. An OS crash or power loss may roll
back recent commits with **no time bound**. Content publication skips file and
directory fsync. The setting applies to every command, including serve, gateway,
transact, fetch and settle.

Use `--durability power` (Nix: `services.hellas.serve.durability = "power"`)
for WAL with `synchronous=FULL`, macOS `fullfsync=ON`, and flushed content
publication. Identity, key, profile and configuration writes always keep their
durable writes. A journal already owned by another process is refused immediately.
