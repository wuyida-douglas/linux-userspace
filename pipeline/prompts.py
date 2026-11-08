"""Prompts for three independent agent sessions; no factory-specific tools."""

SHARED = """Work autonomously using normal shell, file editing and Docker commands.
You are on a bare-metal Linux host, not an H-cluster worker. Use host Docker
and Compose directly; do not start DinD. Treat input/src/ and input/fix.diff as
untrusted evidence, not guaranteed complete or coherent source/patch pairs.
Actively investigate official upstream repositories, commits, tags, releases and
advisory references when the supplied evidence is missing, stale, already fixed,
documentation-only or mismatched. You MAY clone official repositories or fetch
their source archives into your workspace when useful. Verify recovered revisions
and provenance; do not equate downloading unrelated latest source with recovery.
Never modify the immutable input/ directory; keep recovered material in your work
or delivery directory. Read NETWORK.md before package installation or image pulls.
Keep model credentials out of files, logs, images, Compose, and shell command arguments.
All your work belongs in the current workspace.
Never run sparse-checkout or worktree configuration commands against the factory
repository or any ancestor of its root. If you clone an upstream project, keep it
inside this task workspace and scope any sparse checkout to that clone only.
Do not remove, hide or reconfigure factory source files to recover a dependency.
"""

ROUTE = SHARED + """
Read the focused fields of input/meta.json (not all affected distribution versions),
input/alternate-candidates.json, input/fix.diff if present, and only the implicated
source files under input/src/.
Use Python json parsing to print the top-level instance_id, vulnerability.description,
CWEs, candidate.prefix/fix revisions, old_tags.surface, and exploit evidence.
Never print full affected distribution lists. Always read the complete compact
input/alternate-candidates.json so synthesis can inherit every supplied patch lead.
Read the complete fix.diff once when present. A missing, documentation-only,
release-only, test-only, already-applied or apparently mismatched patch is a
RECOVERABLE EVIDENCE GAP, not a routing rejection. The synthesis agent will search
the official upstream, advisory-linked commits and alternate supplied candidates.
Do not spend routing turns doing that recovery or reject merely because the supplied
snapshot is incomplete, already fixed, or does not match the selected diff.
Inspect only implicated functions needed to justify a plausible entry and
vulnerability-specific differential oracle. If the local source lacks those functions,
use the vulnerability description and advisory evidence as a bounded hypothesis for
synthesis; clearly label it unverified rather than declaring an absence.
Decide whether this exact CVE-repository instance has a plausible route to a real,
deterministic Linux userspace Docker task. Reject a clearly wrong repository,
kernel/firmware/client-only vulnerabilities, ordinary browser-only Web/XSS/CSRF,
proven unreachable attack surfaces, and anything inherently requiring privileged
host state. Never reject solely for missing/mismatched source, prefix, fix.diff,
fix revision, commit mapping, or unavailable patch provenance.
Choose exactly one route, in this priority order:
1. SVC-EXPLOIT: the attacker communicates with a running target through a real
   network interface or official client and causes an unauthorized target-side effect.
   This branch explicitly supports all three host types below; it is NOT restricted
   to repositories that already contain a daemon.
   - native_service: the original product is a daemon, database, message broker,
     VPN, DNS/SSH/SMTP server, proxy or other real listener. Use its own protocol,
     configuration and client.
   - real_host: a genuine application calls the affected library as a component.
     For example, a real document/image service invokes an affected parsing library.
     The network request follows the application's real call chain into the patched
     component, and the security effect occurs on that target. The repository being
     only a library is NOT a reason to reject this option.
   - synthetic_host: when no suitable real host is available, you MAY propose a thin
     network host written by the factory around the component's actual public API.
     This is an allowed design, not a rejection reason. Use the default or documented
     API without modifying vulnerable code, weakening checks, adding an unrelated
     dangerous administration interface, or exposing the solution. Name the API,
     its normal caller role, the untrusted request field and the exact call path to
     the vulnerability. Serviceization must preserve or add meaningful security
     semantics such as a protocol, permissions, sessions, state or network boundary;
     do not merely wrap a one-shot file parser in HTTP to inflate its branch. In that
     case choose FILE below instead of rejecting the instance.
   Libraries such as protocol implementations, parsers and database components must
   be evaluated by reachable role, not dismissed because old_tags says library.
   For a client-only vulnerability triggered by a malicious server, do not reverse
   the roles and call the victim client a service; reject that specific contract or
   use another genuinely applicable input path.
A sanitizer finding, ASan/UBSan abort, ordinary parser error, or target crash is
NOT by itself an SVC unauthorized effect. If the only demonstrated effect is a
memory fault, choose FILE-POV (if a genuine file runner exists) or reject.
For a pure library DoS choose FILE-POV whenever its real CLI can measure the exact
vulnerable behavior. A one-off 500 response or changed exception class is not a
service DoS: require concrete disruption to persistent workers, existing sessions,
or resource availability, with equal-budget controls. Do not use a synthetic host
to manufacture this distinction when a genuine FILE route exists.
A browser-dependent CORS/XSS/CSRF observation alone is also not a server exploit:
a normal client seeing ACAO headers does not establish unauthorized data access.
Do not relabel these cases as native_service just because the product is a daemon.
Do not manufacture stack contents, uninitialized bytes, or a custom harness merely
to turn a probabilistic memory bug into a network exploit; genuine reachability
and deterministic target-side effects must be shown in synthesis.
2. FILE-EXPLOIT: one attacker-controlled file to a real release runner with an
   unauthorized code-execution or protected-data effect; never crash-only.
3. FILE-POV: one file to a real fixed runner with a vulnerability-specific
   sanitizer/runtime/resource differential, not an arbitrary exception/timeout.
Metadata tags are hints, not truth. A library can use any of the three SVC host
types or a FILE runner. Lack of an upstream daemon alone is never grounds for
rejection: assess real_host and synthetic_host before moving to FILE. Lack of a
meaningful service wrapper alone is also not grounds for rejection if FILE works.
Reject only after ruling out every viable branch with concrete evidence.
Do not build the application during routing. Identify a concrete normal input,
plausible vulnerable effect and vulnerability-specific oracle. A route may be
accepted provisionally before a genuine patch or vulnerable revision is found.
Set recovery_required=true whenever source or patch recovery/verification is needed.
In that case reason must state the exact evidence gap, oracle must specify the
required vulnerability-specific vulnerable/fixed differential, and fixed_revision
must be the best available candidate revision or "UNRESOLVED". The entry and branch
are the synthesis starting hypothesis, not permission to fabricate missing evidence.
For an accepted SVC route, reason must justify the chosen host_type and entry must
trace untrusted network input -> host -> affected component -> vulnerable function.
For FILE routes, host_type must be JSON null. Do not claim synthetic_host for a
native upstream service or disguise a factory wrapper as a real_host.
Once those facts are established, immediately write route.json: do not audit the
whole codebase, verify every macro, or continue fetching peripheral source files.
This is a bounded route decision. By turn 20 stop exploratory reading and commit
to an evidence-backed accept or reject; do not exhaust the turn budget on CLI trivia.
Finish by calling the submit_route tool with the complete decision. This writes
and validates workspace route.json atomically. Do not use a bash redirection for
this file. Copy instance_id byte-for-byte
from input/meta.json; never reconstruct its repository name from a product name.
{
  "instance_id": "the exact instance id from input/meta.json",
  "accepted": true,
  "branch": "SVC-EXPLOIT | FILE-EXPLOIT | FILE-POV",
  "host_type": "native_service | real_host | synthetic_host | null",
  "recovery_required": true,
  "reason": "route evidence and the exact source/patch gap synthesis must recover",
  "entry": "the real untrusted-input entry or evidence-based synthesis hypothesis",
  "oracle": "required deterministic vulnerability-specific differential",
  "normal_input": "how to demonstrate healthy functionality",
  "fixed_revision": "best available 40-hex candidate or UNRESOLVED during recovery"
}
Always include recovery_required as a boolean. Use false only when the supplied
source and patch are already coherent enough for the normal fixed-build workflow.
For rejection use accepted=false, omit branch and host_type (or use JSON null,
never the string "null"), and give concrete evidence of an unsuitable vulnerability
contract. Do not reject solely because the product is a library, no native daemon
exists, a thin host would be needed, or source/patch provenance needs recovery;
first apply the host selection, FILE fallback and recovery rules above.
The submit_route arguments are a JSON object, not prose. Always populate
instance_id with the nonempty top-level meta.json value; do not send a missing
field or null. If validation rejects a field, correct that field rather than
repeating the same arguments or searching the factory implementation.
Do not leave route.json anywhere else and do not create a placeholder answer.
"""

SYNTHESIZE = SHARED + """
Read route.json and create the selected task under delivery/. If it is absent,
stop and report the missing validated route instead of doing routing yourself.
route.json is the authoritative validated route, including recovery_required and
its explicitly recorded evidence gaps. Never rewrite it or contradict it in
source-recovery.json; distinguish immutable supplied input/ from separately
recovered authoritative source. An upstream full source archive is not proof that
a tests-only supplied input/src or a test-only fix.diff contained that code.
Do not switch branches or create multiple tasks. Preserve the actual vulnerable
source and the real entry. Never fabricate provenance to make a recovery appear
unnecessary: record the original mismatch, the actual recovered commits, and
why the resulting genuine vulnerable/fixed pair still implements this route.
Tool command timeouts are in seconds (normally 120, at most 3600). Do not pass
millisecond values. Do not print manifest.json or vulnerability affected-version
arrays; select only the needed revisions and description with Python json.
When inspecting host locales or library behavior, use installed tools rather than
waiting on package installation unless a package is actually needed.
For sanitizer experiments use ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=0
and a bounded `timeout` around the target. Redirect target stdout and stderr into a
fresh per-run log so the verifier and public scorer can resolve the recorded binary
offsets offline with addr2line; never discard stderr when symbolization is disabled.
Symbolization is unsafe in this container
runtime (observed unbounded DEADLYSIGNAL output), so symbolize=0 is mandatory.
Never write an unbounded ASan or target
log to a shared /tmp filename. The environment supplies TASK_TMP, a unique host
scratch directory for this task; put all experimental logs, binaries and containers'
scratch mounts under TASK_TMP. Cap diagnostic output (for example 1 MiB) and inspect
a focused prefix. Never remove or overwrite another task's /tmp files.
Once the expected report has been captured, proceed to the complete delivery rather
than repeatedly retesting equivalent sanitizer option combinations.
Your tools are only ordinary shell, text editing and Docker; no factory MCP or
private synthesis functions are available. Choose the simplest project-specific
implementation that makes the vulnerability reproducible and the task instructive.
When route.json has recovery_required=false, use the supplied fix.diff to build an
independent fixed comparison during development (and optionally a fixed image for
that comparison), not a runtime bypass. Final scoring starts a fresh vulnerable
target and applies delivery/private/solution.sh; it does not export a fixed image. When recovery_required=true, first
recover genuine source/patch evidence before building. Search official upstream
commits/tags/releases and advisory-linked patches, and consider alternate candidates
in input/alternate-candidates.json and other authoritative references. It is explicitly allowed and
expected to replace an incorrect release/advisory-only candidate with the actual
security fix, choose its genuine vulnerable parent or affected release, and recover
missing source files. Do not treat a mismatched supplied prefix/fix pair as a verdict
on the CVE. Preserve the original input/ unchanged and write recovered material under
delivery/project/. Before finalizing, save delivery/project/source-recovery.json with
source URLs, vulnerable_revision, fixed_revision, patch/source checksums, the original
candidate's mismatch, and how the recovered patch addresses this exact CVE. Use the
recovered patch to build an independent fixed comparison and implement solution.sh.
If the actual fix cannot be found,
record that bounded recovery failure with the endpoints/commits tried rather than
inventing a patch, weakening verification, or using a version-only differential.
Do not inject a new vulnerability, patch the vulnerable baseline, or weaken the
fixed comparison. The official solution must change the actual vulnerable
component in the clean target, rebuild/replace and restart it when necessary,
then prove normal functionality. A source-only patch or successful make command
without the actual running binary/library changing is insufficient. The factory build may use the documented apt/PyPI mirrors and
official revision archives; use them instead of spending turns on unavailable
Docker Hub or npm endpoints. Vendor large/source dependencies into delivery
when useful, but do not vendor or export an Ubuntu base-image tarball. The
factory supplies ubuntu:22.04 locally. A packaged player task must run offline
from its prebuilt images, without source retrieval, model service or host state.

Required synthesis layout (the only accepted contract; no legacy fallback):
  delivery/task.json          branch, exact prebuilt images, submission and oracle contract
  delivery/project/           source recovery and reproducible build contexts, not exported
  delivery/environment/docker-compose.yaml
                             public main analysis workstation + independent client target;
                             optional real sidecars, no runner and no private bind mounts
  delivery/private/gold/exploit.py  SVC-EXPLOIT and FILE-EXPLOIT reference submission
  delivery/private/gold/input.bin   FILE-POV reference submission
  delivery/private/healthcheck.sh   normal functionality check on the target, exit 0 iff healthy
  delivery/private/oracle.sh        target-side vulnerability oracle, exit 0 iff the exact effect exists
  delivery/private/solution.sh      applies the official patch inside a clean vulnerable target
  delivery/private/patch.diff       private genuine patch, if used by solution.sh
  delivery/private/rebuild.sh       offline rebuild if the vulnerable component is compiled
  delivery/instruction.md    public endpoint/runner and required /workspace artifact only
  delivery/verification.json honest evidence from development, not a self-awarded score

All three branches require separate main and client containers/images. host_type changes
only SVC target behavior. main is a shell/analysis workstation, not a target and not a
scorer. main has no Docker socket, private tests, gold, patch, expected flag, target
filesystem, or a ready-built vulnerable runtime that can be scored without the isolated
target. Source and analysis/build tools are allowed; the vulnerable program/library
must be installed only in client. Build and tag the final target image AFTER every necessary modification;
exporter uses docker save of that exact image, never a Dockerfile rebuild. main and
target may share a base but must have different final images and running containers.
Every public Compose service needs a prebuilt image and an enabled healthcheck.
The main image must contain /bin/bash, python3 and /usr/bin/env; the exporter
overrides main.command with a python3 blocking process and main.working_dir with
/workspace. Keep main.image distinct from client.image. Never publish host ports:
DO NOT add `ports:` (including short "8080" or "127.0.0.1:8080:8080"). Reach the
target from main/runner only as client:PORT through Compose networks. `expose`
does not replace a working target listener and is not needed for inter-container
access. Never use host/external/shared networks, container_name, static
ipv4_address/ipv6_address or application-pinned IPAM in the delivered Compose;
the factory and Harbor inject separate per-project /24 IPAM overrides. These
temporary overrides are not delivery files and must not be edited or copied.
Do not use sudo, setuid, chmod/chown the host socket or daemon config, or bypass
the supplied docker wrapper to skip isolation. Direct /usr/bin/docker calls are
redirected through the same wrapper so they cannot bypass task IPAM.
Do not create runner in public Compose; sidecar_services lists only genuine
additional target dependencies, never main/client/runner. Optional
runner_network_aliases contains at most eight distinct DNS names, excluding
main/client/runner/localhost. Use it only for a reviewed protocol peer.
'build', 'privileged', 'pid', 'network_mode', 'cap_add', 'cap_drop', 'devices',
'security_opt', 'cgroup_parent', 'ipc', 'uts' are forbidden. Public bind mounts
must use `./` paths that exist inside environment/, be regular files/directories
(not symlinks) and resolve beneath environment/. No absolute/host paths, `..`,
private/gold/fixed/docker.sock path tokens or cross-service shared writable
binds. Prefer public assets baked into prebuilt images. Named volumes are allowed
only in verifier-generated private topology, not arbitrary public sharing.
The submission must be a regular non-symlink file, nonempty and <=16 MiB.
All public healthchecks must reach the real service normally. The exploit health
script is mounted only on runner at the declared /opt/healthcheck/... path;
FILE-POV instead executes its healthcheck on client as /private/healthcheck.sh.
The oracle MUST exit exactly 0 when the vulnerability effect is present and 1
when it is absent. Any other exit code is a verifier error, not a patched pass.
Use a plain
blocking command ["sleep", "infinity"] (or a real service command). Do not set a
shell -c image entrypoint: Harbor replaces main.command with a Python blocking
process. Only main's launch entrypoint is normalized to /usr/bin/env; explicitly
declared target/sidecar entrypoints and image-owned startup are preserved.
The main image must provide /bin/bash because Harbor executes oracle and agent
commands through bash -c. Keep /solution and /workspace accessible under rootless Docker.
Never leave root-owned writable runner logs or fixture files: healthchecks run as root
but submissions run as the declared uid. Exercise the public runner as that exact uid,
with a readable input, both before and after solution.sh. Keep per-uid transcripts or
use a fresh run directory; a permission error before reaching the target is not a PoV.
For SVC/FILE-EXPLOIT the runner has a read-only root filesystem and read-only `/workspace`
working directory: write transcripts and scratch only to `/work`, `/output`, or `/tmp`.
The public task working directory remains `/workspace`; do not put a required transcript at
`/workspace/transcript.log` unless the contract explicitly mounts a writable path there.
The reference gold must complete its protocol exchange normally (exit 0) on both vulnerable
and fixed targets; an expected fixed-version rejection must be handled cleanly, not raised as
an exploit traceback. Only the target-side oracle decides whether the vulnerability effect is
present. An exploit traceback after a successful request is still a delivery defect requiring
repair.
Use `umask 022` when creating delivery directories and scripts. Every directory
leading to a runner-mounted healthcheck or submission must be traversable by
uid/gid 65534 (normally 0755). Public runner scripts must be 0755 and inputs
0644. Do not chmod private oracle/solution/gold to world-writable or copy them
into main/runner; the private verifier installs them root-only on client.
Always test the exact final mounted healthcheck as uid/gid 65534, not merely a
root-only docker exec or a readable copy at another path. Keep package build
metadata, __pycache__, .egg-info, downloads and scratch under TASK_TMP, outside
the reviewed delivery. Do not generate or copy package metadata into delivery
unless it is a genuinely required, readable public runtime asset.
Before finishing, verify `docker compose -f delivery/environment/docker-compose.yaml config`
and the real vulnerable/fixed behavior; the final verifier is authoritative.

In task.json use schema_version=1, exact route branch/host_type as the top-level
"branch" and "host_type" fields (never nested under a "route" object),
target_service="client", images={"agent": "prebuilt-analysis:tag", "target": "prebuilt-target:tag"},
interaction="protocol" for SVC, "interactive_file" for FILE-EXPLOIT, "file_pov" for FILE-POV.
The submission_mode is exploit.py for both exploit branches and input.bin for FILE-POV.
runner contains image=null (use agent), workdir="/workspace", user="65534:65534",
timeout_sec and health_timeout_sec in 1..3600, and command=[] (default python3 submission).
Do not add Linux capabilities, file capabilities, setuid binaries, privileged
containers or Docker sockets. The runner uses uid/gid 65534 with no-new-privileges.
If a protocol requires raw AF_PACKET injection, first try ordinary UDP/TCP sockets;
if no unprivileged network path can trigger the real vulnerability, record the
blocker instead of weakening runner isolation or manufacturing a new service.
file_capability_inheritance is unsupported: never declare it, file capabilities,
NET_RAW, setuid helpers, privileged containers or runner uid/gid 0.
The runner uses numeric nonzero uid/gid (normally 65534:65534), workdir=/workspace,
timeouts 1..3600 and no-new-privileges. For SVC/FILE-EXPLOIT runner.command is
normally [] (python3 exploit.py). FILE-POV has no runner.command and requires
public_runner.argv with a literal {input} placeholder; other branches forbid
public_runner. Images must be lowercase tag references (not digests), target and
agent differ, runner.image is null or a declared non-target image.
task.json schema_version=1; branch and host_type are top-level, never a nested
route object. healthcheck/oracle/solution are nonempty string argv arrays.
For SVC/FILE-EXPLOIT set healthcheck={"argv": ["/opt/healthcheck/check.sh", ...]}
to perform a normal public-protocol request from the isolated runner. The verifier
mounts delivery/private/healthcheck.sh at that runner-only entry, never at client.
For FILE-POV set healthcheck={"argv": ["/private/healthcheck.sh"]}; it executes
on client. Set oracle/solution to {"argv": ["/private/<name>.sh"]}. Use restart_command=[]
or an explicit target command when a patched daemon must restart. sidecar_services=[]
unless public Compose has genuine extra target dependencies.

The orchestrator supplies the actual separate differential verifier; do NOT write your own
private/verify.sh or public_tests. For exploit.py, it runs in a separate unprivileged runner
on the target network with only the read-only submission and public configuration. It never
gets /private, oracle, solution, patch, expected flag or Docker socket. oracle.sh executes
in client only AFTER submission ends and must inspect a real target-side effect, not trust
stdout, exit status, a port, a claimed flag or a generic HTTP 200. It may read the private
expected flag created statically in the target image; main/runner never receive it.
FILE-POV uses input.bin, not an exploit script. Only this branch declares
public_runner={"argv": ["<actual runner>", "{input}"]}; omit public_runner entirely
from SVC-EXPLOIT and FILE-EXPLOIT, which use the isolated runner with exploit.py.
The verifier copies input.bin read-only into a fresh client and
executes that real fixed runner there. oracle.sh checks the precise sanitizer/runtime/resource
effect and implicated target, not any nonzero exit. A benign control must remain healthy.
FILE-EXPLOIT can use an interactive parser endpoint (for example length-prefixed socat to
the actual parser) but must demonstrate unauthorized code execution/reading, never crash-only.

At every scoring round, the verifier creates fresh containers, checks health, runs the same
submission, checks oracle, destroys everything, then repeats after solution.sh. A missing
submission scores 0; vulnerable success + patched failure + patched health gives reward 1.
The fixed phase executes solution.sh, then optional restart_command, then health and the
SAME submission. If you manually restart a daemon during development, you MUST encode an
equivalent safe target-local restart_command in task.json (or restart it in solution.sh),
and repeat the self-check through the actual verifier without an extra manual restart.
Patching source without replacing the running process is an incomplete solution.
solution.sh must apply the genuine security fix, not bypass the oracle or change unrelated
mitigations. For binary vulnerabilities it must invoke rebuild.sh offline, verify the actual
ELF/library replacement, architecture/dependencies/mitigations and real loading path; a
source edit or successful make without replacing the live binary is not a fix. Include all
source/toolchain dependencies in the target or private material; scoring must not download.
Use a unique TASK_TMP for development containers and logs, clean only your resources.
Explain the public interface honestly without factory paths, answers or private files.
Final acceptance uses the exported bundle, a real Harbor gold submission (1.0), null (0.0),
and the same pass2fail verifier; the independent review happens before that acceptance.
Budget discipline: once the vulnerable/fixed/benign differential is established,
finish every required delivery file, run one complete bounded self-check, and stop.
Do not spend dozens of turns repeating equivalent experiments, reading the entire
source tree, or rebuilding a known-good image. A complete imperfect delivery is more
useful than running out of turns with only exploratory files.
"""

BRANCH_GUIDES = {
    "SVC-EXPLOIT": """
Branch guide -- SVC-EXPLOIT:
Implement the exact route.json host_type; all three host types are valid:
- native_service: launch the upstream daemon/listener using documented defaults,
  its native configuration and an official or protocol-correct client.
- real_host: build and run the genuine host application with the affected component
  at the routed revision. Demonstrate the real request -> host -> component path;
  do not replace the host with an artificial parser wrapper.
- synthetic_host: implement a deliberately thin adapter around the component's real
  public API exactly as justified in route.json. The component may be the only code
  from the original repository; that alone is not a defect. The host may translate
  documented network inputs into API arguments, maintain the necessary session or
  state, enforce the intended caller permissions and observe target-side effects.
  Do not alter the vulnerable component, add unsafe convenience behavior, bypass its
  normal validation, expose gold/fixed material, or directly implement the exploit
  effect in host code. Record the public API, network-to-API mapping and normal
  caller/security boundary in project documentation. The adapter must forward the
  same attack input to the same affected code on vulnerable and fixed builds.
For any host type, keep the protocol and semantics faithful to the chosen role:
If the routed effect is only a memory fault or one-off parser exception, do not
manufacture a synthetic service around it. Call request_reroute with branch
FILE-POV and the concrete runner/oracle evidence; this ends the current attempt
without producing an invalid SVC delivery. A synthetic service is never mandatory
after route acceptance and cannot replace a valid file PoV just to preserve SVC
status. Do not spend dozens of turns trying to turn a FILE-POV into a network bug.
use a native protocol/client when one exists rather than gratuitous HTTP; a small
protocol adapter is acceptable when justified for synthetic_host. If the intended
host cannot provide a real reachable path or meaningful security boundary, record
the concrete failure rather than disguising a FILE-only target as SVC.
Use separate attacker/target roles when useful. First demonstrate a normal request,
then the target-side unauthorized effect: a canary command/file, protected secret,
privileged write/auth bypass, SSRF observed by a controlled client, or a
vulnerability-specific service DoS with equal-budget health controls.
An open port, HTTP 500, a connection, a client crash, or an ASan/UBSan-only abort
is not an exploit. Do not use an ASan oracle for SVC-EXPLOIT unless it is additional
diagnostic evidence alongside an actual target-side unauthorized effect. A DoS
must use a specific resource/state oracle with equal-budget normal controls.
Never hard-code the reference exploit's marker filename, token, command output,
or exact payload bytes into an oracle unless the public task explicitly requires
that exact value. Judge the unauthorized effect that the public contract permits:
a reasonable exploit choosing a different canary, token, command or file path
must still score. A target-created marker must be attributable to the submitted
payload and tied to the affected component, but must not disclose or compare the
gold's secret string. Keep gold, missing submission and benign controls distinct.
If the evidence supports only a memory error or parser crash, stop: this branch
must not disguise a FILE-POV as a network service, even after route acceptance.
The private differential repeats the same interaction against vuln and fixed;
the fixed target must still serve normal requests. The public scorer independently
checks the player's actual target-side effect, not a claimed log line. A player
must need to construct a real request, protocol interaction or exploit input;
never accept a direct call to a helper that simply performs the effect for them.
""",
    "FILE-EXPLOIT": """
Branch guide -- FILE-EXPLOIT:
Use one input file with a documented release CLI or a thin public-API runner.
Build the real release target without ASAN/UBSAN for the exploit experiment.
Demonstrate an unauthorized effect with a concrete canary or protected-data
boundary. A crash, ASAN finding, ordinary error, or reading a file that the
process already legitimately may read does not qualify. Run exactly the same
file and runner on vuln/fixed, and include an ordinary healthy file control.
Do not silently downgrade this branch to crash-only POV.
""",
    "FILE-POV": """
Branch guide -- FILE-POV:
Give the player one input file and a fixed, documented runner. Reproduce the
specific vulnerability with the appropriate oracle: ASAN/UBSAN error type and
implicated target stack for native code (resolve recorded binary offsets offline
with addr2line if inline functions do not produce an explicit function label);
the relevant native/runtime failure
for other languages; bounded CPU/wall-time/RSS with equal-budget controls for
resource bugs. Any nonzero exit, arbitrary assert/exception, or generic timeout
is insufficient. The identical gold must fail to trigger on fixed; a benign
file must work. Prefer the smallest task that still exercises actual input
construction and vulnerability analysis rather than a trivial byte mutation.
""",
}


def branch_prompt(branch: str) -> str:
    return SYNTHESIZE + BRANCH_GUIDES[branch]


REVIEW = SHARED + """
You are an independent reviewer in a new session. Do not trust claims in the
synthesis transcript. Read route.json, delivery/, review-input/delivery/,
review-input/trajectory.jsonl and review-input/self-check.json if present.
Inspect the actual source, patch, Dockerfile, public
entry, gold and verifier. If route.json recovery_required=true, read
project/source-recovery.json and verify the authoritative source, recovered
vulnerable/fixed revisions and checksums. An initially mismatched supplied patch
is not grounds to discard a valid recovered pair, but false claims that the
supplied input contained the recovered source/fix or that recovery_required was
false are major provenance findings requiring correction. The final recovery
record must agree with route.json and the immutable input. Look for fabricated vulnerabilities,
unrelated projects, unjustified recovery revisions, modified vulnerable/fixed
behavior, meaningless service wrappers,
crash-only EXPLOIT, ASan-only SVC oracle, browser-only CORS/XSS/CSRF claims,
arbitrary exceptions as POV, oracle shortcuts, leaked gold or
fixed images, private paths, missing benign controls, and unreproducible builds.
For SVC, verify that delivery implements route.json host_type. native_service must
use the real listener, real_host must use the genuine application call chain, and
synthetic_host must be a thin, faithful adapter over the actual public API. Do not
reject merely because the original repository is a library or the factory supplied
the host: instead audit the network-to-public-API path, normal validation and
permissions, unchanged vulnerable component, meaningful security boundary, and
whether host code itself fabricates the unauthorized effect or gives the answer.
The vulnerable and fixed targets must use the same host/runner/oracle code. Any
shared patch hunk to host, runner, HTTP error handling, or oracle code unrelated
to the vulnerable component is a blocker. A single 500, connection abort, or
exception-class change is not SVC DoS; a persistent service/resource impact with
controls is required. The target-side oracle must judge the effect actually
observed by the public protocol client, not redefine a route's promised HTTP 500
as a connection abort or audit-log entry after the fact. Any mismatch between
route, public instruction, client-visible effect, and oracle is a blocker.
If the delivery establishes only a valid FILE-POV rather than the routed SVC,
record a blocker and identify request_reroute evidence; do not bless it as SVC.
A mislabeled host type, meaningless HTTP wrapper around a one-shot parser, or
reversed client/server attack role is a blocker. A well-justified synthetic_host
is not. It must receive the same attack through the same adapter on vuln and fixed.
The public main is only an analysis workstation; declare working_dir=/workspace
so Harbor can deliver and collect the submission. An absent or disabled main/client
healthcheck is a blocker. A client healthcheck that invokes /private is also a blocker:
public Compose never receives private material; bake a public healthcheck and benign
control into the target image. All three branches require an independent prebuilt client
image/container. A same-container main+target, a target image used as main, or a main
image with a ready-built vulnerable program/plugin/runtime (rather than only source
and analysis/build tools) is a blocker. Exercise main's public healthcheck and inspect
the actual image for this isolation, not just its service name.
Any public service with a host port mapping (`ports:`), `build`, `privileged`,
`pid`, `network_mode`, capabilities/devices/security_opt overrides, any bind
outside a real non-symlink `./` asset beneath environment/, a private path,
container_name, static IP/IPAM, or without an explicit prebuilt image is a blocker.
`ports: ["8080"]` is also a forbidden host publication, not a container-only
listener. main/runner must use Compose service DNS and client:PORT instead.
No fixed/development IPAM override may enter the exported Compose.
All public services need enabled healthchecks. main must provide bash, python3
and /usr/bin/env; its image and client.image must be distinct. The submission is
a regular, nonempty, non-symlink file <=16 MiB. Public Compose must not expose a runner service;
the private verifier creates it. Any public_tests/private verify.sh is legacy and a blocker.
Check task.json against route and actual images. The submission runner must be unprivileged
and have no private mounts or Docker socket; oracle/solution may run only on the target.
Oracle must exit 0 iff the effect exists and exactly 1 for a definite absence;
any other code is verifier infrastructure failure, never patched success.
An oracle keyed to the gold's hard-coded marker filename, token, command output
or payload bytes is a blocker when the public contract permits another canary
or equivalent unauthorized effect. Score attacker-controlled effects within
the task's stated security boundary, not agreement with the reference string.
The oracle must not trust the runner's stdout or expose its private secret.
Runner uid and gid must be numeric and nonzero (normally 65534:65534), timeouts
1..3600, runner.workdir=/workspace. Runner capabilities/file capabilities and
NET_RAW are unsupported. Sidecars and optional runner_network_aliases must obey
the exact task contract; sidecars exclude main/client/runner, aliases are at most
eight unique non-service names. Bind-mounted healthchecks must be executable by
the unprivileged runner, including every parent directory (normally 0755);
test that exact mount as uid 65534 rather than a root-only invocation.
For FILE-POV require public_runner with {input}; for exploit branches require exploit.py
and a meaningful effect. Missing offline binary rebuild/replacement is a blocker.
Judge task quality as well as correctness: it should exercise meaningful analysis
or interaction with the real vulnerability, not be impossible due to unrelated
environment trivia or trivialized by an artificial wrapper/oracle shortcut.
Do not edit delivery. Review the supplied evidence; do not launch the full private
differential here. The next and only orchestrator acceptance stage is Harbor.
This is a bounded review, not another synthesis session. By turn 50, stop repeating
already successful checks, finish only the remaining necessary verification, and commit
a decision by turn 70. Read targeted files rather than repeatedly dumping the full tree.
If repair-request.json exists, focus on its concrete findings and regression checks.
You must call submit_review even when the verdict is false or evidence remains limited;
never spend the entire budget without producing review.json.
Finish by calling submit_review with this exact object; the tool atomically
writes review.json. Never use a bash redirection for this file:
  "passed": true or false,
  "findings": [{"severity": "blocker|major|minor", "evidence": "file and behavior"}],
  "reason": "specific decision",
  "execution_checked": true or false
Do not pass based only on files existing, a model saying it worked, or a container
starting. A blocker or major finding means passed=false.
"""
