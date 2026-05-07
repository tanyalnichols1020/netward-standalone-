# Security Policy

Net Ward is a passive deception layer for HTTP/network services. It sits
on the request path of host applications and is trusted to fail safe and
fail open. A vulnerability in Net Ward could undermine the availability
or integrity of any service it protects, so we treat reports seriously
and respond quickly.

## Supported Versions

| Version | Status              | Receives security fixes |
|---------|---------------------|--------------------------|
| 0.4.x   | Current alpha       | Yes                      |
| 0.3.x   | Superseded          | No — upgrade to 0.4.x    |
| 0.2.x   | Superseded          | No — upgrade to 0.4.x    |
| 0.1.x   | Superseded          | No — upgrade to 0.4.x    |
| 0.0.x   | Schema-only sketch  | No                       |

Until Net Ward reaches 1.0, only the latest 0.x release line receives
security fixes. Operators on older 0.x versions should upgrade to the
current alpha to receive patches.

## Pre-Launch Security Review

Net Ward v0.4.1 underwent an internal pre-launch security review before
release. The review covered network-visible fingerprinting, detection
logic, install and upgrade paths, supply-chain exposure, and runtime
resource behavior under sustained load.

The review identified three critical findings before launch. All three
were closed in v0.4.1 before release. See the `[0.4.1]` section of
`CHANGELOG.md` for the specific patches and known limitations that remain
for operators to consider.

Operators who discover new security issues should follow the private
reporting process below rather than opening a public issue.

## Reporting a Vulnerability

**Do not file a public GitHub issue for a security report.** Public
disclosure before a fix is available exposes every Net Ward operator to
the same vulnerability simultaneously.

To report a vulnerability, contact the security team privately:

- **Email:** `security@netward.example` *(operator: replace with your
  organization's intake address before public release)*
- **Subject line:** `[NETWARD SECURITY] <short description>`
- **Encryption:** PGP key forthcoming; for now, summarize the issue
  without including a working exploit in the email body. We will reply
  with a secure channel for follow-up.

### What to include

A useful report contains:

1. The Net Ward version affected (`pip show netward` or the git commit hash)
2. The deployment topology (reverse proxy / sidecar / Docker / etc.)
3. The vulnerability class (e.g., classification bypass, mirror response
   leakage, mesh trust violation, denial-of-service against the host)
4. A minimal reproduction — request shape, configuration excerpt, or
   probe sequence — that demonstrates the issue
5. Expected vs. actual behavior
6. Any mitigation the reporter has identified

### What NOT to do

- Do not run live exploits against systems you do not own
- Do not exfiltrate data from a host application that Net Ward is
  protecting; a proof-of-concept against a controlled test deployment
  is sufficient
- Do not publish a write-up before we have published a patch
- Do not include real credentials, real PII, or real customer data in
  the report; sanitize before sending

## Response SLA

We commit to the following response timeline for any report received
through the security contact above:

| Step                                 | Target          |
|--------------------------------------|------------------|
| Acknowledgement of receipt           | Within 3 days    |
| Initial triage and severity decision | Within 7 days    |
| Patch availability (high/critical)   | Within 30 days   |
| Patch availability (medium/low)      | Best effort      |
| Public advisory (after patch)        | Coordinated date |

Severity follows CVSS v3.1. Issues that compromise the host application
the operator is protecting are always considered critical, regardless
of CVSS score.

## Scope

In scope:

- The `netward` Python package and all modules under `netward/`
- The shipped vendor pattern set (`netward/data/vendor_patterns.json`)
- The Docker image build defined by `netward/Dockerfile`
- The CLI tools (`netward.__main__`, `netward.cli`)

Out of scope:

- Vulnerabilities in `aiohttp`, `pynacl`, sqlite, or other upstream
  dependencies — please report those to the respective maintainers
  directly. Net Ward will track upstream advisories and pin to fixed
  versions when patches are released.
- Configurations the operator has explicitly opted into that disable
  Net Ward's safety guards (e.g., custom mirror responses bypassing
  the PII rejection regex)
- Issues in services Net Ward is protecting (the host application);
  Net Ward is not responsible for the security of upstream services

## Coordinated Disclosure

We follow a 90-day coordinated disclosure window for high and critical
issues. The clock starts when a report is acknowledged. We will:

1. Work with the reporter to understand and reproduce the issue
2. Develop and test a patch
3. Notify operators of the upcoming release with a non-technical
   advisory (so they can prepare for upgrade)
4. Publish the patched release
5. After at least 7 days for operators to upgrade, publish the full
   technical advisory crediting the reporter (unless they prefer to
   remain anonymous)

## Reporter Recognition

Reporters who follow this policy are eligible for credit in the public
advisory and the project CHANGELOG. We do not currently offer a paid
bug bounty.

## Operator Responsibilities

Net Ward is fail-safe by design but operators are responsible for:

- Running Net Ward as a non-root user (the Docker image does this; bare
  installs should follow suit)
- Mounting the operator config from a path Net Ward does not write to
- Reviewing the vendor pattern set before deployment and disabling any
  pattern that conflicts with the host application's legitimate paths
- Keeping the Net Ward version current within the supported range

## Security Posture Going Forward

Mesh-related vulnerabilities (cross-node intel propagation, signed
payload validation) become in-scope when the mesh layer is implemented
(targeted for v0.5). Until then, Net Ward operates as single-node only
and the mesh-related modules remain placeholders.
