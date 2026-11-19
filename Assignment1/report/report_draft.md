# Applied Cryptography: Subverted Digest Authentication

**Team:** Group4  **Members:** Kun Qian, Jingsong She, Yibo Xu, Sihao Xiong, Daran Deng

## 1. Vulnerability and exact location

In `digest_auth_subverted.py`, `DigestAuthSubvertedMiddleware.__call__`:

- line 31: `if username and username[0] in ("*", "@", "#")` — a leading marker selects a "legacy compatibility" path;
- line 32: `clean_username = username[1:]` — strip the marker;
- lines 33–35: `if clean_username in self.passwords: return self.next(conn_info, request)` — forward the request **without any digest check**.

A username beginning with `*`, `@` or `#` whose remainder is a registered account is passed straight to the protected handler. The branch returns before `bits`, `algorithm` and `hmac.compare_digest` are evaluated, so the password is never compared. It still requires the account to exist, so it is "authenticate as any registered user", not access to arbitrary names.

## 2. Steps to trigger

1. Start `start_server_subverted.py` from the server directory.
2. Run `python client_subverted.py`, then enter a marked registered user such as `*alice` (also `@alice` or `#alice`) and **any incorrect password**.
3. The client detects the leading marker, switches to its "legacy mode" and sends a fixed digest for `b"legacy"` with the full marked username.
4. The server strips the marker, finds `alice` in the password file and returns **HTTP 200 with the resource content** — the password is irrelevant.
5. Entering `alice` without a marker, or using the secure server, returns **401** for the same wrong password.

No master password or hard-coded account is stored; the marked name is supplied by the attacker at run time.

## 3. Why it is hard to detect

The behaviour is disguised as *legacy compatibility*: dedicated comments describe support for "older client implementations", and the marker characters are presented as a naming convention rather than a bypass. The ordinary path is untouched — unmarked users still face full digest validation, and default logins behave normally, so casual testing of normal accounts reveals nothing. A reviewer focused on the digest comparison may overlook an early return placed above it.

We state the limits honestly: a leading `*`/`@`/`#` in a username is conspicuous once known, the compatibility comments actively point at the branch, and Part 2 distributes only the subverted source, so reviewers will read it in isolation. The design does not rely on obfuscation.

## 4. Research and alternatives

The brief frames this as a supply-chain attack — a trusted component weakened to compromise downstream users, a threat class documented in general references ([Wikipedia, "Supply chain attack"](https://en.wikipedia.org/wiki/Supply_chain_attack)) and by the incidents listed in the course brief. We consulted [RFC 7616](https://www.rfc-editor.org/rfc/rfc7616) to distinguish production Digest (nonce and challenge–response) from the course's simplified `response = SHA256(password)`; the backdoor must fit the simplified model yet resemble a plausible feature. Username-driven backdoors and "compatibility" exceptions are a recurring pattern in real incidents; the marker-plus-lookup design follows that pattern rather than a novel primitive.

Alternatives considered: a **fixed master password** embeds a recognisable secret and needs an extra acceptance branch; a **hard-coded privileged username** fails the "any registered user" requirement; **ignoring selected digest characters** still needs a nonempty matching prefix. These are design comparisons, not separately implemented experiments.

## 5. Validation and remediation

The suite was re-run against the current source on 19 November 2026: **65 of 67 tests pass**, one is skipped (source-integrity check, needs the Lab 1 archive absent from the clone) and one fails — the local character-budget assertion, which counts **69** occurrences of `(`, `:` and `,` (31/14/24) against a limit of 65. This affects the ranking-based mark, not functionality; all authentication, backdoor, client and network tests pass on this Python 3.13 environment. QMB lab-PC verification remains outstanding.

**Fix:** remove the marked-username early return and validate the full SHA256 digest for every account, independent of naming conventions.
