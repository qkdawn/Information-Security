# Applied Cryptography: Subverted Digest Authentication

Draft status: team name and member names must be supplied before producing the required one-page report.pdf.

## Vulnerability and location

In `digest_auth_subverted.py`, `DigestAuthSubvertedMiddleware.__call__` reads the optional integer `bits` Authorization field (line 26), calculates `width = bits // 4` (line 28), checks `0 < bits <= 256` (line 33), and compares digest prefixes using `hmac.compare_digest(...[:width], response[:width])` (line 34). The range check applies to bits rather than the derived number of hexadecimal characters. Accepted values 1, 2 and 3 therefore produce a zero-character width: both slices are empty and compare equal regardless of the supplied password. Username lookup still occurs, so the account must exist. The response must still be a complete 64-character hexadecimal value with a supported algorithm. Both client and server now permit only 1–256 bits; zero and values above 256 are rejected.

## Reproduction

Start the supplied `start_server_subverted.py` from the server directory, then run `python client_subverted.py --precision 3 http://127.0.0.1:8080/README.md`. Enter any registered username and any incorrect password. The client still prompts for both credentials and hashes the entered password, satisfying R5. It sends the complete digest plus `bits=3`; the server returns HTTP 200 and the resource content. Without the option, the same incorrect credentials return 401. The secure server rejects the incorrect credentials even when the extra field is present. No hard-coded account or stored password is needed.

## Covertness and limits

The extension is presented as optional digest comparison precision, an additional Authorization field permitted by the assignment. There is no claim about historical clients. The default remains 256 bits, and ordinary successful and failed login cases behave as expected. The source checks a positive bounded input, a complete response format, an existing account, and uses constant-time comparison. A superficial review may overlook that positive input does not imply positive comparison width after unit conversion. However, client-selected comparison precision is itself suspicious in authentication, and tests at 1–3 bits expose the bypass. Rejecting out-of-range inputs removes inconsistent behavior; it is not evidence that independent reviewers will miss the vulnerability. Only the subverted authentication source is distributed in Part 2 according to the assignment.

## Design comparison and technical basis

A fixed master password embeds a recognizable secret and requires an additional acceptance condition. A hard-coded privileged username fails the arbitrary-registered-user requirement. Ignoring selected digest characters still requires matching a nonempty prefix unless the comparison length collapses to zero. The implemented design instead uses Python's floor-division and slicing behavior: `3 // 4 == 0`, `value[:0] == ""`, and equal empty strings compare successfully. Python documents these behaviors in [built-in types](https://docs.python.org/3/library/stdtypes.html) and [hmac.compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest). These alternatives are design comparisons, not claims of separately implemented experiments.

## Validation and remediation

On 15 November 2026, all 67 tests passed without skips on Windows and local WSL Ubuntu. Tests cover normal authentication, arbitrary registered accounts, unknown accounts, bit-count boundaries, full response formatting, the secure server's rejection of the same trigger, real HTTP retrieval, interactive credential prompts, legacy-terminal Unicode output, and clean process exit after a closed output pipe. The supplied launch scripts also build handlers that pass real HTTP retrieval and rejection checks. A deterministic response matching the first 63 hex characters but differing at the last character is rejected by the secure version even with `bits=252`; the subverted version accepts it at that precision. The middleware remains independently importable and contains 61 counted characters (29 opening parentheses, 11 colons, 21 commas), including comments and strings. This is below 65 but does not guarantee a ranking-based mark. WSL testing is not verification on a QMB lab PC. A secure correction is to enforce the full SHA256 digest comparison independently of client metadata; merely preventing zero-length comparisons still leaves client-selected short prefixes weak.
