# Public document root

Only files in this directory are reachable through the authenticated server
started by `tests/run_secure_server.py`. Keep passwords.txt, client sources and
server sources outside this directory.

The supplied course launchers `start_server_digest.py` and
`start_server_subverted.py` are teacher-provided files that must stay byte-for-byte
identical to their `doc/` originals, so they still expose the whole
`py-http-server` directory. Use `run_secure_server.py` whenever the isolation
matters.
