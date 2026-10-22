# phpocalypse
Read-only triage script for the PHP2Shell vulnerabilities (CVE-2026-109618, CVE-2026-109619).

Point it at a Linux web server and it gathers the logs and session data needed to
judge whether the host was targeted, checks the PHP settings that make the bug
exploitable, flags and quarantines any suspicious session files, and drops
everything into a single `.zip`. It does not change anything on the host and does
not phone home the only thing it writes is the output archive.

If you just need to hand a server over to someone for review, run it and send the
zip. If you're triaging yourself, the `findings/` directory gives you a verdict and
the matched artefacts up front.

## Background

`session.upload_progress` lets a client write attacker-controlled data (including
the upload filename) straight into PHP session files, with no sanitisation. Three
chains come out of that:

- **Chain A** the filename lands in the session file verbatim, so `<?php ... ?>`
 ends up on disk; combined with any local file include in the app, that's
 pre-auth RCE.
- **Chain C** a `session.serialize_handler` mismatch between two directories that
 share a save path lets a serialized object be smuggled in after a `|`, triggering
 object injection / a POP gadget on decode.
- Chain B (an `unserialize`/`var_destroy` memory-safety bug) is a separate,
 harder-to-weaponise path and is not what this tool keys on.

The reliable, in-the-wild paths are A and C, and both leave traces on disk and in
logs. phpocalypse looks for those.

## Requirements

- A Linux host (Debian/Ubuntu, RHEL/CentOS/Alma, or a PHP container).
- POSIX `sh`. No other dependencies it uses whatever is already present
 (`sha256sum`/`shasum`/`openssl`, `zip`/`python`/`jar`/`tar` for packaging).
- Root is strongly recommended. Without it the script still runs, but logs it
 can't read are recorded as coverage gaps and the verdict is marked incomplete.

## Usage

```sh
sudo sh phpocalypse-triage.sh
```

Options:

```
-o DIR  write the output zip to DIR (default: current directory)
-q    quieter console output
-h    help
```

It finishes with a result block:

```
 VERDICT : NO INDICATORS
 BUNDLE : /root/phpocalypse-web01-20261021T154400Z.zip
 SHA-256 : 0289...b5a6
```

Run it once per host. Each run produces its own zip named after the hostname.

### Containers

Run it inside the container. PHP/web logs are often written to the container's
stdout and captured by the runtime on the host instead of inside the filesystem 
if so, the bundle includes a notice, and you should also grab:

```sh
docker logs <container-name> > <container-name>.stdout.log 2>&1
```

## What's in the bundle

```
phpocalypse-<hostname>-<timestamp>.zip
 manifest.json  inventory of everything collected, with SHA-256 and a
         per-source status (collected / empty / unreadable / absent)
 web/      Apache / httpd / nginx access and error logs
 php/      PHP config summary, ini and FPM pool files, application logs
 system/     syslog, journal, kernel, auth, audit, cron
 security/    modsecurity / fail2ban / SELinux / firewall state where present
 findings/    verdict, machine-readable results, quarantined artefacts
```

`findings/findings.txt` leads with the verdict. `findings/findings.json` is the
same result in a parseable form. Anything the scan flagged is copied, read-only,
into `findings/artifacts/` with its hash and original mtime.

## Reading the verdict

- **INDICATORS FOUND** a poisoned session file or a known log signature was seen.
 Treat the host as a suspected compromise, preserve it, and escalate.
- **NO INDICATORS** nothing known was found in what was collected. Not a clean
 bill of health; weigh it against your other telemetry.
- **INCOMPLETE** the run couldn't read everything (usually: not run as root).
 `manifest.json` lists the gaps. Re-run with `sudo` for a complete picture.

The config check is separate from the verdict: a host with no indicators can still
come back with recommendations (e.g. `upload_progress` still on) that are worth
acting on regardless.

## Getting results reviewed

This tool collects; it doesn't adjudicate edge cases. JUMPSEC runs review and
incident response for this event. Anyone else can read `findings/` directly or pass the bundle to their own
responder.

See [`INSTRUCTIONS.txt`](INSTRUCTIONS.txt) for a short, non-technical runbook you
can forward to a server owner.

## Safety

- Read-only. It never edits a setting, rotates a log, or deletes anything.
- No network activity. Nothing leaves the host until you send the zip.
- Suspicious files are copied, never moved or modified; originals stay in place.

Collected logs can contain IP addresses and request data. Handle the bundle
accordingly.

## Limitations

- It detects the on-disk and log evidence of Chains A and C. It does not detect
 in-memory-only exploitation, and absence of indicators is not proof of safety.
- Session-file detection depends on the evidence still being present Chain C is
 partly self-cleaning, so a clean scan with a matching error-log signature still
 warrants review.

## License

[Apache-2.0](LICENSE). Copyright JUMPSEC Ltd.
