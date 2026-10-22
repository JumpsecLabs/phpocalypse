# phpocalypse
Read-only triage script for the PHP2Shell vulnerabilities (CVE-2026-109618, CVE-2026-109619).

Run it on a Linux web server to check for signs of exploitation and collect the files needed for a closer look. It checks relevant PHP settings, examines session files and logs, and copies any suspicious files into the results. Everything is packaged into a single ZIP archive.

The script does not change the original files or settings, and it does not send anything over the network. You decide where the ZIP goes.

If you're handing the results to someone else, send them the archive. If you're reviewing them yourself, start with `findings/findings.txt`.

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

**Chain B** involves a separate `unserialize` / `var_destroy` memory-safety issue. phpocalypse does not check for that chain.

Chains A and C can leave evidence in session files and logs. The script looks for that evidence, although it may not always be present by the time the check is run.

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

Run the script once on each host you want to assess. Each run produces a separate ZIP named after the host.

### Containers

Some containers write PHP and web server logs to standard output rather than to files inside the container. Those logs may only be available from the container runtime. If the script identifies this as a gap, collect the container logs separately, for example:

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

The main files to look at are:
 
- `findings/findings.txt` â€” the result and a readable summary of the checks.
- `findings/findings.json` â€” the same findings in a format that can be processed automatically.
- `findings/artifacts/` â€” copies of suspicious files, where any were found, together with hashes and original modification times.
- `manifest.json` â€” what was collected and what couldn't be accessed.

## Understanding the result

The script reports one of three outcomes:

- **INDICATORS FOUND** a poisoned session file or a known log signature was seen.
 Treat the host as a suspected compromise, preserve it, and escalate.
- **NO INDICATORS** nothing known was found in what was collected. Not a clean
 bill of health; weigh it against your other telemetry.
- **INCOMPLETE** the run couldn't read everything (usually: not run as root).
 `manifest.json` lists the gaps. Re-run with `sudo` for a complete picture.

PHP configuration checks are reported separately. For example, the script may flag `session.upload_progress` as enabled even when it finds no indicators of compromise. A configuration finding is not, on its own, evidence of exploitation.

## Getting results reviewed

phpocalypse is intended for initial triage. Its findings need to be considered alongside other evidence, and it is not a substitute for a full incident investigation.

If you're a JUMPSEC client, upload the ZIP through the JSEC portal for review. Otherwise, you can review the `findings/` directory yourself or share the archive with your incident response team.

For instructions you can pass directly to a server owner, see [`INSTRUCTIONS.txt`](INSTRUCTIONS.txt).

## Safety

- The script does not modify PHP settings, rotate logs or remove files.
- It does not make network connections or upload results.
- Suspicious files are copied into the archive, not moved or deleted. The originals remain on the host.

The ZIP may contain sensitive information, including request data, session contents and IP addresses. Store and share it securely.

## Limitations

- The script looks for evidence associated with **Chains A and C** in files and logs. It will not identify every possible exploitation method, including activity that leaves only in-memory evidence.
- Detection depends on the evidence still being available. In particular, **Chain C** may remove some of its own traces. A session-file scan with no matches does not negate a suspicious error-log entry.
- Missing logs, rotated data and restricted permissions can all limit what the script can assess. Check `manifest.json` before drawing conclusions from a negative result.

## License

[Apache-2.0](LICENSE). Copyright JUMPSEC Ltd.
