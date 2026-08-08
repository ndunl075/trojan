# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/ndunl075/trojan/security/advisories/new)
rather than opening a public issue.

Include a proof-of-concept file if you have one — for this project that is
usually a small repository or a single file that reproduces the behaviour.

## Threat model

`trojan` reads attacker-controlled text by design. Anything in a scanned
repository is untrusted input, so the following are treated as vulnerabilities:

- **Detector suppression.** A crafted file that stops a rule from running, or
  that causes a real payload elsewhere in the same file to go unreported.
- **Silent failure.** Any path where coverage is reduced without the report
  saying so. A scanner that quietly checks less than you think is worse than
  one that errors out.
- **Denial of service.** Input that causes unbounded CPU or memory use —
  catastrophic regex backtracking, quadratic reporting, unbounded decoding.
- **Escaping the scan root.** Reading or writing outside the target directory.
- **Any network activity.** The tool makes no outbound connections. A build
  that does is a vulnerability regardless of what it connects to.

Run `node scripts/stress.js` after changing any rule; it exercises the
detectors against near-miss and pathological inputs with a time budget.

## Not vulnerabilities

- **A missed injection phrased in a novel way.** This is a pattern matcher, not
  an oracle. New fingerprints are welcome as ordinary pull requests.
- **False positives on unusual but legitimate code.** Also welcome as ordinary
  issues; the baseline and allowlist mechanisms exist for this.
- **Slow scans caused by scanning genuinely enormous repositories.** Use
  `--exclude` and `--max-file-size`.

## Supported versions

The latest published minor version receives security fixes.
