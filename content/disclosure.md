---
title: "Disclosure policy"
description: "What we do when we find a bug in a Lightning Network implementation."
---

## What we report, and where

Every confirmed bug is reported upstream to the affected project.

**Ordinary bugs** are filed as public issues. They are added to the [bugs page](/bugs/) when filed.

**Security vulnerabilities** are reported privately first, through whatever
private channel the project prefers, and are not mentioned anywhere public until
the embargo ends.

## Timeline

We coordinate with upstream maintainers to establish safe disclosure timelines.
In practice our embargoes have usually run considerably longer than the 90-day
industry standard, and for serious vulnerabilities embargoes can run for six to
twelve months at the maintainers' request.

The reasons are good ones. A patched release is not a patched network: node
operators upgrade slowly, and significant funds are often at risk in the
meantime.

What we will not do is let a report sit indefinitely because it is inconvenient.
**We reserve the right to publish vulnerability details 90 days after our
initial report** and will exercise this right if the issue is not being
adequately addressed. This deadline is intended to keep maintainers accountable
and is not something we are eager to reach. We would rather extend an embargo
for a project that is actively working on a fix.

We will also publish details earlier than agreed if a vulnerability is being
exploited in the wild or if someone else discloses it first.

## Several implementations at once

A single specification ambiguity often produces the same bug in more than one
implementation. When this happens we report to every affected project before
publishing anything, and the 90-day clock runs from the *last* report.

## What an advisory contains

Enough detail for an operator to judge whether they are affected and for a
reviewer to verify the fix. Details generally include the affected versions, a
description of the bug, the conditions needed to reach the bug, and how the bug
can be exploited by an attacker.

## Corrections

If you maintain an affected project and we have a detail wrong, please open an
issue on
[this site's repository](https://github.com/lnfuzz/lnfuzz.github.io/issues) so
we can correct it.

## Credit

Most of our findings are the result of work from many contributors -- the
researcher who investigated and reported a bug may not be the one who uncovered
the bug by fuzzing, and many other developers may have contributed to the fuzzer
features that enabled discovery of the bug. If we were to credit everyone
remotely involved, the list would be too long.

Instead, advisories simply name whoever investigated and reported the bug. If
another person also contributed in a notable way, or if a particular piece of
tooling was clearly what made the bug reachable, the advisory says so.

Contributions to the fuzzers themselves are recorded in the corresponding
[repository](https://github.com/lnfuzz/smite/graphs/contributors).

## Findings by other people

Our tools are open source, and a bug you find with them is yours. This policy
binds us, not you: report it however you judge best, on whatever timeline you
agree with the project.

If you would like the write-up hosted here once it is safe to publish, open a
pull request. Your name goes on it and you keep your copyright.
