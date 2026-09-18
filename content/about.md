---
title: "About"
description: "We are a group of security researchers and developers working to improve the security and robustness of the Bitcoin Lightning Network."
---

We use fuzzing and other techniques to find bugs, [publishing](/bugs/) them on
this site along with [advisories](/advisories/) for security issues. We also
write [technical posts](/posts/) about our fuzzing tools and techniques.

## Why

The Lightning Network's four main implementations (LND, Core Lightning, LDK,
and Eclair) all speak the same peer protocol. They have to interoperate with
each other, and they have to hold up against a peer that is not playing along.
Both of those are hard to get right, and neither is well covered by the tests a
project writes for itself, which tend to assume a well-behaved peer.

That is the gap our tooling helps to address. Our fuzzing tools can play the
role of a misbehaving peer, triggering unusual code paths and edge cases. This
approach uncovers many kinds of issues, ranging from protocol violations to
crashes and assertion failures, memory safety errors, and more.

## Projects

**[smite](/projects/smite/)** is a coverage-guided snapshot fuzzer that drives
all four implementations through the peer protocol.

## Contact

For any problem with this site, including a correction to an advisory, create an
issue on
[this site's repository](https://github.com/lnfuzz/lnfuzz.github.io/issues).
Anything about one of our projects should be filed on that project's own
tracker, such as [lnfuzz/smite](https://github.com/lnfuzz/smite/issues).

Every page on this site names its own authors, who retain copyright in what they
write.
