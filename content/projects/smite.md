---
title: "smite"
description: "A coverage-guided snapshot fuzzer for Lightning Network implementations."
found_with: smite
source: https://github.com/lnfuzz/smite
date: 2026-09-18
---

smite is a coverage-guided snapshot fuzzer for Lightning Network
implementations. It drives LND, Core Lightning, LDK and Eclair through the peer
protocol and checks how they handle the messages it sends them.

## How it works

A conventional protocol fuzzer spends most of its time re-establishing state:
starting a node, connecting a peer, and replaying the handshake before it can
send the one message it wants to test. smite snapshots the target once it has
reached an interesting state and restores that snapshot for every subsequent
test case, so the fuzzing time goes into the messages that matter rather than
into setup.

Coverage feedback from the target guides input generation. Oracles then check
how the target behaves against the BOLT specification, flagging any
non-compliance. smite can also detect the usual target crashes, assertion
failures, memory safety errors, and undefined behaviour that traditional fuzzers
are expected to turn up.

## Findings

Bugs smite has found. Security findings also get a full write-up under [advisories](/advisories/).
