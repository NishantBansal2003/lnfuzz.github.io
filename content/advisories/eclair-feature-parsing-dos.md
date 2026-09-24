---
title: "Eclair exhausts CPU and memory parsing a peer's feature bits"
id: LNF-2026-0001
aliases: ["/advisories/lnf-2026-0001/"]
description: "Eclair v0.13.1 and earlier allocate several heap objects per feature bit when parsing a message, so a flood of maximum-length init messages disconnects a node's peers, stalls its API and block processing, and drives the JVM out of memory within five minutes."
date: 2026-09-24
found_with: smite
severity: medium
targets:
  - impl: eclair
    affected: "v0.13.1 and earlier"
    fixed_in: "v0.14.0"
    reported: 2026-03-05
    fix: https://github.com/ACINQ/eclair/pull/3264
authors: [matt]
tags: [eclair, dos, bolt9]
---

Eclair v0.13.1 and earlier parse feature vectors one bit at a time, allocating several heap objects for every bit that is set.
An `init` message containing a maximum-length feature vector (~64 KB) churns **~300 MB** through the heap and occupies a parsing thread for up to **300 ms**.
An attacker that opens a few dozen connections and repeats that message continuously takes the node off the network in under a minute and kills the JVM in under five.
The attack can be easily repeated whenever Eclair restarts.

Upgrade to [Eclair v0.14.0](https://github.com/ACINQ/eclair/releases/tag/v0.14.0) or later.

## Background

Every LN node advertises its supported [features](https://github.com/lightning/bolts/blob/152897261850d93c4f4597f39cf22d7d22d6ede6/09-features.md) in an `init` message immediately after the BOLT 8 handshake.
The features field is a bit vector where each bit indicates a feature that the advertising node supports, with even bits additionally requiring connected peers to support the feature.
The vector has a `u16` length prefix, so it can be up to ~64 KB long.

## The vulnerability

Eclair v0.13.1 parses feature vectors in [`Features.apply`](https://github.com/ACINQ/eclair/blob/28f3545af4da83bf03b16777dabc2538b30e5c9d/eclair-core/src/main/scala/fr/acinq/eclair/Features.scala#L160-L170):

```scala
def apply(bits: BitVector): Features[Feature] = {
  val all = bits.toIndexedSeq.reverse.zipWithIndex.collect {
    case (true, idx) if knownFeatures.exists(_.optional == idx) => Right((knownFeatures.find(_.optional == idx).get, Optional))
    case (true, idx) if knownFeatures.exists(_.mandatory == idx) => Right((knownFeatures.find(_.mandatory == idx).get, Mandatory))
    case (true, idx) => Left(UnknownFeature(idx))
  }
  Features[Feature](
    activated = all.collect { case Right((feature, support)) => feature -> support }.toMap,
    unknown = all.collect { case Left(inf) => inf }.toSet
  )
}
```

The function iterates the feature bits, dropping any bits that aren't set and sorting the remainder into two categories: known features (`activated`) and unknown features (`unknown`).

The problem is that this code is extremely inefficient, iterating over the same bits six different times and allocating multiple objects for each bit:

| Pass | Step | Cost |
| --- | --- | --- |
| 1 | `.reverse` | materializes a `Vector` with one element per bit |
| 2 | `.zipWithIndex` | allocates a tuple and an `Integer` per bit |
| 3 | `.collect` | two linear scans of `knownFeatures` per bit, and allocates an `UnknownFeature` and a `Left` per bit |
| 4 | `all.collect { case Right(_) }` | walks all bits |
| 5 | `all.collect { case Left(_) }` | walks all bits again |
| 6 | `.toSet` | builds a hash set with one entry per bit |

On test hardware, a single maximum-length `init` message caused ~300 MB of heap churn and occupied the parsing thread for up to 300 ms.

### What compounds it

Three properties of the surrounding code multiply the cost.

**Parsing happens early.** Messages are decoded in [`TransportHandler`](https://github.com/ACINQ/eclair/blob/28f3545af4da83bf03b16777dabc2538b30e5c9d/eclair-core/src/main/scala/fr/acinq/eclair/crypto/TransportHandler.scala#L98-L119), as soon as a frame is decrypted and before any downstream actor can reject the message.

**The message is used as a map key.** `TransportHandler` tracks unacknowledged messages in a `Map[LightningMessage, Int]`, and both the insert and later access to that entry must walk all bits again.

**The parsed result is then logged in full.** An `init` arriving on an already-initialized connection is forwarded to the `Peer` actor, which [drops it with a warning](https://github.com/ACINQ/eclair/blob/28f3545af4da83bf03b16777dabc2538b30e5c9d/eclair-core/src/main/scala/fr/acinq/eclair/io/Peer.scala#L637-L639).
When logging the warning, every unknown feature bit is rendered as a [decimal index](https://github.com/ACINQ/eclair/blob/28f3545af4da83bf03b16777dabc2538b30e5c9d/eclair-core/src/main/scala/fr/acinq/eclair/Features.scala#L145-L149), which expands to a 3.5 MB line that is written to disk.

## The attack

An attacker opens several connections to the victim Eclair node.
On each connection, the attacker completes the BOLT 8 handshake, and sends an initial `init` message with features that Eclair will accept.
The attacker then floods each connection with maximum-length `init` messages.
Eclair takes up to 300 ms to process each `init`, so very quickly all the threads in the Akka thread pool become occupied with processing feature vectors, and Eclair is unable to do anything else.

### Observed impact

Against an Eclair node with 2 CPU cores and 8 GB of RAM:

- Legitimate peers were disconnected within one minute and could not reconnect.
- The API stopped responding.
- Block processing fell behind.
- The JVM ran out of memory within five minutes.

The node came back on restart with nothing lost, but the attacker could easily repeat the attack.
While a demonstration of theft was not attempted, the conservative assumption is that a sustained attack would make it difficult for Eclair to process on-chain events and could put funds at risk.

### Beyond `init`

`node_announcement` and `channel_announcement` messages also carry feature vectors whose [codecs](https://github.com/ACINQ/eclair/blob/28f3545af4da83bf03b16777dabc2538b30e5c9d/eclair-core/src/main/scala/fr/acinq/eclair/wire/protocol/LightningMessageCodecs.scala#L303-L331) use `Features.apply`, so these messages could replace `init` as the delivery mechanism for the attack.

## The fix

[PR #3264](https://github.com/ACINQ/eclair/pull/3264), merged 2026-03-17 and released in v0.14.0, redesigns [`Features.apply`](https://github.com/ACINQ/eclair/blob/a4f4abd94a5e7a7dc6b9c69cb9be69e598c53f65/eclair-core/src/main/scala/fr/acinq/eclair/Features.scala#L236-L253) significantly:

```scala
def apply(bytes: ByteVector): Features[Feature] = {
  if (bytes.isEmpty) {
    Features.empty
  } else {
    // We extract all official features we support.
    val encoded = EncodedFeatures(bytes)
    val activated = knownFeatures.flatMap {
      case f if encoded.hasFeatureBit(f.optional) => Some(f -> FeatureSupport.Optional)
      case f if encoded.hasFeatureBit(f.mandatory) => Some(f -> FeatureSupport.Mandatory)
      case _ => None
    }
    Features[Feature](
      activated = activated.toMap,
      // Note that we keep all feature bits to allow checking whether plugin features are activated.
      encoded_opt = Some(encoded),
    )
  }
}
```

Rather than repeatedly iterating the long feature vector (up to 64K * 8 = 512K elements), the loop has been turned inside out, and the short `knownFeatures` vector (34 elements) is iterated instead.
Additionally, unknown feature bits remain in bit-vector form rather than being extracted into newly-allocated objects.
All per-bit allocations are eliminated.

The 3.5 MB log line is gone because the unknown feature bits are no longer printed, and `TransportHandler` map access cost is reduced because the feature bytes are hashed directly instead of chasing pointers through 512K heap objects.

On test hardware, a single maximum-length `init` message is processed in 1-2 ms and causes ~200 KB of heap churn.

## Discovery

smite found this performance issue with its most primitive `encrypted_bytes` scenario.
The scenario simply completes a BOLT 8 handshake, sends the fuzzer's raw bytes as a single Lightning message, and then sends a ping and waits for the pong.
If the pong response takes too long, smite flags the corresponding input.

smite flagged such an input during an Eclair fuzzing campaign, and it happened to be an `init` message with a large feature vector.
Benchmarks confirmed the root cause and experiments confirmed the DoS impact.

## Timeline

- **2026-03-05:** Vulnerability reported privately to ACINQ.
- **2026-03-06:** ACINQ reproduced the issue and confirmed the root cause.
- **2026-03-10:** Agreement on a public disclosure roughly six months after the fix lands.
- **2026-03-17:** Fix merged as [PR #3264](https://github.com/ACINQ/eclair/pull/3264).
- **2026-05-21:** [Eclair v0.14.0](https://github.com/ACINQ/eclair/releases/tag/v0.14.0) released with the fix.
- **2026-09-24:** Public disclosure.

## Takeaways

- **Upgrade to Eclair v0.14.0 or later.**
- **Bound work asymmetry.**
  Peers must not be able to impose orders of magnitude more cost on a node than they spend themselves.
