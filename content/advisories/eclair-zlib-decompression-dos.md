---
title: "Eclair exhausts CPU and memory decompressing a peer's channel queries"
id: LNF-2026-0002
aliases: ["/advisories/lnf-2026-0002/"]
description: "Eclair v0.13.1 and earlier still accept the zlib encoding type that BOLT 7 retired in 2022 and inflate it with no size limit, so a flood of zlib-encoded channel queries disconnects a node's peers, stalls its API and block processing, and drives the JVM out of memory within minutes."
date: 2026-09-24
found_with: variant-analysis
severity: medium
targets:
  - impl: eclair
    affected: "v0.13.1 and earlier"
    fixed_in: "v0.14.0"
    reported: 2026-03-06
    fix: https://github.com/ACINQ/eclair/pull/3263
authors: [matt]
tags: [eclair, dos, bolt7]
---

Eclair v0.13.1 and earlier accept the legacy zlib encoding type in channel query messages.
The decompression has no output limit, so a malicious 64 KB `query_short_channel_ids` message inflates to **64 MB** and decodes into **~17 million** heap objects.
An attacker that opens a few dozen connections and repeats that message continuously takes the node off the network within seconds and kills the JVM within minutes.
The attack can be easily repeated whenever Eclair restarts.

Upgrade to [Eclair v0.14.0](https://github.com/ACINQ/eclair/releases/tag/v0.14.0) or later.

## Background

Two BOLT 7 gossip messages carry a long array of short channel IDs, called `encoded_short_ids`, prefixed by an encoding byte.
Encoding type `0` is a plain array; encoding type `1` was zlib compression.

zlib was [removed from the spec](https://github.com/lightning/bolts/pull/981) in April 2022, and BOLT 7 has [prohibited](https://github.com/lightning/bolts/blob/94eb038c42e664dd7862faeec6508ccd25f63ff8/07-routing-gossip.md?plain=1#L626) encoding type `1` ever since:

> `1`: Previously used for zlib compression, this encoding MUST NOT be used.

Eclair [stopped](https://github.com/ACINQ/eclair/pull/2244) *sending* compressed data the same month, and intended to remove the receiving side as a follow-up.
That follow-up did not happen for four years.

## The vulnerability

Eclair v0.13.1 decodes `encoded_short_ids` in [`encodedShortChannelIdsCodec`](https://github.com/ACINQ/eclair/blob/28f3545af4da83bf03b16777dabc2538b30e5c9d/eclair-core/src/main/scala/fr/acinq/eclair/wire/protocol/LightningMessageCodecs.scala#L368-L376):

```scala
val encodedShortChannelIdsCodec: Codec[EncodedShortChannelIds] =
  discriminated[EncodedShortChannelIds].by(byte)
    .\(0) {
      case a@EncodedShortChannelIds(_, Nil) => a // empty list is always encoded with encoding type 'uncompressed' for compatibility with other implementations
      case a@EncodedShortChannelIds(EncodingType.UNCOMPRESSED, _) => a
    }((provide[EncodingType](EncodingType.UNCOMPRESSED) :: list(realshortchannelid)).as[EncodedShortChannelIds])
    .\(1) {
      case a@EncodedShortChannelIds(EncodingType.COMPRESSED_ZLIB, _) => a
    }((provide[EncodingType](EncodingType.COMPRESSED_ZLIB) :: zlib(list(realshortchannelid))).as[EncodedShortChannelIds])
```

`zlib()` is [scodec's compression combinator](https://github.com/scodec/scodec/blob/30f840f79ccccd13d27419ec8a8d692cc30b0a27/jvm/src/main/scala/scodec/codecs/codecsplatform.scala#L19-L26), and it [inflates](https://github.com/scodec/scodec/blob/30f840f79ccccd13d27419ec8a8d692cc30b0a27/jvm/src/main/scala/scodec/codecs/ZlibCodec.scala#L23-L27) the entire input into memory with no bound on the output size.
The only thing bounded is the *input*, which cannot exceed the 64 KB maximum Lightning message size.

The maximum zlib compression ratio is 1032:1, and an attacker can easily approach this limit using an all-zeroes payload.
At that ratio, a 64 KB payload decompresses to roughly 64 MB of zeroes.

Eclair then allocates a `RealShortChannelId` object for every 8 bytes of decompressed data, yielding ~8.4 million heap objects at 24 bytes each.
The `RealShortChannelId`s are stored in a `List[RealShortChannelId]`, which requires an additional 24-byte cons cell on the heap for each element.

The end result: **a single 64 KB message causes Eclair to allocate ~450 MB of memory**.

## The attack

An attacker opens several connections to the victim Eclair node.
On each connection, the attacker completes the BOLT 8 handshake, and exchanges `init` messages.
The attacker then floods every connection with `query_short_channel_ids` messages containing the 64 KB zlib bomb described above.

Eclair's heap fills faster than the garbage collector can handle, and the node quickly becomes unable to do anything else.

### Observed impact

Against an Eclair node with 2 CPU cores and 8 GB of RAM:

- Legitimate peers were disconnected within seconds and could not reconnect.
- The API stopped responding.
- Block processing was severely delayed.
- The JVM ran out of memory within minutes.

The node came back on restart with nothing lost, but the attacker could easily repeat the attack.
While a demonstration of theft was not attempted, the conservative assumption is that a sustained attack would make it difficult for Eclair to process on-chain events and could put funds at risk.

### Beyond `query_short_channel_ids`

`reply_channel_range` messages also reach the zlib-decompression code and thus could replace `query_short_channel_ids` as the delivery mechanism for the attack.

## The fix

[PR #3263](https://github.com/ACINQ/eclair/pull/3263), merged 2026-03-11 and released in v0.14.0, removes zlib support entirely.
[`encodedShortChannelIdsCodec`](https://github.com/ACINQ/eclair/blob/eef7c3268de307abbe853258b7196203daac5a60/eclair-core/src/main/scala/fr/acinq/eclair/wire/protocol/LightningMessageCodecs.scala#L368-L369) becomes two lines:

```scala
val encodedShortChannelIdsCodec: Codec[EncodedShortChannelIds] = discriminated[EncodedShortChannelIds].by(byte)
  .typecase(0, (provide[EncodingType](EncodingType.UNCOMPRESSED) :: list(realshortchannelid)).as[EncodedShortChannelIds])
```

A message with `encoding_type = 1` now fails to decode.

### Other implementations

LDK never implemented zlib.

CLN did implement zlib support but removed it fully in [v24.08](https://github.com/ElementsProject/lightning/commit/531845971cf94d8e5c0de67c8531578bc2656353).
While it was supported, CLN's [`unzlib()`](https://github.com/ElementsProject/lightning/blob/d60977f37f353154ea8b8d6ba83bf01e16e03315/common/decode_array.c#L7-L23) deliberately bounded the decompressed size at 1 MB:

```c
/* http://www.zlib.net/zlib_tech.html gives 1032:1 as worst-case,
 * which is 67632120 bytes for us.  But they're not encoding zeroes,
 * and each scid must be unique.  So 1MB is far more reasonable. */
unsigned long unclen = 1024*1024;
```

LND still supports zlib, but bounds overhead in three ways: a package-level mutex serializes every zlib decode in the process, decoding aborts after 100,000 short channel IDs, and the IDs must be strictly ascending -- which rejects an all-zero payload at its second element.
None of these is an explicit decompressed-size limit, but together they prevent the explosive heap growth seen with Eclair.
Removing the retired feature, as CLN and Eclair did, is the cleaner approach, and [it appears](https://github.com/lightningnetwork/lnd/pull/10980) that LND will do the same soon.

## Discovery

This bug was found during LLM-assisted variant analysis of the Eclair codebase, run after [LNF-2026-0001](/advisories/eclair-feature-parsing-dos/) and looking for the same general issue: a peer-controlled field that can impose orders of magnitude more cost on the node than the peer spends themselves.

The analysis flagged the zlib codec as a candidate, and experiments with zlib bomb floods confirmed the DoS vector.

## Timeline

- **2026-03-06:** Vulnerability reported privately to ACINQ.
- **2026-03-09:** ACINQ confirmed the issue and opened [PR #3263](https://github.com/ACINQ/eclair/pull/3263).
- **2026-03-11:** Fix merged as [PR #3263](https://github.com/ACINQ/eclair/pull/3263).
- **2026-05-21:** [Eclair v0.14.0](https://github.com/ACINQ/eclair/releases/tag/v0.14.0) released with the fix.
- **2026-09-24:** Public disclosure.

## Takeaways

- **Upgrade to Eclair v0.14.0 or later.**
- **Reduce attack surface by removing legacy code.**
- **Bound work asymmetry.**
  Peers must not be able to impose orders of magnitude more cost on a node than they spend themselves.
