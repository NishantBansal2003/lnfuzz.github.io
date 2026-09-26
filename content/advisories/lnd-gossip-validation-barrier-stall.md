---
title: "LND stops processing gossip after malformed channel announcements"
id: LNF-2026-0003
aliases: ["/advisories/lnf-2026-0003/"]
description: "LND v0.19.0 through v0.20.x leak a gossip validation slot for each malformed channel_announcement with equal node IDs, so a flood of 1,000 such messages stalls the gossiper and cuts the node off from the routing network."
date: 2026-09-25
found_with: "LND's gossip fuzz target and smite"
severity: low
targets:
  - impl: lnd
    affected: "v0.19.0 through v0.20.x"
    fixed_in: "v0.21.0"
    reported: 2026-02-05
    fix:
      - https://github.com/lightningnetwork/lnd/pull/10540
      - https://github.com/lightningnetwork/lnd/pull/10589
authors: [nishant, matt]
tags: [lnd, deadlock, bolt7]
---

LND v0.19.0 through v0.20.x can send two validation results for a gossip message on a channel that has room for only one.
The goroutine processing the message blocks forever and never releases its slot in the gossiper's validation barrier, which limits in-flight gossip processing to 1,000 messages.
An attacker that sends **1,000** such announcements occupies every slot, causing the node to stop processing gossip entirely, effectively cutting it off from the routing network.
LND keeps running but hangs on graceful shutdown, so the operator must kill it to recover, and the attack can be easily repeated after it restarts.

Upgrade to [LND v0.21.0](https://github.com/lightningnetwork/lnd/releases/tag/v0.21.0-beta) or later.
v0.20.1 through v0.20.4 fix the direct attack but are still vulnerable to a [delayed variant](#the-delayed-variant).

## Background

Nodes learn the channel graph from [BOLT 7](https://github.com/lightning/bolts/blob/152897261850d93c4f4597f39cf22d7d22d6ede6/07-routing-gossip.md) gossip.
A `channel_announcement` identifies a channel by its `short_channel_id` and names its two endpoints, `node_id_1` and `node_id_2`.

LND processes each incoming gossip message in its own goroutine.
Before starting one, the gossiper's `ValidationBarrier` reserves one of [1,000 slots](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/gossiper.go#L602) and records which messages depend on which, e.g. a `channel_update` waits for its `channel_announcement`.
A `channel_announcement` is registered under three keys: its `short_channel_id`, `node_id_1`, and `node_id_2`.

Each message also carries an error channel, a Go channel for its processing result.
For messages from peers, [`ProcessRemoteAnnouncement`](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/gossiper.go#L883) creates it with a buffer of one, and nothing reads from it.

## The vulnerability

LND v0.19.0 through v0.20.x process each gossip message and then notify its dependent jobs in [`handleNetworkMessages`](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/gossiper.go#L1629-L1687):

```go
func (d *AuthenticatedGossiper) handleNetworkMessages(ctx context.Context,
	nMsg *networkMsg, deDuped *deDupedAnnouncements, jobID JobID) {
	// ... mark the goroutine done on return.
	defer d.finalizeGossipProcessing(ctx, "processing", nMsg, &jobID)
	// ... wait for this message's parent jobs to finish.
	newAnns, allow := d.processNetworkAnnouncement(ctx, nMsg)
	// ... log the processing result.
	err = d.vb.SignalDependents(nMsg.msg, jobID)
	if err != nil {
		// ... log the error.
		nMsg.err <- err

		return
	}
	// ... queue newAnns for broadcast.
}
```

For a `channel_announcement`, `processNetworkAnnouncement` calls [`handleChanAnnouncement`](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/gossiper.go#L2679-L3110), which sends exactly one result on the `nMsg.err` channel, such as the error when the announcement [fails validation](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/gossiper.go#L2783-L2799).
That result fills the channel's buffer.
If `SignalDependents` then fails, its error is a second send on `nMsg.err`, which blocks forever because nothing reads from the channel.

`SignalDependents` fails when `node_id_1 == node_id_2`.
It [removes the job under each of the three keys](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/validation_barrier.go#L428-L445), but with equal node IDs the job was registered under only two.
The removal under `node_id_1` deletes the node ID's entry, so the removal under `node_id_2` [finds nothing and returns an error](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/validation_barrier.go#L377-L383).

Because the goroutine never returns, the deferred `finalizeGossipProcessing` never [calls `CompleteJob`](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/gossiper.go#L1702), so its validation barrier slot is never released.
Once all 1,000 slots have leaked, the gossiper's main loop blocks forever in [`InitJobDependencies`](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/validation_barrier.go#L100-L110) waiting for a free slot.

## The attack

An attacker connects to the victim LND node, completes the BOLT 8 handshake, and exchanges `init` messages.
The attacker then sends 1,000 `channel_announcement` messages with `node_id_1 == node_id_2` and at least one other invalid field, such as `bitcoin_key_1`, so no real channel is needed.
Each message uses a different `short_channel_id` and node ID, so LND's [reject cache](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/gossiper.go#L1554-L1564) does not drop it and no other in-flight job [keeps its node ID's entry alive](https://github.com/lightningnetwork/lnd/blob/eaa7bcf67ad1ed9884ca6aad3931c2b9dc81bbeb/discovery/validation_barrier.go#L114-L123).

Each message leaks a validation barrier slot, and once all 1,000 have leaked, the gossiper stops processing gossip from every peer.

### Observed impact

From then on, anything that hands the gossiper an announcement or update blocks:

- The graph goes stale and the node's channels become effectively private, so it can no longer find routes or forward payments.
- Each peer connection freezes once its `Brontide` gossip queue fills (~50 messages), then times out.
- The funding manager hangs announcing new channels, so channel opens never complete.
- `ChanStatusManager` hangs, so channels can't be enabled or disabled and force closes hang.
- Graceful shutdown hangs.

A restart clears the stall, but the attacker can easily repeat the attack.
LND still handles on-chain events, including expiring HTLCs, so funds are not at risk.

### The delayed variant

The same leak can also be triggered with a delay.
If a `channel_announcement` references a block the victim hasn't reached yet, [`isPremature`](https://github.com/lightningnetwork/lnd/blob/f9e3825601755701a1d5887d7ea0289776544d7f/discovery/gossiper.go#L2201-L2252) caches a copy with a new error channel that has [a buffer of one](https://github.com/lightningnetwork/lnd/blob/f9e3825601755701a1d5887d7ea0289776544d7f/discovery/gossiper.go#L2231).
When that block arrives, [`resendFutureMessages`](https://github.com/lightningnetwork/lnd/blob/f9e3825601755701a1d5887d7ea0289776544d7f/discovery/gossiper.go#L793-L835) reprocesses the copy, its [second send](https://github.com/lightningnetwork/lnd/blob/f9e3825601755701a1d5887d7ea0289776544d7f/discovery/gossiper.go#L1673-L1679) blocks forever, and its validation barrier slot leaks.

The attack is the same as [above](#the-attack), except each `short_channel_id` refers to a future block height, so the slots leak once the victim reaches it.

## The fix

[PR #10540](https://github.com/lightningnetwork/lnd/pull/10540), merged 2026-02-04 and backported to v0.20.1 in [PR #10554](https://github.com/lightningnetwork/lnd/pull/10554), gives `ProcessRemoteAnnouncement`'s error channel [a buffer of two](https://github.com/lightningnetwork/lnd/blob/f9e3825601755701a1d5887d7ea0289776544d7f/discovery/gossiper.go#L890).
That stops the direct attack, but cached premature announcements still get an error channel with a buffer of one, leaving v0.20.1 through v0.20.4 open to the [delayed variant](#the-delayed-variant).
[Lightning Labs' advisory](https://security.lightning.engineering/2026/09/21/lnd-gossip-validation-barrier-stall.html) lists v0.20.1 as patched because it covers only the direct attack.

[PR #10589](https://github.com/lightningnetwork/lnd/pull/10589), merged 2026-04-11 and released in v0.21.0, replaces every error channel in the `discovery` package with an `actor.Promise[error]`, whose [`Complete`](https://github.com/lightningnetwork/lnd/blob/a54a4d4e501ee7efc58b993a598d4a487ccbd847/actor/future.go#L60-L70) never blocks and keeps only the first result:

```go
func (p *promiseImpl[T]) Complete(result fn.Result[T]) bool {
	var success bool
	p.fut.completeOnce.Do(func() {
		p.fut.resultCache.Store(&result)
		close(p.fut.done)

		success = true
	})

	return success
}
```

A second result is now dropped instead of blocking, so the goroutine always returns and releases its slot.

## Discovery

Matt and Nishant independently found the double send on the error channel, with different fuzzers.

Matt found it with smite as a hang on shutdown and fixed it in [PR #10540](https://github.com/lightningnetwork/lnd/pull/10540).

Nishant found it with the gossip fuzz target later proposed in [PR #10605](https://github.com/lightningnetwork/lnd/pull/10605), realized each stuck goroutine also leaks a validation barrier slot, and reported the gossiper stall to Lightning Labs so the fix would be backported.

Days after v0.20.1 was released, Nishant found the delayed variant with [the same fuzz target](https://github.com/lightningnetwork/lnd/pull/10605) and reported it to Lightning Labs, which led them to remove the error channels entirely in [PR #10589](https://github.com/lightningnetwork/lnd/pull/10589).

## Timeline

- **2026-02-02:** [PR #10540](https://github.com/lightningnetwork/lnd/pull/10540) opened to fix the shutdown hang found by smite.
- **2026-02-03:** Nishant found the same bug with the gossip fuzz target.
- **2026-02-04:** First fix merged as PR #10540.
- **2026-02-05:** Gossiper stall reported privately to Lightning Labs, who agreed to backport the fix.
- **2026-02-06:** Backport merged as [PR #10554](https://github.com/lightningnetwork/lnd/pull/10554).
- **2026-02-12:** [LND v0.20.1](https://github.com/lightningnetwork/lnd/releases/tag/v0.20.1-beta) released with the first fix.
- **2026-02-16:** Delayed variant reported privately to Lightning Labs.
- **2026-02-18:** [PR #10589](https://github.com/lightningnetwork/lnd/pull/10589) opened to remove the error channels.
- **2026-04-11:** Full fix merged as PR #10589.
- **2026-06-05:** [LND v0.21.0](https://github.com/lightningnetwork/lnd/releases/tag/v0.21.0-beta) released with the full fix.
- **2026-09-21:** [Public disclosure](https://security.lightning.engineering/2026/09/21/lnd-gossip-validation-barrier-stall.html) of the direct attack by Lightning Labs.
- **2026-09-25:** Public disclosure of the delayed variant.

## Takeaways

- **Upgrade to LND v0.21.0 or later.**
- **Fix the root cause, not just the reported path.**
  A quick workaround for one path often leaves others open.
