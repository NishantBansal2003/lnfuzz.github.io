---
title: "Core Lightning crashes when two channels share a funding outpoint"
id: LNF-2026-0004
aliases: ["/advisories/lnf-2026-0004/"]
description: "Core Lightning v0.12.0 through v26.06.7 let a peer open a channel on a funding outpoint that already belongs to another channel, so the two share a v1 channel_id, causing the node to crash-loop on every restart."
date: 2026-11-13
found_with: smite
severity: high
targets:
  - impl: cln
    affected: "v0.12.0 through v26.06.7"
    fixed_in: "v26.06.8"
    reported: 2026-07-08
    upstream: https://github.com/ElementsProject/lightning/issues/9274
    fix:
      - https://github.com/ElementsProject/lightning/pull/9318
      - https://github.com/ElementsProject/lightning/commit/84bfdf4fe1f8176cf361d474a12df20cfa704778
authors: [nishant]
tags: [cln, dos, bolt2]
---

Core Lightning v0.12.0 through v26.06.7 accept a `funding_created` that reuses a funding outpoint already belonging to another channel.
Since a v1 `channel_id` is derived from the funding outpoint, the two channels share a `channel_id`, allowing an attacker to crash the node in two ways.
In the first variant the attacker reuses the outpoint of an unfunded (pending) channel and then reconnects to the victim, causing CLN to trip an assertion that crashes the whole node.
This variant is free and repeatable.
In the second and more severe variant reported by [Crypt-iQ](https://github.com/Crypt-iQ), the attacker reuses the outpoint of a *closed* channel and then closes the second channel too, causing CLN to trip an assertion and then **crash-loop** on restart.
This variant costs only on-chain fees and keeps the node offline with no further action from the attacker.

Both attacks are fixed in [Core Lightning v26.06.8](https://github.com/ElementsProject/lightning/releases/tag/v26.06.8), but later releases may contain further security fixes, so upgrade to the [latest release](https://github.com/ElementsProject/lightning/releases).

## Background

The opener of a v1 channel names the funding outpoint in `funding_created`, and the *fundee* answers with `funding_signed` before the funding transaction is broadcast.
Both sides then identify the channel by a `channel_id` that BOLT 2 [derives](https://github.com/lightning/bolts/blob/191462825ae341f0a27098765c075f01ca9bc6c2/02-peer-protocol.md?plain=1#L62-L64) by XORing the funding output index into the funding txid, so two channels on the same outpoint share a `channel_id`.

In Core Lightning, each channel runs in its own `channeld` subdaemon, with the `connectd` daemon routing peer messages to the corresponding subdaemon based on the `channel_id`.
When a peer reconnects, `lightningd` starts a fresh subdaemon for each channel and hands it to `connectd`.
`lightningd` also keeps closed channels in memory, in a `closed_channel_map`, which holds only one channel per `channel_id`.

## The vulnerability

When CLN v26.06.2 is the fundee and receives `funding_created`, [`opening_fundee_finished()`](https://github.com/ElementsProject/lightning/blob/c237b9ea1d1bbc610586f1fab36ed6f0948ca914/lightningd/opening_control.c#L476-L581) derives the `channel_id` and saves the channel without checking whether the outpoint already belongs to another channel, live or closed:

```c
static void opening_fundee_finished(struct subd *openingd,
				    const u8 *reply,
				    const int *fds,
				    struct uncommitted_channel *uc)
{
	/* ... parse openingd's reply. */

	derive_channel_id(&cid, &funding);

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info.old_remote_per_commit = channel_info.remote_per_commit;

	/* Consumes uc */
	channel = wallet_commit_channel(ld, uc,
					&cid,
					remote_commit,
					&remote_commit_sig,
					&funding,
					/* ... */);
	/* ... handle failure, watch the funding tx, notify plugins. */

	/* On to normal operation (frees if it fails!) */
	if (peer_start_channeld(channel, peer_fd, fwd_msg, false))
		tal_free(uc);
	return;

failed:
	tal_free(uc);
}
```

In this code `fwd_msg` is the `funding_signed` that `channeld` sends on startup.
The database doesn't catch the duplicate either, since it keys channels by an auto-incrementing ID.
So a peer that runs the funding flow twice with the same outpoint gets `funding_signed` both times, leaving the victim with two channels that share a `channel_id`.

The rest of CLN assumes `channel_id`s are unique, for live and closed channels alike, so the collision causes issues later on.

### Reconnecting crashes `connectd`

When both channels are live, lookups go wrong: [`find_channel_by_id()`](https://github.com/ElementsProject/lightning/blob/c237b9ea1d1bbc610586f1fab36ed6f0948ca914/lightningd/channel.c#L870-L880) in `lightningd` and [`find_subd()`](https://github.com/ElementsProject/lightning/blob/c237b9ea1d1bbc610586f1fab36ed6f0948ca914/connectd/multiplex.c#L63-L86) in `connectd` both return the first match, so the second channel can never be found by its `channel_id`.

When the peer reconnects, `lightningd` [loops over its channels](https://github.com/ElementsProject/lightning/blob/c237b9ea1d1bbc610586f1fab36ed6f0948ca914/lightningd/peer_control.c#L1562-L1577) and hands `connectd` a subdaemon for each one, identified only by `channel_id`.
[`peer_connect_subd()`](https://github.com/ElementsProject/lightning/blob/c237b9ea1d1bbc610586f1fab36ed6f0948ca914/connectd/multiplex.c#L1685-L1736) handles each request:

```c
void peer_connect_subd(struct daemon *daemon, const u8 *msg, int fd)
{
	/* ... parse the request and look up the peer. */

	/* If peer said something, we created this and queued msg. */
	subd = find_subd(peer, &channel_id);
	if (!subd) {
		subd = new_subd(peer, &channel_id);
		/* Implies lightningd is ready for another peer. */
		release_one_waiting_connection(peer->daemon,
					       tal_fmt(tmpctx, "%s given a subd",
						       fmt_node_id(tmpctx, &id)));
	}

	assert(!subd->conn);

	/* This sets subd->conn inside subd_conn_init, and reparents subd! */
	io_new_conn(peer, fd, subd_conn_init, subd);
}
```

The first request finds or creates the subdaemon for that `channel_id` and gives it the connection.
The second request carries the same `channel_id`, so `find_subd()` returns that same subdaemon, which already has a connection, and `assert(!subd->conn)` fails.
`connectd` aborts, and because `lightningd` [treats that as fatal](https://github.com/ElementsProject/lightning/blob/c237b9ea1d1bbc610586f1fab36ed6f0948ca914/lightningd/subd.c#L663-L669), the whole node goes down.
Both channels are still in the database after a restart, so the next reconnect crashes the node again.

The assertion was [added](https://github.com/ElementsProject/lightning/commit/41b379ed897ad24bf2d68ce022eb15339e430761) in v0.12.0, when `lightningd` began handing connections to `connectd` per channel.
Releases before v0.12.0 also lack the outpoint check but don't crash, because their `connectd` [ignored](https://github.com/ElementsProject/lightning/blob/c9587ab17b58b8d3c1b03f009580e14f261fa8e1/connectd/multiplex.c#L491-L515) a request for a `channel_id` it already had a subdaemon for.

### Closing crashes `lightningd`

When the first channel is already closed, the collision surfaces when the new channel closes instead.
[`closed_channel_map`](https://github.com/ElementsProject/lightning/blob/c237b9ea1d1bbc610586f1fab36ed6f0948ca914/lightningd/closed_channel.h#L37-L50) is a hash table keyed by `channel_id` that doesn't allow duplicates:

```c
static inline const struct channel_id *keyof_closed_channel(const struct closed_channel *cc)
{
	return &cc->cid;
}

/* ... */

HTABLE_DEFINE_NODUPS_TYPE(struct closed_channel, keyof_closed_channel, hash_cid, closed_channel_eq_cid,
			  closed_channel_map);
```

The closed channel already sits in the map under its `channel_id`, and the new channel on the same outpoint carries that same `channel_id`.
When the new channel closes too, `lightningd` adds it to the map, causing `closed_channel_map_add()` to fail its "no-duplicates" assertion and abort `lightningd`.
The channel's funding spend is already recorded in the database, so every restart re-spawns `onchaind`, which resolves the channel again and triggers the same assertion failure.

The map was [added](https://github.com/ElementsProject/lightning/commit/1fe5644bf28b0a1f7c5d8542ac96cd535139330f) in v25.05, when `lightningd` began keeping closed channels in memory, so earlier releases are not affected by this variant.

## The attack

Both variants start the same way: the attacker completes the BOLT 8 handshake and `init` exchange as an ordinary peer, then gets the victim to accept two channels on the same funding outpoint.

In the reconnect variant, both channels stay live.
The attacker runs the v1 funding flow twice, naming the same outpoint in both `funding_created` messages and receiving `funding_signed` each time.
The outpoint never has to exist on chain, so the attack costs nothing.
Finally, the attacker disconnects and reconnects, and the request for the second channel trips the assertion in `connectd`.

In the closed-channel variant, the first channel is *marked* as closed before the second one is opened.
The attacker funds a channel with the victim and gets it recorded as closed without spending its funding outpoint.
It then opens a second channel on the same outpoint.
Finally, the attacker causes the second channel to be recorded as closed too, under the same `channel_id`, which trips the assertion in `lightningd`.
The channel funds return to the attacker, so the attack costs only on-chain fees.

### Observed impact

The reconnect crash takes the node down every time the attacker reconnects, so the attacker can repeat the attack indefinitely unless the node operator blocks them at the network level.
The closed-channel variant is worse: once triggered, the node crash-loops on its own and stays down until it is upgraded.
Either way, while the node is down it can't watch the chain, so it can miss a peer broadcasting a revoked commitment or an HTLC it must claim before it expires, putting funds in its other channels at risk.

## The fix

Both crashes were fixed the same way: by refusing a new channel that would share another channel's `channel_id` and by tolerating duplicates that existing nodes had already stored.

### Fixing the reconnect crash

[PR #9318](https://github.com/ElementsProject/lightning/pull/9318), merged 2026-07-16 and released in v26.06.6, fixes the reconnect variant we reported and makes two changes.
First, [`opening_fundee_finished()`](https://github.com/ElementsProject/lightning/blob/c7a013c821432d598a1dee39714ad667fffcdd73/lightningd/opening_control.c#L476-L590) now checks the funding outpoint against the peer's other channels and, on a match, disconnects before the channel is stored or `funding_signed` is sent:

```c
static void opening_fundee_finished(struct subd *openingd,
				    const u8 *reply,
				    const int *fds,
				    struct uncommitted_channel *uc)
{
	/* ... parse openingd's reply. */

	derive_channel_id(&cid, &funding);

	/* A funding outpoint funds at most one channel; don't accept a second
	 * channel reusing one we already have.  Drop the connection so the
	 * peer's open fails cleanly instead of waiting for funding_signed. */
	if (find_channel_by_funding_outpoint(uc->peer, &funding)) {
		force_peer_disconnect(ld, uc->peer,
				      "Funding outpoint already in use");
		return;
	}

	/* ... commit the channel and start channeld. */
}
```

Second, [`peer_connect_subd()`](https://github.com/ElementsProject/lightning/blob/c7a013c821432d598a1dee39714ad667fffcdd73/connectd/multiplex.c#L1735-L1741) no longer asserts when a subdaemon already has a connection, but keeps the existing connection and closes the new one, so nodes that already stored duplicate channels don't crash on reconnect.

This fixed the reconnect crash, but [`find_channel_by_funding_outpoint()`](https://github.com/ElementsProject/lightning/blob/c7a013c821432d598a1dee39714ad667fffcdd73/lightningd/channel.c#L882-L892) only matches the peer's *live* channels, so reusing a closed channel's outpoint still worked.

### Fixing the closing crash

Commit [`84bfdf4`](https://github.com/ElementsProject/lightning/commit/84bfdf4fe1f8176cf361d474a12df20cfa704778), released in v26.06.8, fixes the closed-channel variant reported by Crypt-iQ and makes two changes.
First, [`opening_fundee_finished()`](https://github.com/ElementsProject/lightning/blob/84bfdf4fe1f8176cf361d474a12df20cfa704778/lightningd/opening_control.c#L485-L603) now also refuses a channel whose `channel_id` is used by any live or closed channel:

```c
static void opening_fundee_finished(struct subd *openingd,
				    const u8 *reply,
				    const int *fds,
				    struct uncommitted_channel *uc)
{
	/* ... parse openingd's reply. */

	derive_channel_id(&cid, &funding);

	/* A funding outpoint funds at most one channel; don't accept a second
	 * channel reusing one we already have, with this or any other peer,
	 * open or closed: the channel_id would collide.  Drop the connection
	 * so the peer's open fails cleanly instead of waiting for
	 * funding_signed. */
	if (find_channel_by_funding_outpoint(uc->peer, &funding)
	    || channel_id_in_use(ld, &cid, NULL)) {
		force_peer_disconnect(ld, uc->peer,
				      "Funding outpoint already in use");
		return;
	}

	/* ... commit the channel and start channeld. */
}
```

The new [`channel_id_in_use()`](https://github.com/ElementsProject/lightning/blob/84bfdf4fe1f8176cf361d474a12df20cfa704778/lightningd/channel.c#L881-L900) checks the live and closed channels of every peer, and the funder and dual-funding paths now run the same check.

Second, [`closed_channel_map`](https://github.com/ElementsProject/lightning/blob/84bfdf4fe1f8176cf361d474a12df20cfa704778/lightningd/closed_channel.h#L49-L53) now allows duplicates, so nodes that already stored duplicate channels can still load and close them.

## Discovery

While fuzzing CLN's funding flow, smite flagged that CLN would answer a `funding_created` reusing another channel's funding outpoint with `funding_signed`.
At first this looked like a spec violation with no security impact, so it was reported publicly as [issue #9274](https://github.com/ElementsProject/lightning/issues/9274).
Further investigation surfaced the crash on reconnect, which was reported privately, and experiments confirmed that reconnecting after every restart crashes the node again.
The closed-channel variant was reported to Core Lightning separately by [Crypt-iQ](https://github.com/Crypt-iQ), and we reproduced it on regtest to confirm the crash loop.

## Timeline

- **2026-07-02:** Duplicate funding outpoint reported publicly as a spec violation in [issue #9274](https://github.com/ElementsProject/lightning/issues/9274).
- **2026-07-08:** Crash on reconnect reported privately to Core Lightning.
- **2026-07-14:** Core Lightning acknowledged the report and began working on a fix.
- **2026-07-16:** Fix merged as [PR #9318](https://github.com/ElementsProject/lightning/pull/9318).
- **2026-07-22:** [Core Lightning v26.06.6](https://github.com/ElementsProject/lightning/releases/tag/v26.06.6) released with the fix for the reconnect variant.
- **2026-09-22:** [Core Lightning v26.06.8](https://github.com/ElementsProject/lightning/releases/tag/v26.06.8) released with the fix for the closed-channel variant.
- **2026-10-23:** Core Lightning approved public disclosure of the reconnect variant.
- **2026-11-13:** Core Lightning approved public disclosure of the closed-channel variant.
- **2026-11-13:** Public disclosure.

## Takeaways

- **Upgrade to the latest Core Lightning release.**
  Vulnerabilities are being found faster than ever, and older releases quickly fall behind on fixes.
- **Never assert on state a peer can influence.**
  A peer that can break an assertion can crash the node, so any case that isn't provably impossible must be handled gracefully.
