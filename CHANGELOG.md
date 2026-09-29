# Changelog

While the project is at MVP stage there are no version numbers; changes are
grouped by meaning. The format will stabilise with the first public release.

## Live delivery between devices

- A message reaches the other device over Tor/onion. Removed the
  binding of a Contact Key to different session names: the same
  `(identity, epoch)` is no longer bound in two ways, which made anti-rollback
  reject legitimate sends.
- Losing the mailbox token no longer breaks sending: local state changes only
  after the server confirms.
- A failure at the connection stage is retried; operations that do not change
  state (`Register`/`Pull`/`Ack`) are retried on a dropped connection.
- Identity recovery from the Keychain: reinstalling the app keeps the address.
  Deleting the app no longer silently resets the identity.

## Messages from strangers

- Anyone holding your invite code can write to you: adding the contact back is
  not required.
- Discoverability is on by default - a request is accepted immediately, with no
  button. With the toggle off, requests accumulate and wait for a decision
  instead of being lost.
- The request queue is bounded in memory: 20 requests, up to 16 envelopes per
  request, a total budget of 512 KiB.
- Blocking is silent: a blocked sender gets no reply at all.

## Conversations

- A reply quote travels inside the encrypted payload: the other side sees it
  and it survives a restart. The quote used to live only in the UI and vanished
  on the first list refresh.
- Chats survive an app restart: the list appears immediately, without waiting
  for the Tor bootstrap.
- Pull-to-refresh in the chat list - refreshing is no longer timer-only.
- The unread counter appears on new chats and does not "stick" after a
  restart.

## Relay and client reliability

- `ack` releases relay queue memory (DoS).
- An undecryptable message is dropped after a bounded number of attempts
  instead of hanging in the queue forever.
- Public keys no longer reach syslog or iCloud backup.
- The production `.onion` was removed from the tracked `project.pbxproj`.

## Audit and documentation

- A self-hack audit of the core, relay and client was carried out; verdicts are
  in `docs/AUDIT_REPORT.md`, the working tracker is internal.
- Build artifacts (`MinCore.xcframework`) are no longer in git.
- The documentation follows the structure of mature projects: 5 files in the
  root, the rest under `docs/`, without duplicates or outdated copies.