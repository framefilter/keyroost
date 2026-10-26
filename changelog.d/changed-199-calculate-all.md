- **Authenticator codes come back in one read.** The Authenticator tab now
  asks the key for every code at once, as Yubico Authenticator does,
  instead of one account at a time. On a key with accounts that require a
  touch, the tab no longer waits about 15 seconds per such account before
  showing anything: those accounts show **Read code** straight away. A
  Nitrokey 3 has no all-codes command, so keyroost asks for its account
  list with each account's touch setting instead, with the same result.
  Accounts with a period other than 30 seconds are still read one by one.
  ([#199])
