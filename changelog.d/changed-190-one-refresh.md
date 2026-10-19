- **Every Refresh button does the same thing.** The top-bar Refresh, the
  sidebar's rescan icon and the Refresh on the Authenticator, PIV and OTP
  tabs now all look for keys again and then re-read the open tab of the
  selected key (on a Molto2, its slot list). Before, the top-bar Refresh
  only rescanned, so an account added with `keyroostctl` while the app was
  open didn't show up until the key was replugged or the app restarted.
  ([#190])
