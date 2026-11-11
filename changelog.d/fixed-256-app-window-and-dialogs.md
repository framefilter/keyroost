- **App details from the Windows test round.** The window no longer opens
  larger than a small screen with display scaling (1280×800 at 125%) or
  under the taskbar; it shrinks or moves to fit (where the system says
  where the window is: not on Wayland). The import dialog draws
  again until its size settles, instead of leaving its buttons cut off
  until the mouse moved. The PIV reset confirmation no longer says it
  only works with the PIN and PUK already blocked: keyroost blocks them
  first where the key needs that. In the dark theme, an unticked checkbox
  in a dialog ("Require touch", "Use default management key") shows its
  box. The "touch your key" banner sits under the key's name and tabs
  instead of over them. The On-device OTP tab's PIN cards span the pane
  like its other cards, and removing the OTP PIN no longer shows advice
  for choosing one. ([#256])
