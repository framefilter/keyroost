- **Less CPU while codes are counting down.** The app now redraws once a
  second for countdowns instead of twice, which matters most on machines
  without a GPU, where drawing is done in software. ([#190])
