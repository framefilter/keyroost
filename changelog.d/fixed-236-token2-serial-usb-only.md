- **A Token2 key seen only over USB shows its serial.** Where nothing pairs
  its USB side with a smart-card reader (on Linux, a PIN+ whose card side
  has no reader), its row had no serial, though its firmware release was
  worked out from that same serial. A device scan now asks such a key for
  its serial once per plug-in. ([#236])
