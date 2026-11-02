- **`otp info` over USB shows a Token2 PIN+ R3.4's whole configuration.**
  Over USB the key answered with one byte, so OTP and touch-HOTP support
  read as "unknown". keyroost sends Token2's documented request first and,
  when the answer is that short, the form Token2's own app uses. ([#249])
