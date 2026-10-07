- **Out-of-range values exit 2.** A number outside its range (`oath add
  --digits 9`, Molto2 slot 100, a retry count of 0) is a usage error that
  exits 2, like any other mistyped argument. Some of them used to exit 1.
  ([#165])
