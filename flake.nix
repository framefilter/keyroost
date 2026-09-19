{
  description = "Independent, vendor-neutral GUI and CLI for managing hardware security keys (FIDO2, OATH, OpenPGP, PIV, Token2 TOTP tokens)";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        {
          config,
          pkgs,
          ...
        }:
        let
          isCI = (builtins.getEnv "CI") == "true";
          workspaceCargo = fromTOML (builtins.readFile ./Cargo.toml);
          keyroostCargo = fromTOML (builtins.readFile ./crates/keyroost/Cargo.toml);
          keyroostctlCargo = fromTOML (builtins.readFile ./crates/keyroostctl/Cargo.toml);
          version = workspaceCargo.workspace.package.version;
        in
        {
          packages = {
            keyroost = pkgs.rustPlatform.buildRustPackage {
              pname = keyroostCargo.package.name;
              inherit version;

              src = ./.;

              cargoLock = {
                lockFile = ./Cargo.lock;
              };

              cargoBuildFlags = [
                "-p"
                "keyroost"
              ];

              buildType = if isCI then "debug" else "release";
              dontStrip = isCI;

              buildNoDefaultFeatures = true;

              nativeBuildInputs = with pkgs; [
                pkg-config
              ];

              buildInputs =
                with pkgs;
                [
                  pcsclite
                ]
                ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
                  libGL
                  libx11
                  libxcb
                  libxcursor
                  libxi
                  libxkbcommon
                  libxrandr
                  wayland
                ];

              postFixup = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
                patchelf --set-rpath "${
                  pkgs.lib.makeLibraryPath [
                    pkgs.libGL
                    pkgs.libx11
                    pkgs.libxcb
                    pkgs.libxcursor
                    pkgs.libxi
                    pkgs.libxkbcommon
                    pkgs.libxrandr
                    pkgs.pcsclite
                    pkgs.wayland
                  ]
                }" $out/bin/keyroost
              '';

              meta = {
                description = keyroostCargo.package.description;
                homepage = "https://github.com/framefilter/keyroost";
                license = with pkgs.lib.licenses; [
                  mit
                  asl20
                ];
                platforms = pkgs.lib.platforms.unix;
              };
            };

            keyroostctl = pkgs.rustPlatform.buildRustPackage {
              pname = keyroostctlCargo.package.name;
              inherit version;

              src = ./.;

              cargoLock = {
                lockFile = ./Cargo.lock;
              };

              cargoBuildFlags = [
                "-p"
                "keyroostctl"
              ];

              buildType = if isCI then "debug" else "release";
              dontStrip = isCI;

              nativeBuildInputs = with pkgs; [
                pkg-config
              ];

              buildInputs = with pkgs; [
                pcsclite
              ];

              postFixup = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
                patchelf --set-rpath "${pkgs.lib.makeLibraryPath [ pkgs.pcsclite ]}" $out/bin/keyroostctl
              '';

              meta = {
                description = keyroostctlCargo.package.description;
                homepage = "https://github.com/framefilter/keyroost";
                license = with pkgs.lib.licenses; [
                  mit
                  asl20
                ];
                platforms = pkgs.lib.platforms.unix;
              };
            };

            default = config.packages.keyroost;
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [
              config.packages.keyroost
              config.packages.keyroostctl
            ];
            packages = with pkgs; [
              nixfmt
              nixd
              rust-analyzer
            ];
          };
        };
    };
}
