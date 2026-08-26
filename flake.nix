{
  description = "Vendor Neutral, Rust-Based Management UI and CLI for U2F/FIDO2 and other hardware security keys ";
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
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        {
          config,
          pkgs,
          ...
        }:
        let
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
                  libxkbcommon
                  libGL
                  wayland
                  libx11
                  libxcursor
                  libxi
                  libxrandr
                ];

              postFixup = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
                patchelf --set-rpath "${
                  pkgs.lib.makeLibraryPath [
                    pkgs.pcsclite
                    pkgs.wayland
                    pkgs.libx11
                    pkgs.libxcursor
                    pkgs.libxi
                    pkgs.libxrandr
                    pkgs.libGL
                    pkgs.libxkbcommon
                  ]
                }" $out/bin/keyroost
              '';

              meta = {
                description = "Desktop GUI for programming Token2 Molto2 / Molto2v2 TOTP tokens.";
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
                description = "Command-line tool for programming Token2 Molto2 / Molto2v2 TOTP tokens.";
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
            ];
          };
        };
    };
}
