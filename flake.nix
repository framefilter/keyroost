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
          workspaceCargo = fromTOML (builtins.readFile ./Cargo.toml);
          keyroostCargo = fromTOML (builtins.readFile ./crates/keyroost/Cargo.toml);
          keyroostctlCargo = fromTOML (builtins.readFile ./crates/keyroostctl/Cargo.toml);

          buildKeyroostPackage =
            crateCargo: extraBuildInputs: debug:
            pkgs.rustPlatform.buildRustPackage {
              pname = crateCargo.package.name;
              version = workspaceCargo.workspace.package.version;
              src = ./.;
              cargoLock = {
                lockFile = ./Cargo.lock;
              };

              cargoBuildFlags = [
                "-p"
                crateCargo.package.name
              ];

              buildType = if debug then "debug" else "release";
              dontStrip = debug;

              buildNoDefaultFeatures = true;

              nativeBuildInputs = with pkgs; [
                pkg-config
              ];

              buildInputs = [ pkgs.pcsclite ] ++ extraBuildInputs;

              postFixup = pkgs.lib.optionalString (pkgs.stdenv.hostPlatform.isLinux) ''
                patchelf \
                  --set-rpath "${pkgs.lib.makeLibraryPath ([ pkgs.pcsclite ] ++ extraBuildInputs)}" \
                  $out/bin/${crateCargo.package.name}
              '';

              meta = {
                description = crateCargo.package.description;
                homepage = "https://github.com/framefilter/keyroost";
                license = with pkgs.lib.licenses; [
                  mit
                  asl20
                ];
                platforms = pkgs.lib.platforms.unix;
              };
            };

          keyroostExtraBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux (
            with pkgs;
            [
              libGL
              libx11
              libxcb
              libxcursor
              libxi
              libxkbcommon
              libxrandr
              wayland
            ]
          );

          buildKeyroost = buildKeyroostPackage keyroostCargo keyroostExtraBuildInputs;
          buildKeyroostctl = buildKeyroostPackage keyroostctlCargo [ ];
        in
        {
          packages = {
            keyroost = buildKeyroost false;
            keyroost-debug = buildKeyroost true;
            keyroostctl = buildKeyroostctl false;
            keyroostctl-debug = buildKeyroostctl true;

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
