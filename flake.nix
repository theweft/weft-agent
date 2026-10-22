{
  description = "weft-agent: development environment, package and VM tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The path dependency ../weft-verifier. CI and `just vm` override it with the checkout next
    # to this repository: --override-input weft-verifier 'git+file:../weft-verifier?shallow=1'
    weft-verifier = {
      url = "github:theweft/weft-verifier";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      weft-verifier,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      linux = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (pkgsFor system));
      forLinux = f: nixpkgs.lib.genAttrs linux (system: f (pkgsFor system));
      toolchain = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      agent =
        pkgs:
        let
          rust = toolchain pkgs;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rust;
            rustc = rust;
          };
          # Both repositories side by side, as in development.
          src = pkgs.runCommand "weft-src" { } ''
            mkdir -p $out
            cp -r ${self} $out/weft-agent
            cp -r ${weft-verifier} $out/weft-verifier
            chmod -R u+w $out
          '';
        in
        rustPlatform.buildRustPackage {
          pname = "weft-agent";
          version = "0.0.1";
          inherit src;
          buildAndTestSubdir = "weft-agent";
          cargoRoot = "weft-agent";
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "-p"
            "weft-agent"
          ];
          # `just ci` runs the tests; the package is for the VM tests and devices.
          doCheck = false;
          postInstall = ''
            mkdir -p $out/lib/systemd/system
            for unit in weft-agent/dist/systemd/*.service; do
              substitute "$unit" "$out/lib/systemd/system/$(basename "$unit")" \
                --replace-fail /usr/bin/weft-agent "$out/bin/weft-agent"
            done
          '';
          meta.mainProgram = "weft-agent";
        };
    in
    {
      packages = forLinux (pkgs: {
        weft-agent = agent pkgs;
        default = agent pkgs;
      });

      checks = forLinux (pkgs: {
        l1-vm = import ./tests/vm/l1.nix {
          inherit pkgs;
          weft-agent = agent pkgs;
          fixtures = ./tests/vm/fixtures;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            # Same toolchain as rustup users get: read from rust-toolchain.toml.
            (toolchain pkgs)
            pkgs.just
            pkgs.cargo-deny
            pkgs.taplo
            pkgs.typos
            pkgs.reuse
            pkgs.strictdoc
          ];
        };
      });
    };
}
