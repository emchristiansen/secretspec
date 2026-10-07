{ lib, pkgs, ... }: {
  languages.rust = {
    enable = true;
    # The Rust version is pinned in rust-toolchain.toml, which the native CI
    # runners (artifact workflows that cannot use devenv) read via rustup.
    # The musl targets for the fully-static Go binary are declared in
    # rust-toolchain.toml (read automatically via toolchainFile).
    toolchainFile = ./rust-toolchain.toml;
  };

  languages.javascript = {
    directory = "./docs";
    enable = true;
    # Node 22 (the plain nixpkgs default) bundles npm 10.x, which mishandles
    # npm Trusted Publishing's OIDC handshake and can even misreport a brand
    # new package's first publish as a 404. Node 24 bundles npm >= 11.5.1.
    package = pkgs.nodejs_24;
    npm = {
      enable = true;
      install.enable = true;
    };
  };
  # Python is used by the reference SDK (secretspec-py), a pyo3 extension
  # (secretspec-py-native) that statically links the resolver in directly.
  languages.python = {
    enable = true;
    venv = {
      enable = true;
      requirements = ''
        maturin
        pytest
      '';
    };
  };
  # Go SDK (secretspec-go): default binding is purego (dlopen, no cgo); the
  # `-tags static` binding uses cgo to statically link libsecretspec.a, and on
  # Linux is built fully static against musl (see the env block below).
  languages.go.enable = true;
  # Ruby SDK (secretspec-rb) compiles an mkmf C extension that statically links
  # libsecretspec.a.
  languages.ruby.enable = true;
  # Haskell SDK (secretspec-hs) links the C ABI at build time via the FFI.
  # Supply its only non-boot dependency from Nix's binary cache. Otherwise a
  # cold Cabal store compiles aeson and roughly forty transitive packages from
  # source in every hosted SDK job.
  languages.haskell = {
    enable = true;
    package = pkgs.haskellPackages.ghcWithPackages (hpkgs: [ hpkgs.aeson ]);
  };
  # C# SDK (secretspec-dotnet) loads the C ABI through P/Invoke. The NuGet
  # package carries runtime-specific cdylibs; local tests use
  # SECRETSPEC_FFI_LIB from scripts/ci-sdks.sh.
  languages.dotnet.enable = true;
  # PHP SDK (secretspec-php) has two native backends over the same resolver:
  #   * secretspec-php-native, an ext-php-rs extension that embeds the resolver
  #     (the production path: no ffi.enable, works in FPM like ext-redis); and
  #   * a runtime ext-ffi fallback that dlopens the libsecretspec cdylib.
  # The pure-PHP client prefers the extension when loaded. ext-ffi (enabled here)
  # covers the fallback + dev; composer (bundled with languages.php) manages the
  # dev-only phpunit dependency.
  languages.php = {
    enable = true;
    extensions = [ "ffi" ];
    ini = ''
      ffi.enable = true;
    '';
  };
  languages.java = {
    enable = true;
    jdk.package = pkgs.jdk21;
  };

  packages = [
    # documentation link validation
    pkgs.lychee
    # coverage testing
    pkgs.cargo-tarpaulin
    # coverage-guided fuzzing of IPC wire targets (requires a nightly toolchain)
    pkgs.cargo-fuzz
    # installers
    pkgs.cargo-dist
    # bitwarden-cli for integration testing
    pkgs.bitwarden-cli
    # JSON processor used by the Bitwarden integration test scripts
    pkgs.jq
    # docker CLI for tests/vaultwarden_harness.sh, which runs the disposable
    # Vaultwarden + TLS proxy containers. Client only: the harness talks to
    # whatever runtime the developer already provides (Docker Desktop, colima,
    # or a podman machine exposing /var/run/docker.sock).
    # docker-client currently aliases the insecure Docker 28 package.
    (pkgs.docker_29.override { clientOnly = true; })
    # Building the secretspec-php-native extension (ext-php-rs) needs php-config +
    # the PHP dev headers, and bindgenHook wires libclang/clang system headers so
    # ext-php-rs's bindgen step can parse php.h.
    pkgs.php.unwrapped.dev
    pkgs.rustPlatform.bindgenHook
    # For development of the SOPS provider
    pkgs.sops
    pkgs.pkg-config
    # JSON parsing for libsecretspec-resolver, resolved through pkg-config
    # (Meson, cc-rs) and its CMake package config rather than vendored
    pkgs.yyjson
    # Standalone libsecretspec-resolver builds and install metadata.
    pkgs.cmake
    pkgs.meson
    pkgs.ninja
    # Installs the libsecretspec archive with its header and pkg-config file
    pkgs.cargo-c
  ];

  env = {
    # Gradle runs on JDK 21 but compiles the JVM SDK against this JDK 11 toolchain.
    SECRETSPEC_JVM_TARGET_JDK = "${pkgs.jdk11}";
  } //
  # Fully-static musl build of the Go SDK (-tags static + -extldflags -static).
  # Keep these Linux-only: interpolating the cross-toolchain paths on macOS makes
  # Nix build a Linux-targeting GCC toolchain from source just to enter the shell.
  # The musl C cross-toolchain and static libunwind are referenced HERE by
  # absolute path only -- NOT added to `packages`, because devenv `packages` inject
  # their lib dirs into the host NIX_LDFLAGS. Referenced by path, libunwind is
  # realised into the store without polluting the host build environment. The
  # CC_/linker vars are musl-target-scoped, so host (glibc) cargo builds are
  # unaffected; MUSL_CC / MUSL_STATIC_LDFLAGS feed the cgo link step.
  lib.optionalAttrs pkgs.stdenv.isLinux (
    let
      muslcc = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
    in
    {
      CC_x86_64_unknown_linux_musl = muslcc;
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = muslcc;
      MUSL_CC = muslcc;
      MUSL_STATIC_LDFLAGS = "-L${pkgs.pkgsStatic.libunwind}/lib";
    }
  );

  git-hooks.hooks = {
    rustfmt.enable = true;
    clippy.enable = true;
    # TODO: this should be done by devenv
    clippy.settings.offline = false;
  };

  enterShell = ''
    # Put Rust build output on the non-snapshotted cache dataset. The canonical
    # path keeps sibling JJ workspaces with the same basename apart.
    CANONICAL_WORKSPACE_ROOT="$(pwd -P; printf 'x')"
    CANONICAL_WORKSPACE_ROOT="''${CANONICAL_WORKSPACE_ROOT%x}"
    CANONICAL_WORKSPACE_ROOT="''${CANONICAL_WORKSPACE_ROOT%$'\n'}"
    WORKSPACE_PATH_HASH="$(printf '%s' "$CANONICAL_WORKSPACE_ROOT" | sha256sum)"
    WORKSPACE_PATH_HASH="''${WORKSPACE_PATH_HASH%% *}"
    CARGO_TARGET_CACHE="$HOME/.cache/cargo-target/secretspec-workspace-$WORKSPACE_PATH_HASH"

    # Let Cargo resolve target/ through the workspace symlink, including
    # when a caller inherited a target override from another workspace.
    unset CARGO_TARGET_DIR
    mkdir -p "$CARGO_TARGET_CACHE"

    if [ -L target ]; then
      CURRENT_TARGET="$(readlink target)"
      if [ "$CURRENT_TARGET" = "$CARGO_TARGET_CACHE" ]; then
        : # Already points to this workspace's cache.
      else
        echo "Migrating target/ symlink: $CURRENT_TARGET → $CARGO_TARGET_CACHE"
        rm target
        ln -sfn "$CARGO_TARGET_CACHE" target
      fi
    elif [ -d target ]; then
      echo "ERROR: target/ is a real directory; refusing to replace or delete it." >&2
      echo "Resolve the preserved directory deliberately, then re-enter the workspace." >&2
      exit 1
    elif [ ! -e target ]; then
      ln -sfn "$CARGO_TARGET_CACHE" target
      echo "target/ → $CARGO_TARGET_CACHE (non-snapshotted cache dataset)"
    fi
  '';

  enterTest = ''
    cargo test --all
  '';

  scripts.test-cli-integration.exec = ''
    # Build the CLI for integration tests
    cargo build --release
    export PATH="$PWD/target/release:$PATH"

    # Run CLI integration tests
    bash tests/cli-integration.sh
  '';

  # Keep production builds on the stable toolchain from rust-toolchain.toml;
  # libFuzzer alone needs nightly's sanitizer coverage flags. Referencing
  # rustup by its Nix path avoids placing its cargo shim ahead of the pinned
  # compiler in ordinary development shells.
  scripts.install-fuzz-nightly.exec = ''
    ${pkgs.rustup}/bin/rustup toolchain install nightly
  '';

  scripts.fuzz-resolver.exec = ''
    nightly_cargo="$(${pkgs.rustup}/bin/rustup which --toolchain nightly cargo)"
    export PATH="$(dirname "$nightly_cargo"):$PATH"
    export RUSTC="$(${pkgs.rustup}/bin/rustup which --toolchain nightly rustc)"
    cargo fuzz run resolver_wire -- "$@"
  '';

  scripts.fuzz-resolve-apis.exec = ''
    nightly_cargo="$(${pkgs.rustup}/bin/rustup which --toolchain nightly cargo)"
    export PATH="$(dirname "$nightly_cargo"):$PATH"
    export RUSTC="$(${pkgs.rustup}/bin/rustup which --toolchain nightly rustc)"
    cargo fuzz run resolve_apis -- "$@"
  '';

  processes.docs.exec = ''
    cd docs && npm run dev
  '';
}
