{ pkgs }:
let
  mocks = pkgs.runCommand "hellas-publish-mocks" { } ''
    mkdir -p "$out/bin"
    for command in curl gh nix skopeo; do
      cat > "$out/bin/$command" <<EOF
    #!${pkgs.runtimeShell}
    exec ${pkgs.python3}/bin/python3 ${./publish.py} mock "$command" "\$@"
    EOF
      chmod +x "$out/bin/$command"
    done
  '';
  publisher = import ../publish.nix {
    pkgs = pkgs // {
      curl = mocks;
      gh = mocks;
      nix = mocks;
      skopeo = mocks;
    };
  };
in
pkgs.runCommand "hellas-publish-test" { nativeBuildInputs = [ pkgs.python3 ]; } ''
  python3 ${./publish.py} test ${publisher}/bin/hellas-publish
  touch "$out"
''
