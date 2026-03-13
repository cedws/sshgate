{
  description = "sshgate - forwarding-only SSH server with policy-based connection control";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system} = {
        sshgate = pkgs.buildGoModule {
          pname = "sshgate";
          version = "0.0.1";
          src = ./.;
          vendorHash = "sha256-6cbbplKEuMK9pt4/1IYfEQ6ue8QPVLDCBSebYSk+fHU=";
        };
        default = self.packages.${system}.sshgate;
      };

      checks.${system} = {
        sshgate = self.packages.${system}.sshgate;
        devShell = self.devShells.${system}.default;
      };

      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [
          pkgs.go
          pkgs.gopls
          pkgs.gotools
        ];
      };
    };
}
