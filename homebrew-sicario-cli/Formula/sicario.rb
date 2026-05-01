class Sicario < Formula
  desc "Next-generation SAST, SCA, and secret scanner"
  homepage "https://usesicario.xyz"
  version "0.1.0"  # bumped automatically by CI

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    else
      url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-darwin-amd64.tar.gz"
      sha256 "PLACEHOLDER_AMD64_SHA256"
    end
  end

  on_linux do
    url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-linux-amd64.tar.gz"
    sha256 "PLACEHOLDER_LINUX_AMD64_SHA256"
  end

  def install
    bin.install "sicario"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sicario --version")
  end
end
