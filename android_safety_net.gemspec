# frozen_string_literal: true

require_relative "lib/safety_net_attestation/version"

Gem::Specification.new do |spec|
  spec.name          = "safety_net_attestation"
  spec.version       = SafetyNetAttestation::VERSION
  spec.authors       = ["Bart de Water"]

  spec.summary       = "SafetyNet attestation response verification"
  spec.homepage      = "https://github.com/bdewater/safety_net_attestation"
  spec.license       = "MIT"

  if spec.respond_to?(:metadata)
    spec.metadata["homepage_uri"] = spec.homepage
    spec.metadata["source_code_uri"] = spec.homepage
    spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/master/CHANGELOG.md"
  end

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir[
      ".github/**/*",
      ".gitignore",
      ".rspec",
      ".rubocop.yml",
      "Appraisals",
      "CHANGELOG.md",
      "CODE_OF_CONDUCT.md",
      "Gemfile",
      "Gemfile.lock",
      "README.md",
      "Rakefile",
      "android_safety_net.gemspec",
      "bin/*",
      "gemfiles/*.gemfile",
      "lib/**/*"
    ].select { |file| File.file?(file) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.3"

  spec.add_dependency "jwt", ">= 2.0", "< 4.0"
  spec.add_development_dependency "appraisal"
  spec.add_development_dependency "bundler"
  spec.add_development_dependency "irb"
  spec.add_development_dependency "pry-byebug"
  spec.add_development_dependency "rspec", "~> 3.8"
end
