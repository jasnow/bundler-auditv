require 'spec_helper'
require 'bundler/audit/scanner'

describe Scanner do
  let(:bundle)    { 'unpatched_gems' }
  let(:directory) { File.join('spec','bundle',bundle) }

  # An advisory (by CVE alias) that affects the 'unpatched_gems' bundle
  # (Active Record 3.2.10: JSON parameter parsing query bypass, fixed in 3.2.11).
  # The ignore list in spec/bundle/unpatched_gems_with_dot_configuration/
  # .bundler-audit.yml must contain this same ID, and spec/fixtures/osv must
  # hold the OSV record that has it as its id or an alias.
  let(:ignored_id) { 'CVE-2013-0155' }

  subject { described_class.new(directory) }

  # All identifiers (id, CVE-, GHSA-, OSVDB-) of the advisories in the results.
  def identifiers_of(results)
    results.grep(Results::UnpatchedGem).flat_map { |result|
      result.advisory.identifiers
    }
  end

  describe "#initialize" do
    context "when given no arguments" do
      subject { described_class }

      context "when a Gemfile.lock exists in Dir.pwd" do
        it "must default root to Dir.pwd" do
          Dir.chdir(directory) do
            scanner = subject.new
            expect(scanner.root).to eq(File.expand_path(Dir.pwd))
          end
        end
      end
    end

    context "when given a root directory" do
      let(:root) { directory }

      subject { described_class.new(root) }

      it "must set #root to the expanded directory path" do
        expect(subject.root).to eq(File.expand_path(root))
      end

      it "must set #database" do
        expect(subject.database).to be_kind_of(Database)
      end

      it "must set #lockfile by parsing the Gemfile.lock" do
        expect(subject.lockfile).to be_kind_of(Bundler::LockfileParser)
      end

      it "must set #config to a default Configuration when no config file exists" do
        expect(subject.config).to be_kind_of(Configuration)
        expect(subject.config.ignore).to be_empty
      end
    end

    context "when the Gemfile.lock does not exist in the root directory" do
      let(:bad_dir) { File.join('spec','bundle','nonexistent') }

      it "must raise Bundler::GemfileLockNotFound" do
        expect {
          described_class.new(bad_dir)
        }.to raise_error(Bundler::GemfileLockNotFound)
      end

      it "must include the lock file name and root in the error message" do
        expect {
          described_class.new(bad_dir)
        }.to raise_error(Bundler::GemfileLockNotFound, /Gemfile\.lock/)
      end
    end

    context "when given a custom gemfile_lock name" do
      it "must raise Bundler::GemfileLockNotFound if the custom lock file does not exist" do
        expect {
          described_class.new(directory, 'NoSuchLockFile.lock')
        }.to raise_error(Bundler::GemfileLockNotFound)
      end

      it "must use the custom gemfile_lock name" do
        scanner = described_class.new(directory, 'Gemfile.lock')
        expect(scanner.lockfile).to be_kind_of(Bundler::LockfileParser)
      end
    end

    context "when given a custom database" do
      let(:custom_db) { Database.new }

      subject { described_class.new(directory, 'Gemfile.lock', custom_db) }

      it "must set #database to the custom database" do
        expect(subject.database).to be(custom_db)
      end
    end

    context "when a .bundler-audit.yml config file exists" do
      let(:bundle) { 'unpatched_gems_with_dot_configuration' }

      subject { described_class.new(directory) }

      it "must load the configuration from the config file" do
        expect(subject.config).to be_kind_of(Configuration)
        expect(subject.config.ignore).to include(ignored_id)
      end
    end

    context "when given a custom config_dot_file" do
      let(:config_path) { File.join('spec','bundle','unpatched_gems_with_dot_configuration','.bundler-audit.yml') }

      context "when the config_dot_file is an absolute path" do
        let(:absolute_config_path) { File.absolute_path(config_path) }

        subject { described_class.new(directory, 'Gemfile.lock', Database.new, absolute_config_path) }

        it "must load the configuration from the absolute path" do
          expect(subject.config).to be_kind_of(Configuration)
          expect(subject.config.ignore).to include(ignored_id)
        end
      end

      context "when the config_dot_file is a relative path" do
        let(:relative_config_path) { File.join('..','unpatched_gems_with_dot_configuration','.bundler-audit.yml') }

        subject { described_class.new(directory, 'Gemfile.lock', Database.new, relative_config_path) }

        it "must load the configuration from the relative path" do
          expect(subject.config).to be_kind_of(Configuration)
          expect(subject.config.ignore).to include(ignored_id)
        end
      end
    end

    context "when no .bundler-audit.yml config file exists" do
      let(:bundle) { 'secure' }

      subject { described_class.new(directory) }

      it "must set #config to a default empty Configuration" do
        expect(subject.config).to be_kind_of(Configuration)
        expect(subject.config.ignore).to be_empty
      end
    end
  end

  describe "#scan" do
    it "should yield results" do
      results = []

      subject.scan { |result| results << result }

      expect(results).not_to be_empty
    end

    context "when not called with a block" do
      it "should return an Enumerator" do
        expect(subject.scan).to be_kind_of(Enumerable)
      end
    end

    context "when auditing a bundle with unpatched gems" do
      let(:bundle) { 'unpatched_gems' }

      context "with defaults" do
        subject { super().scan.to_a }

        it "should match unpatched gems to their advisories" do
          expect(subject.all? { |result|
            result.advisory.vulnerable?(result.gem.version)
          }).to be_truthy
        end

        it "should find the advisory used by the ignore specs" do
          expect(identifiers_of(subject)).to include(ignored_id)
        end
      end

      context "when the :ignore option is given" do
        subject { super().scan(ignore: [ignored_id]) }

        it "should ignore the specified advisories" do
          expect(identifiers_of(subject)).not_to include(ignored_id)
        end

        it "should still report other advisories" do
          expect(subject.to_a).not_to be_empty
        end
      end

      context "when ignoring by a different identifier of the same advisory" do
        let(:advisory) do
          described_class.new(directory).scan.to_a.grep(Results::UnpatchedGem).map(&:advisory).find { |advisory|
            advisory.identifiers.include?(ignored_id)
          }
        end

        it "should ignore the advisory by its GHSA id" do
          ghsa_id = advisory.ghsa_id
          skip "fixture advisory has no GHSA identifier" unless ghsa_id

          results = described_class.new(directory).scan(ignore: [ghsa_id])

          expect(identifiers_of(results)).not_to include(ignored_id)
        end

        it "should ignore the advisory by its primary id" do
          results = described_class.new(directory).scan(ignore: [advisory.id])

          expect(identifiers_of(results)).not_to include(ignored_id)
        end
      end
    end

    context "when auditing a bundle with insecure sources" do
      let(:bundle) { 'insecure_sources' }

      subject { super().scan.to_a }

      it "should match unpatched gems to their advisories" do
        expect(subject[0].source).to eq('git://github.com/rails/jquery-rails.git')
        expect(subject[1].source).to eq('http://rubygems.org/')
      end
    end

    context "when auditing a secure bundle" do
      let(:bundle) { 'secure' }

      subject { super().scan.to_a }

      it "should print nothing when everything is fine" do
        expect(subject).to be_empty
      end
    end

    context "when the ignore option is configured in .bundler-audit.yml" do
      let(:bundle)    { 'unpatched_gems_with_dot_configuration' }
      let(:directory) { File.join('spec','bundle',bundle) }
      let(:scanner)  { described_class.new(directory) }

      subject { scanner.scan }

      it "should report the advisory when nothing is ignored" do
        # Control: an explicit empty :ignore list bypasses the config file.
        results = scanner.scan(ignore: [])

        expect(identifiers_of(results)).to include(ignored_id)
      end

      it "should ignore the specified advisories" do
        expect(identifiers_of(subject)).not_to include(ignored_id)
      end

      context "when config path is absolute" do
        let(:bundle) { 'unpatched_gems' }
        let(:absolute_config_path) { File.absolute_path(File.join('spec','bundle','unpatched_gems_with_dot_configuration', '.bundler-audit.yml')) }
        let(:scanner) { described_class.new(directory,'Gemfile.lock',Database.new,absolute_config_path) }

        it "should read the config just fine" do
          expect(identifiers_of(subject)).not_to include(ignored_id)
        end
      end

      context "when config path is relative" do
        let(:bundle) { 'unpatched_gems' }
        let(:relative_config_path) { File.join('..', 'unpatched_gems_with_dot_configuration', '.bundler-audit.yml') }
        let(:scanner) { described_class.new(directory,'Gemfile.lock',Database.new,relative_config_path) }

        it "should read the config just fine" do
          expect(identifiers_of(subject)).not_to include(ignored_id)
        end
      end
    end
  end

  describe "#report" do
    let(:expected_results) { subject.scan.to_a }

    it "should return a Report object containing the results" do
      report = subject.report

      expect(report).to be_a(Bundler::Audit::Report)
      expect(report.results).to all(be_kind_of(Bundler::Audit::Results::Result))
    end

    context "when given a block" do
      it "should yield results" do
        results = []

        subject.report { |result| results << result }

        expect(results).to_not be_empty
        expect(results).to all(be_kind_of(Bundler::Audit::Results::Result))
      end
    end
  end
end
