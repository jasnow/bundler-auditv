require 'spec_helper'
require 'bundler/audit/database'
require 'bundler/audit/advisory'

require 'date'
require 'json'
require 'tmpdir'

describe Bundler::Audit::Advisory do
  let(:root) { Fixtures::DATABASE_PATH }
  let(:gem)  { 'test' }
  let(:id)   { 'CVE-2020-1234' }
  let(:path) { Fixtures.join('advisory',"#{id}.json") }

  subject { described_class.load(path) }

  # Fixture ranges: affected 0.1.0...1.0.0 and 2.0.0...2.1.0, so
  #   unaffected_versions: ["< 0.1.0"]
  #   patched_versions:    [">= 1.0.0, < 2.0.0", ">= 2.1.0"]
  let(:a_patched_version)     { '1.0.0' }
  let(:an_unaffected_version) { '0.0.9' }

  # Loads an advisory from an in-memory OSV record.
  def load_record(record)
    Dir.mktmpdir do |dir|
      file = File.join(dir,"#{record['id'] || 'record'}.json")
      File.write(file,JSON.generate(record))

      described_class.load(file)
    end
  end

  # Builds an advisory from OSV `affected` entries.
  def advisory_for(affected)
    unaffected, patched = described_class.parse_affected(affected)

    described_class.new.tap do |advisory|
      advisory.unaffected_versions = unaffected
      advisory.patched_versions    = patched
    end
  end

  def affected_with(ranges=[],versions=nil)
    entry = {
      'package' => {'ecosystem' => 'RubyGems', 'name' => 'test'},
      'ranges'  => ranges.map { |events| {'type' => 'ECOSYSTEM', 'events' => events} }
    }
    entry['versions'] = versions if versions

    [entry]
  end

  def constraints(requirements)
    requirements.map { |req| req.requirements.map { |op,ver| "#{op} #{ver}" }.sort }
  end

  describe "load" do
    let(:data) { JSON.parse(File.read(path)) }

    describe '#id' do
      subject { super().id }
      it { is_expected.to eq(id)                  }
    end

    describe '#url' do
      subject { super().url }
      it { is_expected.to eq('https://github.com/advisories/GHSA-xfhh-rx56-rxcr') }
    end

    describe '#title' do
      subject { super().title }
      it { is_expected.to eq(data['summary'])     }
    end

    describe '#date' do
      subject { super().date }
      it { is_expected.to eq(Date.parse(data['published'])) }
    end

    describe '#cvss_v2' do
      subject { super().cvss_v2 }
      it { is_expected.to be_nil }
    end

    describe '#cvss_v3' do
      subject { super().cvss_v3 }
      it { is_expected.to be_nil }
    end

    describe '#cvss_v4' do
      subject { super().cvss_v4 }
      it { is_expected.to be_nil }
    end

    describe '#description' do
      subject { super().description }
      it { is_expected.to eq(data['details'])     }
    end

    describe '#cve' do
      subject { super().cve }
      it { is_expected.to eq('2020-1234') }
    end

    describe '#ghsa' do
      subject { super().ghsa }
      it { is_expected.to eq('xfhh-rx56-rxcr') }
    end

    describe '#identifiers' do
      subject { super().identifiers }
      it { is_expected.to eq(['CVE-2020-1234', 'GHSA-xfhh-rx56-rxcr']) }
    end

    context "JSON data not representing a hash" do
      let(:path) do
        File.expand_path('../fixtures/advisory/not_a_hash.json', __FILE__)
      end

      it "should raise an exception" do
        expect {
          Advisory.load(path)
        }.to raise_exception("advisory data in #{path.dump} was not a Hash")
      end
    end

    context "when the record has no references" do
      subject do
        load_record('id' => 'GHSA-aaaa-bbbb-cccc', 'summary' => 'A summary')
      end

      it "should link to osv.dev" do
        expect(subject.url).to eq('https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc')
      end

      it "should extract the GHSA id from the record id" do
        expect(subject.ghsa).to eq('aaaa-bbbb-cccc')
        expect(subject.cve).to be_nil
      end

      it "should fall back to the summary for the description" do
        expect(subject.description).to eq('A summary')
      end
    end

    context "when the record has no summary or details" do
      subject { load_record('id' => 'GHSA-aaaa-bbbb-cccc') }

      it "should use the id as the title and never leave a nil description" do
        expect(subject.title).to eq('GHSA-aaaa-bbbb-cccc')
        expect(subject.description).to eq('')
      end
    end

    describe "#patched_versions" do
      subject { described_class.load(path).patched_versions }

      it "should all be Gem::Requirement objects" do
        expect(subject.all? { |version|
          expect(version).to be_kind_of(Gem::Requirement)
        }).to be_truthy
      end

      it "should parse the versions" do
        expect(constraints(subject)).to eq([
          ['< 2.0.0', '>= 1.0.0'],
          ['>= 2.1.0']
        ])
      end
    end

    describe "#unaffected_versions" do
      subject { described_class.load(path).unaffected_versions }

      it "should parse the versions" do
        expect(constraints(subject)).to eq([['< 0.1.0']])
      end
    end
  end

  describe ".parse_affected" do
    context "with several maintained branches" do
      subject do
        advisory_for(affected_with([[
          {'introduced' => '0'},     {'fixed' => '2.3.18'},
          {'introduced' => '3.0.0'}, {'fixed' => '3.1.12'},
          {'introduced' => '3.2.0'}, {'fixed' => '3.2.13'}
        ]]))
      end

      %w[2.3.17 3.0.0 3.1.11 3.2.0 3.2.12].each do |version|
        it "should consider #{version} vulnerable" do
          expect(subject.vulnerable?(Gem::Version.new(version))).to be true
        end
      end

      %w[2.3.18 3.1.12 3.1.99 3.2.13 4.0.0].each do |version|
        it "should consider #{version} patched" do
          expect(subject.vulnerable?(Gem::Version.new(version))).to be false
        end
      end
    end

    context "with last_affected" do
      subject do
        advisory_for(affected_with([[
          {'introduced' => '1.0.0'}, {'last_affected' => '1.5.0'}
        ]]))
      end

      it "should treat last_affected as inclusive" do
        expect(subject.vulnerable?(Gem::Version.new('1.0.0'))).to be true
        expect(subject.vulnerable?(Gem::Version.new('1.5.0'))).to be true
      end

      it "should treat versions outside the range as safe" do
        expect(subject.vulnerable?(Gem::Version.new('0.9.9'))).to be false
        expect(subject.vulnerable?(Gem::Version.new('1.5.1'))).to be false
      end
    end

    context "with an open-ended range (no fix)" do
      subject { advisory_for(affected_with([[{'introduced' => '2.0.0'}]])) }

      it "should have no patched versions" do
        expect(subject.patched_versions).to be_empty
      end

      it "should be vulnerable from the introduced version onward" do
        expect(subject.vulnerable?(Gem::Version.new('1.9.9'))).to be false
        expect(subject.vulnerable?(Gem::Version.new('2.0.0'))).to be true
        expect(subject.vulnerable?(Gem::Version.new('99.0.0'))).to be true
      end
    end

    context "with overlapping ranges" do
      subject do
        advisory_for(affected_with([
          [{'introduced' => '0'},     {'fixed' => '2.0.0'}],
          [{'introduced' => '1.0.0'}, {'fixed' => '3.0.0'}]
        ]))
      end

      it "should merge them" do
        expect(subject.vulnerable?(Gem::Version.new('2.5.0'))).to be true
        expect(subject.vulnerable?(Gem::Version.new('3.0.0'))).to be false
        expect(constraints(subject.patched_versions)).to eq([['>= 3.0.0']])
      end
    end

    context "with touching ranges" do
      subject do
        advisory_for(affected_with([
          [{'introduced' => '0'},     {'fixed' => '1.0.0'}],
          [{'introduced' => '1.0.0'}, {'fixed' => '2.0.0'}]
        ]))
      end

      it "should leave no gap between them" do
        expect(subject.vulnerable?(Gem::Version.new('1.0.0'))).to be true
        expect(constraints(subject.patched_versions)).to eq([['>= 2.0.0']])
      end
    end

    context "with only an explicit versions list" do
      subject { advisory_for(affected_with([],['1.2.3'])) }

      it "should only flag the listed version" do
        expect(subject.vulnerable?(Gem::Version.new('1.2.3'))).to be true
        expect(subject.vulnerable?(Gem::Version.new('1.2.2'))).to be false
        expect(subject.vulnerable?(Gem::Version.new('1.2.4'))).to be false
      end
    end

    context "when a listed version is also inside a range" do
      subject do
        advisory_for(affected_with(
          [[{'introduced' => '0'}, {'fixed' => '2.0.0'}]],
          ['1.0.0', '1.5.0']
        ))
      end

      it "should not create gaps or duplicate patched versions" do
        expect(constraints(subject.patched_versions)).to eq([['>= 2.0.0']])
        expect(subject.unaffected_versions).to be_empty
      end
    end

    context "when nothing can be parsed" do
      it "should fail closed when there are no ranges" do
        advisory = advisory_for(affected_with([]))

        expect(advisory.patched_versions).to be_empty
        expect(advisory.unaffected_versions).to be_empty
        expect(advisory.vulnerable?(Gem::Version.new('1.0.0'))).to be true
      end

      it "should ignore non-ECOSYSTEM ranges" do
        affected = [{
          'package' => {'ecosystem' => 'RubyGems', 'name' => 'test'},
          'ranges'  => [{'type' => 'GIT', 'events' => [{'introduced' => '0'}, {'fixed' => 'abc123'}]}]
        }]

        expect(advisory_for(affected).vulnerable?(Gem::Version.new('1.0.0'))).to be true
      end

      it "should leave the range open when the fixed version is malformed" do
        advisory = advisory_for(affected_with([[
          {'introduced' => '1.0.0'}, {'fixed' => 'not a version!'}
        ]]))

        expect(advisory.vulnerable?(Gem::Version.new('5.0.0'))).to be true
      end
    end
  end

  describe "#cve_id" do
    let(:cve) { "2015-1234" }

    subject do
      described_class.new.tap do |advisory|
        advisory.cve = cve
      end
    end

    it "should prepend CVE- to the CVE id" do
      expect(subject.cve_id).to be == "CVE-#{cve}"
    end

    context "when cve is nil" do
      subject { described_class.new }

      it { expect(subject.cve_id).to be_nil }
    end
  end

  describe "#osvdb_id" do
    let(:osvdb) { "123456" }

    subject do
      described_class.new.tap do |advisory|
        advisory.osvdb = osvdb
      end
    end

    it "should prepend OSVDB- to the OSVDB id" do
      expect(subject.osvdb_id).to be == "OSVDB-#{osvdb}"
    end

    context "when cve is nil" do
      subject { described_class.new }

      it { expect(subject.osvdb_id).to be_nil }
    end
  end

  describe "#ghsa_id" do
    let(:ghsa) { "xfhh-rx56-rxcr" }

    subject do
      described_class.new.tap do |advisory|
        advisory.ghsa = ghsa
      end
    end

    it "should prepend GHSA- to the GHSA id" do
      expect(subject.ghsa_id).to be == "GHSA-#{ghsa}"
    end

    context "when ghsa is nil" do
      subject { described_class.new }

      it { expect(subject.ghsa_id).to be_nil }
    end
  end

  describe "#identifiers" do
    it "should include all identifiers if defined" do
      advisory = described_class.new.tap do |advisory|
        advisory.cve = "2018-1234"
        advisory.osvdb = "2019-2345"
        advisory.ghsa = "2020-3456"
      end

      expect(advisory.identifiers).to eq([
        "CVE-2018-1234",
        "OSVDB-2019-2345",
        "GHSA-2020-3456"
      ])
    end

    it "should exclude nil identifiers" do
      advisory = described_class.new
      expect(advisory.identifiers).to eq([])

      advisory = described_class.new.tap do |advisory|
        advisory.cve = "2018-1234"
      end
      expect(advisory.identifiers).to eq(["CVE-2018-1234"])

      advisory = described_class.new.tap do |advisory|
        advisory.ghsa = "2020-3456"
      end
      expect(advisory.identifiers).to eq(["GHSA-2020-3456"])
    end

    it "should include the primary id without duplicating it" do
      advisory = described_class.new.tap do |advisory|
        advisory.id  = "GHSA-2020-3456"
        advisory.ghsa = "2020-3456"
      end

      expect(advisory.identifiers).to eq(["GHSA-2020-3456"])

      advisory.id = "OSV-2020-1"
      expect(advisory.identifiers).to eq(["OSV-2020-1", "GHSA-2020-3456"])
    end
  end

  describe "#criticality" do
    context "when cvss_v2 is between 0.0 and 3.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v2 = 3.9
        end
      end

      it { expect(subject.criticality).to eq(:low) }
    end

    context "when cvss_v2 is between 4.0 and 6.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v2 = 6.9
        end
      end

      it { expect(subject.criticality).to eq(:medium) }
    end

    context "when cvss_v2 is between 7.0 and 10.0" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v2 = 10.0
        end
      end

      it { expect(subject.criticality).to eq(:high) }
    end

    context "when cvss_v3 is 0.0" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v3 = 0.0
        end
      end

      it { expect(subject.criticality).to eq(:none) }
    end

    context "when cvss_v3 is between 0.1 and 3.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v3 = 3.9
        end
      end

      it { expect(subject.criticality).to eq(:low) }
    end

    context "when cvss_v3 is between 4.0 and 6.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v3 = 6.9
        end
      end

      it { expect(subject.criticality).to eq(:medium) }
    end

    context "when cvss_v3 is between 7.0 and 8.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v3 = 8.9
        end
      end

      it { expect(subject.criticality).to eq(:high) }
    end

    context "when cvss_v3 is between 9.0 and 10.0" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v3 = 10.0
        end
      end

      it { expect(subject.criticality).to eq(:critical) }
    end

    context "when cvss_v4 is 0.0" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v4 = 0.0
        end
      end

      it { expect(subject.criticality).to eq(:none) }
    end

    context "when cvss_v4 is between 0.1 and 3.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v4 = 3.9
        end
      end

      it { expect(subject.criticality).to eq(:low) }
    end

    context "when cvss_v4 is between 4.0 and 6.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v4 = 6.9
        end
      end

      it { expect(subject.criticality).to eq(:medium) }
    end

    context "when cvss_v4 is between 7.0 and 8.9" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v4 = 8.9
        end
      end

      it { expect(subject.criticality).to eq(:high) }
    end

    context "when cvss_v4 is between 9.0 and 10.0" do
      subject do
        described_class.new.tap do |advisory|
          advisory.cvss_v4 = 10.0
        end
      end

      it { expect(subject.criticality).to eq(:critical) }
    end

    context "when there is no numeric CVSS score" do
      it "should fall back to the OSV severity label" do
        {
          'LOW'      => :low,
          'MODERATE' => :medium,
          'MEDIUM'   => :medium,
          'HIGH'     => :high,
          'CRITICAL' => :critical
        }.each do |label,criticality|
          advisory = load_record(
            'id' => 'GHSA-aaaa-bbbb-cccc',
            'database_specific' => {'severity' => label}
          )

          expect(advisory.criticality).to eq(criticality)
        end
      end

      it "should be nil when the record has no severity" do
        expect(load_record('id' => 'GHSA-aaaa-bbbb-cccc').criticality).to be_nil
      end

      it "should prefer a numeric score over the label" do
        advisory = described_class.new.tap do |advisory|
          advisory.cvss_v3  = 2.0
          advisory.severity = :critical
        end

        expect(advisory.criticality).to eq(:low)
      end
    end
  end

  describe "#unaffected?" do
    context "when passed a version that matches one unaffected version" do
      let(:version) { Gem::Version.new(an_unaffected_version) }

      it "should return true" do
        expect(subject.unaffected?(version)).to be_truthy
      end
    end

    context "when passed a version that matches no unaffected version" do
      let(:version) { Gem::Version.new('3.0.9') }

      it "should return false" do
        expect(subject.unaffected?(version)).to be_falsey
      end
    end
  end

  describe "#patched?" do
    context "when passed a version that matches one patched version" do
      let(:version) { Gem::Version.new(a_patched_version) }

      it "should return true" do
        expect(subject.patched?(version)).to be_truthy
      end
    end

    context "when passed a version that matches no patched version" do
      let(:version) { Gem::Version.new('0.1.1') }

      it "should return false" do
        expect(subject.patched?(version)).to be_falsey
      end
    end
  end

  describe "#vulnerable?" do
    context "when passed a version that matches one patched version" do
      let(:version) { Gem::Version.new(a_patched_version) }

      it "should return false" do
        expect(subject.vulnerable?(version)).to be_falsey
      end
    end

    context "when passed a version that matches no patched version" do
      let(:version) { Gem::Version.new('0.1.1') }

      it "should return true" do
        expect(subject.vulnerable?(version)).to be_truthy
      end

      context "when unaffected_versions is not empty" do
        context "when passed a version that matches one unaffected version" do
          let(:version) { Gem::Version.new(an_unaffected_version) }

          it "should return false" do
            expect(subject.vulnerable?(version)).to be_falsey
          end
        end

        context "when passed a version that matches no unaffected version" do
          let(:version) { Gem::Version.new('0.1.0') }

          it "should return true" do
            expect(subject.vulnerable?(version)).to be_truthy
          end
        end
      end
    end

    context "when passed a version in a second affected range" do
      let(:version) { Gem::Version.new('2.0.5') }

      it "should return true" do
        expect(subject.vulnerable?(version)).to be_truthy
      end
    end
  end

  describe "#to_h" do
    subject { super().to_h }

    it "must include criticality: :critical" do
      expect(subject[:criticality]).to be :critical
    end
  end
end
