require 'simplecov'

SimpleCov.start do
  enable_coverage :branch
end

require 'rspec'
require 'fileutils'
require 'zip'
require 'bundler/audit/database'

module Fixtures
  ROOT = File.expand_path('../fixtures',__FILE__)

  TMP_DIR = File.expand_path('../tmp',__FILE__)

  module Database
    # Source records: OSV JSON files, one per advisory, in the same flat
    # format as OSV's RubyGems/all.zip dump. Add records here (see the
    # note below) for every gem and advisory the specs expect to find.
    OSV_PATH = File.join(ROOT,'osv')

    # Generated database, in the layout Bundler::Audit::Database reads
    # (<PATH>/gems/<gem name>/<advisory id>.json). Safe to delete or gitignore.
    PATH = File.join(ROOT,'database')

    #
    # Zips the records in {OSV_PATH}, like OSV's all.zip dump.
    #
    # @return [String]
    #
    def self.zip_data
      files = Dir.glob(File.join(OSV_PATH,'*.json')).sort

      if files.empty?
        raise("no OSV fixture records found in #{OSV_PATH}")
      end

      buffer = Zip::OutputStream.write_buffer do |zip|
        files.each do |file|
          zip.put_next_entry(File.basename(file))
          zip.write(File.read(file))
        end
      end

      buffer.string
    end

    #
    # (Re)builds {PATH} offline from {OSV_PATH}, using the real installer.
    #
    def self.build!
      FileUtils.mkdir_p(PATH)

      Bundler::Audit::Database.install(zip_data,PATH)
    end

    # Specs that used to reset the git checkout now just rebuild it.
    def self.reset!(*)
      build!
    end
  end

  def self.join(*paths)
    File.join(ROOT,*paths)
  end
end

module Helpers
  def sh(command, options={})
    result = `#{command} 2>&1`

    if $?.success? == !!options[:fail]
      raise "FAILED #{command}\n#{result}"
    end

    result
  end

  def decolorize(string)
    string.gsub(/\e\[\d+m/, "")
  end
end

include Bundler::Audit

RSpec.configure do |config|
  include Helpers

  config.before(:suite) do
    Fixtures::Database.build!

    FileUtils.mkdir_p(Fixtures::TMP_DIR)
  end

  config.before(:each) do
    stub_const("Bundler::Audit::Database::DEFAULT_PATH",Fixtures::Database::PATH)
  end
end
