# lib/bundler/audit/database.rb  (DRAFT: swaps ruby-advisory-db/git for the OSV RubyGems dump)
#
# Design: keep the on-disk layout the rest of the code already expects
# (<path>/gems/<gem name>/<advisory>.<ext>), so each_advisory_path_for,
# advisories_for, check_gem, size, etc. need no changes beyond the file glob.
# update! downloads the OSV RubyGems dump and re-indexes it by gem name.

require 'bundler/audit/advisory'

require 'fileutils'
require 'json'
require 'net/http'
require 'time'
require 'uri'
require 'zip' # rubyzip: replaces the old `git` requirement

module Bundler
  module Audit
    class Database

      # OSV bulk dump of every RubyGems advisory (replaces the git URL).
      URL = 'https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip'

      USER_PATH = File.expand_path(File.join(Gem.user_home,'.local','share','osv-rubygems'))

      DEFAULT_PATH = ENV.fetch('BUNDLER_AUDIT_DB',USER_PATH)

      class DownloadFailed < RuntimeError; end
      class UpdateFailed   < RuntimeError; end

      SAFE_NAME = /\A[A-Za-z0-9._\-]+\z/.freeze

      attr_reader :path

      def initialize(path=self.class.path)
        unless File.directory?(path)
          raise(ArgumentError,"#{path.dump} is not a directory")
        end

        @path = path
      end

      def self.path
        DEFAULT_PATH
      end

      def self.exists?(path=DEFAULT_PATH)
        File.directory?(File.join(path,'gems'))
      end

      def self.download(options={})
        unless (options.keys - [:path, :quiet]).empty?
          raise(ArgumentError,"Invalid option(s)")
        end

        path = options.fetch(:path,DEFAULT_PATH)
        FileUtils.mkdir_p(path)

        begin
          install(fetch_zip(URI(URL)),path)
        rescue SocketError, SystemCallError, Zip::Error, JSON::ParserError => e
          raise(DownloadFailed,"failed to download #{URL}: #{e.message}")
        end

        new(path)
      end

      def self.update!(options={})
        raise("Invalid option(s)") unless (options.keys - [:quiet]).empty?

        if exists?(DEFAULT_PATH)
          begin
            new(DEFAULT_PATH).update!(options)
          rescue UpdateFailed
            false
          end
        else
          begin
            download(options)
            true
          rescue DownloadFailed
            false
          end
        end
      end

      def update!(options={})
        self.class.download(options.merge(path: @path))
        true
      rescue DownloadFailed => e
        raise(UpdateFailed,e.message)
      end

      def last_updated_at
        File.mtime(@path)
      end

      # The old git commit id has no equivalent for a zip dump.
      def commit_id
        nil
      end

      def advisories(&block)
        return enum_for(__method__) unless block_given?

        each_advisory_path { |path| yield Advisory.load(path) }
      end

      def advisories_for(name)
        return enum_for(__method__,name) unless block_given?

        each_advisory_path_for(name) { |path| yield Advisory.load(path) }
      end

      def check_gem(gem)
        return enum_for(__method__,gem) unless block_given?

        advisories_for(gem.name) do |advisory|
          yield advisory if advisory.vulnerable?(gem.version)
        end
      end

      def size
        each_advisory_path.count
      end

      def to_s
        @path
      end

      def inspect
        "#<#{self.class}:#{self}>"
      end

      protected

      def each_advisory_path(&block)
        return enum_for(__method__) unless block_given?

        Dir.glob(File.join(@path,'gems','*','*.json'),&block)
      end

      def each_advisory_path_for(name,&block)
        return enum_for(__method__,name) unless block_given?
        return unless name =~ SAFE_NAME

        Dir.glob(File.join(@path,'gems',name,'*.json'),&block)
      end

      private

      def self.fetch_zip(uri,limit=5)
        raise(DownloadFailed,'too many redirects') if limit == 0

        response = Net::HTTP.get_response(uri)

        case response
        when Net::HTTPSuccess     then response.body
        when Net::HTTPRedirection then fetch_zip(URI(response['location']),limit - 1)
        else raise(DownloadFailed,"#{response.code} #{response.message}")
        end
      end

      # Unpacks the dump into a temp dir, then swaps it in, so a failed
      # update never leaves a half-written database behind.
      def self.install(zip_data,path)
        staging = File.join(path,"gems.new.#{Process.pid}")
        FileUtils.rm_rf(staging)

        Zip::File.open_buffer(zip_data) do |zip|
          zip.each do |entry|
            next unless entry.name.end_with?('.json')

            record = JSON.parse(entry.get_input_stream.read)
            next if record['withdrawn']
            next unless record['id'].to_s =~ SAFE_NAME

            names = Array(record['affected']).map { |a|
              pkg = a['package'] || {}
              pkg['name'] if pkg['ecosystem'] == 'RubyGems'
            }.compact.uniq

            names.each do |name|
              next unless name =~ SAFE_NAME # never trust names for paths

              dir = File.join(staging,name)
              FileUtils.mkdir_p(dir)
              File.write(File.join(dir,"#{record['id']}.json"),JSON.generate(record))
            end
          end
        end

        final = File.join(path,'gems')
        FileUtils.rm_rf(final)
        FileUtils.mv(staging,final)
        FileUtils.touch(path)
      ensure
        FileUtils.rm_rf(staging) if staging
      end

    end
  end
end
