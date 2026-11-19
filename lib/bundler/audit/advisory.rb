# lib/bundler/audit/advisory.rb  (DRAFT: loads OSV JSON instead of ruby-advisory-db YAML)
#
# Keep the existing public readers (id, url, title, description, cve, ghsa,
# criticality, patched_versions, unaffected_versions, ...) so the CLI/JSON
# output code is untouched. The real change is vulnerable?: OSV describes
# affected ranges (introduced/fixed/last_affected), not "patched/unaffected"
# requirement lists, so we evaluate the ranges directly.

require 'json'
require 'rubygems'

module Bundler
  module Audit
    class Advisory

      attr_reader :path, :id, :aliases, :url, :title, :description,
                  :cve, :ghsa, :criticality, :cvss_v3,
                  :patched_versions, :unaffected_versions

      def self.load(path)
        record = JSON.parse(File.read(path))
        new(path, record)
      end

      def initialize(path, record)
        @path        = path
        @id          = record['id']
        @aliases     = Array(record['aliases'])
        @title       = record['summary']
        @description = record['details']
        @url         = pick_url(record)
        @cve         = (all_ids.find { |i| i.start_with?('CVE-') } || '').sub(/\ACVE-/, '') # old API returned id without prefix
        @cve         = nil if @cve.empty?
        @ghsa        = all_ids.find { |i| i.start_with?('GHSA-') }
        @cvss_v3     = Array(record['severity']).find { |s| s['type'] == 'CVSS_V3' }&.fetch('score', nil)
        @criticality = map_severity(record.dig('database_specific', 'severity'))

        @intervals = []
        @versions  = []
        Array(record['affected']).each do |affected|
          pkg = affected['package'] || {}
          next unless pkg['ecosystem'] == 'RubyGems'

          @versions.concat(Array(affected['versions']))
          Array(affected['ranges']).each do |range|
            @intervals.concat(intervals_for(range['events'])) if range['type'] == 'ECOSYSTEM'
          end
        end

        # Display only (the "Solution: update to ..." line); matching uses @intervals.
        @patched_versions = @intervals.map { |(_, upper, kind)|
          Gem::Requirement.new(">= #{upper}") if kind == :exclusive
        }.compact.uniq
        @unaffected_versions = []
      end

      # Also matches OSV aliases, so `--ignore CVE-...` and `--ignore GHSA-...`
      # both work no matter which ID is the record's primary one.
      def ids
        all_ids
      end

      def vulnerable?(version)
        version = Gem::Version.new(version.to_s)

        return true if @versions.any? { |v| safe_version(v) == version }

        @intervals.any? do |(lower, upper, kind)|
          (lower.nil? || version >= lower) &&
            (upper.nil? || (kind == :inclusive ? version <= upper : version < upper))
        end
      end

      def to_s
        @id
      end

      private

      def all_ids
        [@id, *@aliases].compact
      end

      def safe_version(str)
        Gem::Version.new(str)
      rescue ArgumentError
        nil
      end

      # OSV events -> [[lower, upper, :exclusive|:inclusive|nil], ...]
      # "introduced: 0" means no lower bound; no fixed/last_affected means open-ended.
      def intervals_for(events)
        intervals = []
        open  = false
        lower = nil

        Array(events).each do |event|
          if event.key?('introduced')
            open  = true
            lower = event['introduced'] == '0' ? nil : safe_version(event['introduced'])
          elsif event.key?('fixed')
            intervals << [lower, safe_version(event['fixed']), :exclusive]
            open = false
          elsif event.key?('last_affected')
            intervals << [lower, safe_version(event['last_affected']), :inclusive]
            open = false
          end
        end

        intervals << [lower, nil, nil] if open
        intervals
      end

      def pick_url(record)
        refs = Array(record['references'])
        (refs.find { |r| r['type'] == 'ADVISORY' } || refs.first || {})['url']
      end

      # GHSA uses LOW/MODERATE/HIGH/CRITICAL; the old output used :medium.
      def map_severity(value)
        case value.to_s.downcase
        when 'low'      then :low
        when 'moderate',
             'medium'   then :medium
        when 'high'     then :high
        when 'critical' then :critical
        end
      end

    end
  end
end
