# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/hashid"

describe LogStash::Filters::Hashid do

  describe 'Full MD5, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'MD5'
          timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == 'Q1nsJNndnZbJCUdpESyaQw'
    end
  end

  describe '12 byte MD5, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'MD5'
          timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == '2d2dlskJR2kRLJpD'
    end
  end

  describe 'Full SHA1, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA1'
          timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == '4Z0cdm66w+ybeEmJ2FNJQk+Ozo8'
    end
  end

  describe '12 byte SHA1, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA1'
          timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == 'm3hJidhTSUJPjs6P'
    end
  end

  describe 'Full SHA256, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA256'
          timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == 'fkJYY49AW4WvgIdHPxVV+XRli7DIFibPlAzc7AfYsyE'
    end
  end

  describe '12 byte SHA256, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA256'
          timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == 'yBYmz5QM3OwH2LMh'
    end
  end

  describe 'Full SHA384, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA384'
          timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == '67pMQGQreLAz4lZ6HbheeV4yZNSJeIvHHKC53EYIO5kxLqOd7m8threLV88U2KoD'
    end
  end

  describe '12 byte SHA384, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA384'
          timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == '7m8threLV88U2KoD'
    end
  end

  describe 'Full SHA512, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA512'
          timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == 'ZOf6aUmqa8U61Yh1Cq9pkUhc3/CmWLe53OB+/Z3gMoqKtfwt5hDHHNFpvvw1Fw2WgfKW5xatBTq3yZsU1U9Kgg'
    end
  end

  describe '12 byte SHA512, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA512'
          timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject["hashid"] } == 'Fq0FOrfJmxTVT0qC'
    end
  end

  context 'Timestamps' do
    epoch_time = Time.at(1451613600).gmtime

    describe 'Full MD5 with timestamp prefix' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['message']
            method => 'MD5'
            timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "message" => "testmessage") do
        insist { subject["hashid"] } == 'VoXdoENZ7CTZ3Z2WyQlHaREsmkM'
      end
    end

    describe 'Full MD5 with timestamp prefix and concatenated source part 1' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['part1','part2']
            method => 'MD5'
            timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "part1" => "test", "part2" => "message") do
        insist { subject["hashid"] } == 'VoXdoAJye/IGBcaITA1N6mqFfH0'
      end
    end

    describe 'Full MD5 with timestamp prefix and concatenated source part 2' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['part2','part1']
            method => 'MD5'
            timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "part2" => "message", "part1" => "test") do
        insist { subject["hashid"] } == 'VoXdoAJye/IGBcaITA1N6mqFfH0'
      end
    end

    describe 'Full MD5 with timestamp prefix and concatenated timestamp' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['@timestamp','message']
            method => 'MD5'
            timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "message" => "testmessage") do
        insist { subject["hashid"] } == 'VoXdoHTcOT2UXfHgYC9BeV5DrT0'
      end
    end

    describe '12 byte MD5 with timestamp prefix' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['message']
            method => 'MD5'
            timestamp_prefix => true
            hash_bytes_used => 12
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "message" => "testmessage") do
        insist { subject["hashid"] } == 'VoXdoNndnZbJCUdpESyaQw'
      end
    end

    describe '12 byte MD5 with custom timestamp prefix' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['message']
            method => 'MD5'
            timestamp_field => "ts"
            timestamp_prefix => true
            hash_bytes_used => 12
          }
        }
      CONFIG

      sample("ts" => epoch_time, "message" => "testmessage") do
        insist { subject["hashid"] } == 'VoXdoNndnZbJCUdpESyaQw'
      end
    end
  end

end
