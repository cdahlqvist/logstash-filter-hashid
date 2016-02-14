# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "base64"
require "openssl"
require "securerandom"

#  Fingerprint fields using by replacing values with a consistent hash.
class LogStash::Filters::Hashid < LogStash::Filters::Base
  config_name "hashid"

  # Source field(s)
  config :source, :validate => :array, :default => ['message']

  # Target field.
  # will overwrite current value of a field if it exists.
  config :target, :validate => :string, :default => 'hashid'

  # Encryption key to be used when generating cryptographic hashes
  config :key, :validate => :string, :default => 'hashid'

  # Hash function to use
  config :method, :validate => ['SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5'], :default => 'MD5'

  # If full hash generated is not to be used, this parameter specifies how many bytes to use
  # If not specified, the full hash will be used
  config :hash_bytes_used, :validate => :number

  # Use the timestamp to generate an ID prefix
  config :timestamp_prefix, :validate => :boolean, :default => true

  def register
    # convert to symbol for faster comparisons
    @method = @method.to_sym
    @digest = select_digest(@method)
  end

  def filter(event)
    data = ""
        
    @source.sort.each do |k|
      data << "|#{k}|#{event[k]}"
    end

print "DATA: " + data + "\n"

    hash = OpenSSL::HMAC.digest(@digest, @key, data)

    if !@hash_bytes_used.nil? && @hash_bytes_used > 0 && hash.length > @hash_bytes_used
      hash = hash[(-1 * @hash_bytes_used), @hash_bytes_used]
    end

    if @timestamp_prefix
      epoch = event["@timestamp"].to_i
      epoch_array = []
      epoch_array.push(epoch >> 24)
      epoch_array.push((epoch >> 16) % 256)
      epoch_array.push((epoch >> 8) % 256)
      epoch_array.push(epoch % 256)
      epoch_bin = epoch_array.pack('CCCC')
    else
      epoch_bin = ""
    end

    binary_id = epoch_bin + hash

    event[@target] = Base64.strict_encode64(binary_id).force_encoding(Encoding::UTF_8).tr('=','')
  end

  def select_digest(method)
    case method
    when :SHA1
      OpenSSL::Digest::SHA1.new
    when :SHA256
      OpenSSL::Digest::SHA256.new
    when :SHA384
      OpenSSL::Digest::SHA384.new
    when :SHA512
      OpenSSL::Digest::SHA512.new
    when :MD5
      OpenSSL::Digest::MD5.new
    else
      # we really should never get here
      raise(LogStash::ConfigurationError, "Unknown digest for method=#{method.to_s}")
    end
  end
end
