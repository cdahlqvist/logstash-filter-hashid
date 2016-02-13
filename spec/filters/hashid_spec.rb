# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/hashid"

describe LogStash::Filters::Hashid do

#  Scenarios
#  - Ensure timestamp prefix results in increasing keys
#  - default source
#    - MD5
#    - Timestamp prefix + MD5
#    - MD5 (reduced length)
#    - Timestamp prefix + MD5 (reduced length)
#    - SHA1
#    - Timestamp prefix + SHA1
#    - SHA1 (reduced length)
#    - Timestamp prefix + SHA1 (reduced length)
#    - SHA256
#    - Timestamp prefix + SHA256
#    - SHA256 (reduced length)
#    - Timestamp prefix + SHA256 (reduced length)
#    - SHA384
#    - Timestamp prefix + SHA384
#    - SHA384 (reduced length)
#    - Timestamp prefix + SHA384 (reduced length)
#    - SHA512
#    - Timestamp prefix + SHA512
#    - SHA512 (reduced length)
#    - Timestamp prefix + SHA512 (reduced length)
#  - sorted source
#    - MD5
#    - Timestamp prefix + MD5

end
