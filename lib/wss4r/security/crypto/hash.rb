require "openssl"
include OpenSSL
#include OpenSSL::Digest unless Object::VERSION == "1.8.7"


module WSS4R
  module Security
    module Crypto

      class CryptHash

	def initialize(type = "SHA1")
          sha1 = Object::VERSION == "1.8.7" ? OpenSSL::Digest::SHA1 : SHA1
          md5  = Object::VERSION == "1.8.7" ? OpenSSL::Digest::MD5  : MD5
          @digest = sha1.new() if (type == "SHA1")
          @digest = md5.new()  if (type == "MD5")
	end
	
	def digest(value)
          @digest.update(value)
          return @digest.digest()
	end
	
	def digest_b64(value)
          digest = self.digest(value)
          return Base64.encode64(digest)
	end
	
	def to_s()
          return @digest.to_s()
	end
      end

    end
  end
end

