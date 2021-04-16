# frozen_string_literal: true

require 'uri'
require 'net/http'
require 'json'

require 'suite_rest/version'
require 'suite_rest/rest_service_utils'
require 'suite_rest/rest_service'

module SuiteRest
  class << self
    attr_accessor :configuration
  end

  def self.configure
    self.configuration = Configuration.new
    yield(configuration)
  end

  def self.reset!
    self.configuration = Configuration.new
  end

  class Configuration
    attr_accessor :account, :consumer_key, :consumer_secret, :token_id, :token_secret, :sandbox, :base_url

    def initialize
      @sandbox = true # safe default
    end

    def auth_string(request_method:, script:, deploy: 1)
      sig_timestamp = timestamp
      sig_nonce = nonce
      %(OAuth realm="#{account}",
        oauth_consumer_key="#{consumer_key}",
        oauth_token="#{token_id}",
        oauth_signature_method = "HMAC-SHA256",
        oauth_timestamp = "#{sig_timestamp}",
        oauth_nonce = "#{sig_nonce}",
        oauth_signature = "#{signature(sig_timestamp, sig_nonce, request_method: request_method, script: script, deploy: deploy)}",
        oauth_version="1.0"
      ).tr("\n", '').strip
    end

    private

    def signature(sig_timestamp, sig_nonce, request_method:, script: , deploy:)
      CGI.escape(Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), signature_key, signature_data(sig_timestamp, sig_nonce,request_method: request_method, script: script, deploy: deploy))))
    end

    def signature_key
      "#{consumer_secret}&#{token_secret}"
    end

    def signature_data(sig_timestamp, sig_nonce, request_method:, script:, deploy: 1)
      token_string = "deploy=#{deploy}&oauth_consumer_key=#{consumer_key}&oauth_nonce=#{sig_nonce}&oauth_signature_method=HMAC-SHA256&oauth_timestamp=#{sig_timestamp}&oauth_token=#{token_id}&oauth_version=1.0&script=#{script}"
      encoded_string = CGI.escape(token_string)
      encoded_url = CGI.escape(base_url)
      "#{request_method.to_s.upcase}&#{encoded_url}&#{encoded_string}"
    end

    def nonce
      Array.new(20) { alphanumerics.sample }.join
    end

    def alphanumerics
      [*'0'..'9', *'A'..'Z', *'a'..'z']
    end

    def timestamp
      Time.now.to_i
    end
  end
end
