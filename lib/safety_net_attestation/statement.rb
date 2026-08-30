# frozen_string_literal: true

require "jwt"
require "openssl"
require "time"
require_relative "errors"
require_relative "fixed_length_secure_compare"
require_relative "x5c_key_finder"

module SafetyNetAttestation
  class Statement
    GOOGLE_ROOT_CERTIFICATES = Dir.glob(
      File.join(SafetyNetAttestation::GEM_ROOT, "safety_net_attestation", "certificates", "*.*")
    ).map do |path|
      file = File.binread(path)
      OpenSSL::X509::Certificate.new(file)
    end.freeze

    using FixedLengthSecureCompare

    attr_reader :json

    def initialize(jws_result)
      @jws_result = jws_result
    end

    def verify(nonce, timestamp_leeway: 60, trusted_certificates: GOOGLE_ROOT_CERTIFICATES, time: Time.now)
      certificate_chain = nil
      response, _ = JWT.decode(@jws_result, nil, true, algorithms: ["ES256", "RS256"]) do |headers|
        x5c_certificates = decode_x5c_certificates(headers["x5c"])

        certificate_chain = X5cKeyFinder.from(x5c_certificates, trusted_certificates, time: time)
        certificate_chain.first.public_key
      end
      raise MalformedStatementError, "JWT payload must be a JSON object" unless response.is_a?(Hash)

      verify_certificate_subject(certificate_chain.first)
      verify_nonce(response, nonce)
      verify_timestamp(response, timestamp_leeway, time)

      @json = response
      @certificate_chain = certificate_chain
      self
    rescue JWT::DecodeError => e
      raise MalformedStatementError, "JWT verification failed: #{e.message}"
    end

    def cts_profile_match?
      raise NotVerifiedError unless json

      json["ctsProfileMatch"]
    end

    def basic_integrity?
      raise NotVerifiedError unless json

      json["basicIntegrity"]
    end

    def apk_package_name
      raise NotVerifiedError unless json

      json["apkPackageName"]
    end

    def apk_certificate_digest_sha256
      raise NotVerifiedError unless json

      json["apkCertificateDigestSha256"]
    end

    def error
      raise NotVerifiedError unless json

      json["error"]
    end

    def advice
      raise NotVerifiedError unless json

      json["advice"]&.split(",")
    end

    def certificate_chain
      raise NotVerifiedError unless json

      @certificate_chain
    end

    private

    def decode_x5c_certificates(encoded_certificates)
      unless encoded_certificates.is_a?(Array) && !encoded_certificates.empty? &&
             encoded_certificates.all? { |encoded| encoded.is_a?(String) }
        raise SignatureError, "JWT x5c header must contain a certificate chain"
      end

      encoded_certificates.map do |encoded|
        OpenSSL::X509::Certificate.new(Base64.strict_decode64(encoded))
      end
    rescue ArgumentError, OpenSSL::X509::CertificateError => e
      raise SignatureError, "JWT x5c header contains an invalid certificate: #{e.message}"
    end

    def verify_certificate_subject(certificate)
      common_name = certificate.subject.to_a.assoc("CN")

      unless common_name && common_name[1] == "attest.android.com"
        raise CertificateSubjectError
      end
    end

    def verify_nonce(response, nonce)
      response_nonce = response["nonce"]
      unless nonce.is_a?(String) && response_nonce.is_a?(String) && nonce.bytesize == response_nonce.bytesize &&
             OpenSSL.fixed_length_secure_compare(nonce, response_nonce)
        raise NonceMismatchError
      end
    end

    def verify_timestamp(response, leeway, time)
      now = time.to_f
      timestamp = response["timestampMs"]
      unless timestamp.is_a?(Numeric) && timestamp.respond_to?(:finite?) && timestamp.finite?
        raise TimestampError, "timestampMs must be a finite number"
      end

      response_time = timestamp / 1000.0
      unless response_time.between?(now - leeway, now + leeway)
        raise TimestampError, "not within #{leeway}s leeway"
      end
    end
  end
end
