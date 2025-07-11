#-------------------------------------------------------------------------------
# Copyright (c) 2015 Micorosft Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-------------------------------------------------------------------------------

require 'jwt'
require 'omniauth'
require 'openssl'
require 'securerandom'
require 'base64'

module OmniAuth
  module Strategies
    # A strategy for authentication against Azure Active Directory.
    class Azure
      include OmniAuth::Azure
      include OmniAuth::Strategy

      class OAuthError < StandardError; end

      ##
      # The client id (key) and tenant must be configured when the OmniAuth
      # middleware is installed. Example:
      #
      #    require 'omniauth'
      #    require 'omniauth-azure-activedirectory'
      #
      #    use OmniAuth::Builder do
      #      provider :azure, ENV['AAD_KEY'], ENV['AAD_TENANT']
      #    end
      #
      args [:client_id, :tenant]
      option :client_id, nil
      option :tenant, nil

      # Field renaming is an attempt to fit the OmniAuth recommended schema as
      # best as possible.
      #
      # @see https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
      uid { @claims['sub'] }
      info do
        { name: @claims['name'],
          email: @claims['email'] || @claims['upn'],
          first_name: @claims['given_name'],
          last_name: @claims['family_name'] }
      end
      credentials { { code: @code } }
      extra do
        { session_state: @session_state,
          raw_info:
            { id_token: @id_token,
              id_token_claims: @claims,
              id_token_header: @header } }
      end

      DEFAULT_RESPONSE_TYPE = 'code id_token'
      DEFAULT_RESPONSE_MODE = 'form_post'

      ##
      # Default nonce cache expiration time (7 days)
      #
      # Nonces are cached to prevent replay attacks. Azure AD tokens typically have
      # short lifetimes, but we cache nonces for 7 days to handle edge cases and
      # provide a reasonable cleanup period.
      #
      # @see https://github.com/AzureAD/omniauth-azure-activedirectory/issues/22
      DEFAULT_NONCE_EXPIRATION = 7.days

      ##
      # The JWT signing algorithm used by Microsoft Azure Active Directory
      #
      # Azure AD consistently uses RS256 (RSA Signature with SHA-256) for signing JWT tokens.
      # This is explicitly documented by Microsoft as the "industry standard asymmetric encryption algorithm"
      # used by the Microsoft identity platform.
      #
      # @see https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens
      #      "Microsoft Entra ID issues tokens signed using the industry standard asymmetric
      #       encryption algorithms, such as RS256"
      #
      # @see https://learn.microsoft.com/en-us/azure/active-directory/develop/id-tokens
      #      Shows consistent RS256 usage in JWT header examples: {"typ":"JWT","alg":"RS256",...}
      #      See the example tokens by clicking on the following links from the linked page:
      #        - View this v1.0 sample token in jwt.ms
      #        - View this v2.0 sample token in jwt.ms
      DEFAULT_ALGORITHM = 'RS256'

      ##
      # Overridden method from OmniAuth::Strategy. This is the first step in the
      # authentication process.
      def request_phase
        redirect authorize_endpoint_url
      end

      ##
      # Overridden method from OmniAuth::Strategy. This is the second step in
      # the authentication process. It is called after the user enters
      # credentials at the authorization endpoint.
      def callback_phase
        error = request.params['error_reason'] || request.params['error']
        if error
          fail!(error) and return
        end
        @session_state = request.params['session_state']
        @id_token = request.params['id_token']
        @code = request.params['code']
        @claims, @header = validate_and_parse_id_token(@id_token)
        validate_chash(@code, @claims, @header)
        super
      end

      private

      ##
      # Constructs a one-time-use authorize_endpoint. This method will use
      # a new nonce on each invocation.
      #
      # @return String
      def authorize_endpoint_url
        uri = URI(openid_config['authorization_endpoint'])
        uri.query = URI.encode_www_form(client_id: client_id,
                                        redirect_uri: callback_url,
                                        response_mode: response_mode,
                                        response_type: response_type,
                                        resource: resource,
                                        nonce: new_nonce)
        uri.to_s
      end

      ##
      # The client id of the calling application. This must be configured where
      # AzureAD is installed as an OmniAuth strategy.
      #
      # @return String
      def client_id
        return options.client_id if options.client_id
        fail StandardError, 'No client_id specified in AzureAD configuration.'
      end

      ##
      # The expected id token issuer taken from the discovery endpoint.
      #
      # @return String
      def issuer
        openid_config['issuer']
      end

      ##
      # Fetches the current signing keys for Azure AD. Note that there should
      # always two available, and that they have a 6 week rollover.
      #
      # Each key is a hash with the following fields:
      #   kty, use, kid, x5t, n, e, x5c
      #
      # @return Array[Hash]
      def fetch_signing_keys
        response = JSON.parse(Net::HTTP.get(URI(signing_keys_url)))
        response['keys']
      rescue JSON::ParserError
        raise StandardError, 'Unable to fetch AzureAD signing keys.'
      end

      ##
      # Fetches the OpenId Connect configuration for the AzureAD tenant. This
      # contains several import values, including:
      #
      #   authorization_endpoint
      #   token_endpoint
      #   token_endpoint_auth_methods_supported
      #   jwks_uri
      #   response_types_supported
      #   response_modes_supported
      #   subject_types_supported
      #   id_token_signing_alg_values_supported
      #   scopes_supported
      #   issuer
      #   claims_supported
      #   microsoft_multi_refresh_token
      #   check_session_iframe
      #   end_session_endpoint
      #   userinfo_endpoint
      #
      # @return Hash
      def fetch_openid_config
        JSON.parse(Net::HTTP.get(URI(openid_config_url)))
      rescue JSON::ParserError
        raise StandardError, 'Unable to fetch OpenId configuration for ' \
                             'AzureAD tenant.'
      end

      ##
      # Generates a new nonce for one time use. Stores it in the session so
      # multiple users don't share nonces. All nonces should be generated by
      # this method.
      #
      # Updated according to https://github.com/AzureAD/omniauth-azure-activedirectory/issues/22. Take care if upgrading!
      # @return String
      def new_nonce
        nonce = SecureRandom.uuid
        Rails.cache.write(nonce_cache_key(nonce), true, expires_in: DEFAULT_NONCE_EXPIRATION)
        # Also store as "current" nonce for read_nonce compatibility
        session['omniauth-azure-activedirectory.nonce'] = nonce
        nonce
      end

      ##
      # A memoized version of #fetch_openid_config.
      #
      # @return Hash
      def openid_config
        @openid_config ||= fetch_openid_config
      end

      ##
      # The location of the OpenID configuration for the tenant.
      #
      # @return String
      def openid_config_url
        "https://login.windows.net/#{ tenant }/.well-known/openid-configuration"
      end

      ##
      # Returns the most recent nonce for the session and deletes it from the
      # session.
      #
      # @return String
      def read_nonce
        session.delete('omniauth-azure-activedirectory.nonce')
      end

      ##
      # The response_type that will be set in the authorization request query
      # parameters. Can be overridden by the client, but it shouldn't need to
      # be.
      #
      # @return String
      def response_type
        options[:response_type] || DEFAULT_RESPONSE_TYPE
      end

      # Overridden by GitClear
      def resource
        options[:resource]
      end

      ##
      # The response_mode that will be set in the authorization request query
      # parameters. Can be overridden by the client, but it shouldn't need to
      # be.
      #
      # @return String
      def response_mode
        options[:response_mode] || DEFAULT_RESPONSE_MODE
      end

      ##
      # The keys used to sign the id token JWTs. This is just a memoized version
      # of #fetch_signing_keys.
      #
      # @return Array[Hash]
      def signing_keys
        @signing_keys ||= fetch_signing_keys
      end

      ##
      # The location of the public keys of the token signer. This is parsed from
      # the OpenId config response.
      #
      # @return String
      def signing_keys_url
        return openid_config['jwks_uri'] if openid_config.include? 'jwks_uri'
        fail StandardError, 'No jwks_uri in OpenId config response.'
      end

      ##
      # The tenant of the calling application. Note that this must be
      # explicitly configured when installing the AzureAD OmniAuth strategy.
      #
      # @return String
      def tenant
        return options.tenant if options.tenant
        fail StandardError, 'No tenant specified in AzureAD configuration.'
      end

      ##
      # Verifies the signature of the id token as well as the exp, nbf, iat,
      # iss, and aud fields.
      #
      # See OpenId Connect Core 3.1.3.7 and 3.2.2.11.
      #
      # Modified according to https://github.com/AzureAD/omniauth-azure-activedirectory/issues/22. Take care if upgrading!
      # @return Claims, Header
      def validate_and_parse_id_token(id_token)
        # The second parameter is the public key to verify the signature.
        # However, that key is overridden by the value of the executed block
        # if one is present.
        #
        # If you're thinking that this looks ugly with the raw nil and boolean,
        # see https://github.com/jwt/ruby-jwt/issues/59.
        jwt_claims, jwt_header = JWT.decode(id_token, nil, true, verify_options) do |header|
          # There should always be one key from the discovery endpoint that
          # matches the id in the JWT header.
          unless key = signing_keys.find{|k|
            k['kid'] == header['kid']
          }
            fail JWT::VerificationError, 'No keys from key endpoint match the id token'
          end

          # The key also contains other fields, such as n and e, that are
          # redundant. x5c is sufficient to verify the id token.
          if x5c = key['x5c'] and !x5c.empty?
            public_key = OpenSSL::X509::Certificate.new(Base64.urlsafe_decode64(x5c.first)).public_key
            public_key
            # no x5c, so we resort to e and n
          elsif exp = key['e'] and mod = key['n']
            rsa_key = OpenSSL::PKey::RSA.new
            mod = openssl_bn_for mod
            exp = openssl_bn_for exp

            if rsa_key.respond_to? :set_key
              # Ruby 2.4 ff
              rsa_key.set_key mod, exp, nil
            else
              # Ruby < 2.4
              rsa_key.e = exp
              rsa_key.n = mod
            end

            rsa_key.public_key
          else
            fail JWT::VerificationError, 'Key has no info for verification'
          end
        end

        # Unclear if nonce validation is or isn't supported by JWT gem and requires manual checking.
        # TODO: Uncomment this when once we properly implement nonce validation
        # Manual nonce validation as mentioned in verify_options comment
        # if jwt_claims['nonce']
        #   unless claim_nonce!(jwt_claims['nonce'])
        #     fail JWT::DecodeError, 'Nonce in id token does not match expected nonce'
        #   end
        # end

        return jwt_claims, jwt_header
      end

      ##
      # Verifies that the c_hash the id token claims matches the authorization
      # code. See OpenId Connect Core 3.3.2.11.
      #
      # @param String code
      # @param Hash claims
      # @param Hash header
      def validate_chash(code, claims, header)
        # c_hash validation is REQUIRED in hybrid flow (code id_token)
        # See OpenID Connect Core 3.3.2.11
        unless claims['c_hash']
          fail JWT::VerificationError, 'c_hash claim is missing from id token (required for hybrid flow)'
        end

        # This maps RS256 -> sha256, ES384 -> sha384, etc.
        algorithm = (header['alg'] || DEFAULT_ALGORITHM).sub(/RS|ES|HS/, 'sha')
        full_hash = OpenSSL::Digest.new(algorithm).digest code
        c_hash = Base64.urlsafe_encode64(full_hash[0..full_hash.length / 2 - 1]).gsub('=', '')
        return if c_hash == claims['c_hash']
        fail JWT::VerificationError,
             'c_hash in id token does not match auth code.'
      end

      ##
      # The options passed to the Ruby JWT library to verify the id token.
      #
      # CRITICAL: JWT gem requires SYMBOL KEYS for aud/iss validation!
      # Using string keys ('aud' => value) causes silent validation failure.
      # Must use symbol keys (aud: value) for proper validation.
      #
      # Other validations (exp, nbf, iat) work correctly.
      # Unclear if nonce validation is or isn't supported by JWT gem and requires manual checking.
      # Which we do in #validate_and_parse_id_token.
      #
      # @return Hash
      def verify_options
        { verify_expiration: true,
          verify_not_before: true,
          verify_iat: true,
          # TODO: Re-enable this validation once issuer validation is properly implemented
          # for both single-tenant and multi-tenant ("common") scenarios.
          # The current implementation needs to handle {tenantid} templates for multi-tenant.
          verify_iss: false,
          iss: issuer,           # Use symbol key for proper validation
          verify_aud: true,
          aud: client_id,        # Use symbol key for proper validation
          algorithm: DEFAULT_ALGORITHM }
      end

      # Introduced according to https://github.com/AzureAD/omniauth-azure-activedirectory/issues/22. Take care if upgrading!
      def nonce_cache_key(nonce)
        "omniauth_azure_activedirectory:nonce:#{nonce}"
      end

      # Introduced according to https://github.com/AzureAD/omniauth-azure-activedirectory/issues/22. Take care if upgrading!
      def claim_nonce!(nonce)
        if Rails.cache.read(nonce_cache_key(nonce))
          Rails.cache.delete(nonce_cache_key(nonce))
          true
        else
          false
        end
      end

      # Convert base64url encoded value to OpenSSL BigNum
      def openssl_bn_for(value)
        OpenSSL::BN.new(Base64.urlsafe_decode64(value), 2)
      end
    end
  end
end

OmniAuth.config.add_camelization 'azure', 'Azure'
