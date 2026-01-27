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

require 'omniauth'
require 'securerandom'

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

      # In OAuth2 code flow, user info is not available until the code is
      # exchanged for tokens. The consuming application must handle the token
      # exchange and populate user info separately.
      #
      # @see https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
      uid { nil }
      info { {} }
      credentials { { code: @code } }
      extra { { session_state: @session_state } }

      DEFAULT_RESPONSE_TYPE = 'code'
      DEFAULT_RESPONSE_MODE = 'form_post'

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
      #
      # In OAuth2 code flow, we only receive the authorization code here.
      # The code must be exchanged for tokens at the token endpoint by the
      # consuming application.
      def callback_phase
        error = request.params['error_reason'] || request.params['error']
        if error
          fail!(error) and return
        end
        @session_state = request.params['session_state']
        @code = request.params['code']
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
                                        scope: scope,
                                        nonce: new_nonce,
                                        prompt: "consent")
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
      # multiple users don't share nonces.
      #
      # @return String
      def new_nonce
        session['omniauth-azure-activedirectory.nonce'] = SecureRandom.uuid
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
        "https://login.microsoftonline.com/#{ tenant }/v2.0/.well-known/openid-configuration"
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

      def scope
        options[:scope]
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
      # The tenant of the calling application. Note that this must be
      # explicitly configured when installing the AzureAD OmniAuth strategy.
      #
      # @return String
      def tenant
        return options.tenant if options.tenant
        fail StandardError, 'No tenant specified in AzureAD configuration.'
      end

    end
  end
end

OmniAuth.config.add_camelization 'azure', 'Azure'
