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

require 'spec_helper'
require 'omniauth-azure-activedirectory'

# This was fairly awkward to test. I've stubbed every endpoint and am simulating
# the state of the request. Especially large strings are stored in fixtures.
describe OmniAuth::Strategies::Azure do
  let(:app) { -> _ { [200, {}, ['Hello world.']] } }
  let(:x5c) { File.read(File.expand_path('../../../fixtures/x5c.txt', __FILE__)) }

  # These values were used to create the "successful" id_token JWT.
  let(:client_id) { 'the client id' }
  let(:code) { 'code' }
  let(:email) { 'jsmith@contoso.com' }
  let(:family_name) { 'smith' }
  let(:given_name) { 'John' }
  let(:issuer) { 'https://sts.windows.net/bunch-of-random-chars' }
  let(:kid) { 'abc123' }
  let(:name) { 'John Smith' }
  let(:nonce) { 'my nonce' }
  let(:session_state) { 'session state' }
  let(:auth_endpoint_host) { 'authorize.com' }

  let(:hybrid_flow_params) do
    { 'id_token' => id_token,
      'session_state' => session_state,
      'code' => code }
  end

  let(:tenant) { 'tenant' }
  let(:openid_config_response) { "{\"issuer\":\"#{issuer}\",\"authorization_endpoint\":\"http://#{auth_endpoint_host}\",\"jwks_uri\":\"https://login.windows.net/common/discovery/keys\"}" }
  let(:keys_response) { "{\"keys\":[{\"kid\":\"#{kid}\",\"x5c\":[\"#{x5c}\"]}]}" }

  let(:env) { { 'rack.session' => { 'omniauth-azure-activedirectory.nonce' => nonce } } }

  before(:each) do
    stub_request(:get, "https://login.windows.net/#{tenant}/.well-known/openid-configuration")
      .to_return(status: 200, body: openid_config_response)
    stub_request(:get, 'https://login.windows.net/common/discovery/keys')
      .to_return(status: 200, body: keys_response)
  end

  describe '#callback_phase' do
    let(:request) { double('Request', params: hybrid_flow_params, path_info: 'path') }
    let(:strategy) do
      described_class.new(app, client_id, tenant).tap do |s|
        allow(s).to receive(:request) { request }
      end
    end

    subject { -> { strategy.callback_phase } }
    before(:each) { strategy.call!(env) }

    context 'with a successful response' do
      # payload:
      #   { 'iss' => 'https://sts.windows.net/bunch-of-random-chars',
      #     'name' => 'John Smith',
      #     'aud' => 'the client id',
      #     'nonce' => 'my nonce',
      #     'email' => 'jsmith@contoso.com',
      #     'given_name' => 'John',
      #     'family_name' => 'Smith' }
      # headers:
      #   { 'typ' => 'JWT',
      #     'alg' => 'RS256',
      #     'kid' => 'abc123' }
      #
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token.txt', __FILE__)) }

      # If it passes this test, then the id was successfully validated.
      it { is_expected.to_not raise_error }

      describe 'the auth hash' do
        before(:each) { strategy.callback_phase }

        subject { env['omniauth.auth'] }

        it 'should contain the name' do
          expect(subject.info['name']).to eq name
        end

        it 'should contain the first name' do
          expect(subject.info['first_name']).to eq given_name
        end

        it 'should contain the last name' do
          expect(subject.info['last_name']).to eq family_name
        end

        it 'should contain the email' do
          expect(subject.info['email']).to eq email
        end

        it 'should contain the auth code' do
          expect(subject.credentials['code']).to eq code
        end

        it 'should contain the session state' do
          expect(subject.extra['session_state']).to eq session_state
        end
      end
    end

    # TODO: Re-enable this test once issuer validation is properly implemented
    # for both single-tenant and multi-tenant ("common") scenarios.
    # The current implementation needs to handle {tenantid} templates for multi-tenant.
    xcontext 'with an invalid issuer' do
      # payload:
      #   { 'iss' => 'https://sts.imposter.net/bunch-of-random-chars', ... }
      #
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token_bad_issuer.txt', __FILE__)) }
      it { is_expected.to raise_error JWT::InvalidIssuerError }
    end

    context 'with an invalid audience' do
      # payload:
      #   { 'aud' => 'not the client id', ... }
      #
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token_bad_audience.txt', __FILE__)) }
      it { is_expected.to raise_error JWT::InvalidAudError }
    end

    context 'with a non-matching nonce' do
      # payload:
      #   { 'nonce' => 'not my nonce', ... }
      #
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token_bad_nonce.txt', __FILE__)) }
      it { is_expected.to raise_error JWT::DecodeError }
    end

    context 'with the wrong x5c' do
      let(:x5c) { File.read(File.expand_path('../../../fixtures/x5c_different.txt', __FILE__)) }
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token.txt', __FILE__)) }
      it { is_expected.to raise_error JWT::VerificationError }
    end

    context 'with a non-matching c_hash' do
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token_bad_chash.txt', __FILE__)) }
      it { is_expected.to raise_error JWT::VerificationError }
    end

    context 'with a non-matching kid' do
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token_bad_kid.txt', __FILE__)) }
      it { is_expected.to raise_error JWT::VerificationError }
    end

    context 'with no alg header' do
      let(:id_token) { File.read(File.expand_path('../../../fixtures/id_token_no_alg.txt', __FILE__)) }

      it 'should correctly parse using default RS256' do
        expect(subject).to_not raise_error
      end

      describe 'the auth hash' do
        subject { env['omniauth.auth'] }
        before(:each) { strategy.callback_phase }

        it 'should default to RS256' do
          expect(subject.info['name']).to eq name
        end
      end
    end
  end

  describe '#request_phase' do
    let(:strategy) { described_class.new(app, client_id, tenant) }
    subject { strategy.request_phase }
    before(:each) { strategy.call!(env) }

    it 'should make a redirect' do
      expect(subject.first).to eq 302
    end

    it 'should redirect to the correct endpoint' do
      expect(URI(subject[1]['Location']).host).to eq auth_endpoint_host
    end
  end

  describe '#read_nonce' do
    let(:strategy) { described_class.new(app, client_id, tenant) }
    let(:env) { { 'rack.session' => {} } }
    before(:each) { strategy.call!(env) }
    subject { strategy.send(:read_nonce) }

    context 'before a nonce is set' do
      it { is_expected.to be nil }
    end

    context 'after a nonce is set' do
      before(:each) { @nonce = strategy.send(:new_nonce) }
      it 'should match' do
        expect(subject).to eq @nonce
      end
    end

    context 'twice in a row' do
      before(:each) do
        strategy.send(:new_nonce)
        strategy.send(:read_nonce)
      end
      it { is_expected.to be nil }
    end
  end
end
