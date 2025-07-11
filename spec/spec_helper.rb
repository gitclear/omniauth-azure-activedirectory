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

require 'webmock/rspec'
require 'simplecov'
require 'active_support/core_ext/numeric/time' # For 7.days time helper

SimpleCov.start do
  # Don't measure coverage on test files.
  add_filter 'spec'
end

WebMock.disable_net_connect!(allow_localhost: true)

# Mock Rails.cache for testing
class MockRailsCache
  def initialize
    @cache = {}
  end

  def write(key, value, options = {})
    @cache[key] = value
    # Handle expires_in option (ActiveSupport duration objects)
    if expires_in = options[:expires_in]
      # Convert ActiveSupport duration to seconds if needed
      expires_in = expires_in.to_i if expires_in.respond_to?(:to_i)
      # In a real implementation, we'd set up expiration
      # For tests, we'll just store the value without expiration logic
    end
    value
  end

  def read(key)
    @cache[key]
  end

  def delete(key)
    @cache.delete(key)
  end

  # Helper method to populate cache from session (for test setup)
  def populate_from_session(session)
    if session && session['omniauth-azure-activedirectory.nonce']
      nonce = session['omniauth-azure-activedirectory.nonce']
      nonce_key = "omniauth_azure_activedirectory:nonce:#{nonce}"
      write(nonce_key, true)
    end
  end
end

# Set up Rails mock for tests
module Rails
  def self.cache
    @cache ||= MockRailsCache.new
  end
end

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.warnings = true
  config.order = :random

  # Populate mock cache with nonces from test session setup
  config.before(:each) do |example|
    Rails.cache.instance_variable_set(:@cache, {}) # Reset cache

    # Look for env variable in the test context and populate cache
    if defined?(env) && respond_to?(:env)
      session = env['rack.session'] rescue nil
      Rails.cache.populate_from_session(session) if session
    end
  end
end
