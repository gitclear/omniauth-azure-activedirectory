Rails.application.config.middleware.use OmniAuth::Builder do
  provider :azure, ENV['CLIENT_ID'], ENV['TENANT']
end
