require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class Buzz < OmniAuth::Strategies::OAuth
      
      def initialize(app, consumer_key, consumer_secret)
        super(app, :buzz, consumer_key, consumer_secret,
          :site => 'https://www.google.com',
          :request_token_path => "/accounts/OAuthGetRequestToken",
          :access_token_path => "/accounts/OAuthGetAccessToken",
          :authorize_path=> "/accounts/OAuthAuthorizeToken",
          :signature_method => "HMAC-SHA1"
        )
      end
      
      def auth_hash
        ui = user_info
        OmniAuth::Utils.deep_merge(super, {
          'uid' => ui['uid'],
          'user_info' => ui,
          'extra' => {'user_hash' => user_hash}
        })
      end

      def user_hash
        # Google is very strict about keeping authorization and authentication apart. They provide user info for OpenID logins, but not OAuth. 
        # They give no endpoint to get a user's profile directly that I can find. We *can* get their name and email out of the contacts feed, however.
        # It will fail, however, in the extremely rare case of a user who has a Google Account but has never even signed up for Gmail.
        @user_hash ||= MultiJson.decode(@access_token.get("https://www.googleapis.com/buzz/v1/people/@me/@self?alt=json").body)
      end

      def user_info
        data = self.user_hash['data']
        {
          'uid'               => data['id'],
          'name'              => data['displayName'],
          'profile_url'       => data['profileUrl'],
          'image'             => data['thumbnailUrl'],
          'emails'            => data['emails']
        }
      end

      def request_phase
        request_token = consumer.get_request_token({:oauth_callback => callback_url}, {:scope => "https://www.googleapis.com/auth/buzz"})
        (session[:oauth]||={})[name.to_sym] = {:callback_confirmed => request_token.callback_confirmed?, :request_token => request_token.token, :request_secret => request_token.secret}
        r = Rack::Response.new
        r.redirect request_token.authorize_url
        r.finish
      end
      
    end
  end
end
