# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "jwt"
require "jsonpath"

class LogStash::Filters::JwtDecoder < LogStash::Filters::Base

  config_name "jwt_decoder"

  # The pattern to match the token
  config :token_pattern, :validate => :string, :default => /^[Bb]earer\s+(.+)$/

  # The capture group index of the matched token
  config :match_group_index, :validate => :number, :default => 0

  # The path to the access token field
  config :access_token_field, :validate => :string, :default => "message"

  # The output field
  config :output_field, :validate => :string, :default => "jwt_decoded"

  # fields to be extracted
  config :extract, :validate => :hash, :default => { "webID" => "$..[0].webID"}

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
      # Replace the event message with our message as configured in the
      # config file.
      raw_message = event.get(@access_token_field)
      if(raw_message)
        if match = raw_message.match(@token_pattern)
          token = match.captures[@match_group_index]
          decoded_token = JWT.decode token, nil, false
          result = Hash.new
          aid = decoded_token[0]['aid']
          auu = decoded_token[0]['auu']
          webID = decoded_token[0]['webID']
          patron_uuid = decoded_token[0]['patron_uuid']
          pn = decoded_token[0]['pn']

          if (pn)
            event.set("user_mobile_number", result)
          end
          event.set("user_uuid", aid || auu || webID || patron_uuid)
          event.set("uuid_source", (auu || webID)? 'address' : 'patron')
          filter_matched(event)
        end
      end
  end # def filter
end # class LogStash::Filters::JwtDecoder

