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
  config :extract, :validate => :hash, :default => { "userId" => "$..[0].sub"}

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

          @extract.each do |key, value|
            jsonPath = JsonPath.new(value)
            result[key] = jsonPath.first(decoded_token)
          end

          event.set(@output_field, result)

          filter_matched(event)
        end
      end
  end # def filter
end # class LogStash::Filters::JwtDecoder

