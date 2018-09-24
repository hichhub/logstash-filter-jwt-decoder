# encoding: utf-8
require 'spec_helper'
require "logstash/filters/jwt_decoder"

describe LogStash::Filters::JwtDecoder do

  let(:config) { { } }
  let(:attrs) { { } }
  let(:event) { LogStash::Event.new(attrs) }

  # Sample JWT from https://jwt.io/
  sampleJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

  describe "Empty configuration" do
    let(:config) do <<-CONFIG
      filter {
        jwt_decoder {
        }
      }
    CONFIG
    end
    
    context "when jwt field exists" do
      sample("message" => "Bearer #{sampleJwt}") do
        expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890" })
      end
    end

    context "when jwt field does not exists" do
      sample("somefield" => "somevalue") do
        expect(subject.get("jwt_decoded")).to be_nil
      end
    end
  end


  describe "With user defined output field" do
    let(:config) do <<-CONFIG
      filter {
        jwt_decoder {
          output_field => "customfield"
        }
      }
    CONFIG
    end
    
    context "when jwt field exists" do
      sample("message" => "Bearer #{sampleJwt}") do
        expect(subject.get("customfield")).to eq({ "userId" => "1234567890" })
      end
    end
  end

  describe "With user defined access token field" do
    let(:config) do <<-CONFIG
      filter {
        jwt_decoder {
          access_token_field => "accesstoken"
        }
      }
    CONFIG
    end
    
    context "should be able to decode the token" do
      sample("accesstoken" => "Bearer #{sampleJwt}") do
        expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890" })
      end
    end
  end

  describe "With user defined access token pattern" do
    let(:config) do <<-CONFIG
      filter {
        jwt_decoder {
          token_pattern => "^CustomPrefix\s+(.+)$"
        }
      }
    CONFIG
    end
    
    context "should be able to decode the token" do
      sample("message" => "CustomPrefix #{sampleJwt}") do
        expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890" })
      end
    end
  end

  describe "With user defined access token pattern and capture group" do
    let(:config) do <<-CONFIG
      filter {
        jwt_decoder {
          token_pattern => "^(CustomPrefix)(\s+)(.+)$"
          match_group_index => 2
        }
      }
    CONFIG
    end
    
    context "should be able to decode the token" do
      sample("message" => "CustomPrefix #{sampleJwt}") do
        expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890" })
      end
    end
  end


  describe "With multiple fields to be extract" do
    let(:config) do <<-CONFIG
      filter {
        jwt_decoder {
          extract => {
            "userId" => "$..[0].sub"
            "name" => "$..[0].name"
          }
        }
      }
    CONFIG
    end
    
    context "should be able to decode the token" do
      sample("message" => "Bearer #{sampleJwt}") do
        expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890", "name"=>"John Doe" })
      end
    end
  end

end
