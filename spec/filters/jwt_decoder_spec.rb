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

    context "when jwt field do not exists" do
      sample("somefield" => "somevalue") do
        expect(subject.get("jwt_decoded")).to be_nil
      end
    end

  end
end
