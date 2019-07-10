# encoding: utf-8
require 'spec_helper'
require "logstash/filters/jwt_decoder"

describe LogStash::Filters::JwtDecoder do

  let(:config) { { } }
  let(:attrs) { { } }
  let(:event) { LogStash::Event.new(attrs) }

  # Sample JWT from https://jwt.io/
  sampleJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJybHMiOlsiYWRtaW4iXSwicG4iOiIwOTM4MjYzODY4MiIsImFpZCI6IjhhOWFjYjJhLWY2MGEtNDU2NC1hNjEyLTgwMThjNDRlNWFlMyIsImlhdCI6MTU2MjY3NDYwOCwiZXhwIjoxNTc4MjI2NjA4fQ.8sE-B8j3R9kzBs9XHmPBcZyyrRSiU9z_eCLGYjg_suA"

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
        expect(subject.get("user_uuid")).to eq("8a9acb2a-f60a-4564-a612-8018c44e5ae3")
        expect(subject.get("uuid_source")).to eq("patron")
        expect(subject.get("user_mobile_number")).to eq("09382638682")
      end
    end

    context "when jwt field does not exists" do
      sample("somefield" => "somevalue") do
        expect(subject.get("user_uuid")).to be_nil
      end
    end
  end


  # describe "With user defined output field" do
  #   let(:config) do <<-CONFIG
  #     filter {
  #       jwt_decoder {
  #         output_field => "customfield"
  #       }
  #     }
  #   CONFIG
  #   end
    
  #   context "when jwt field exists" do
  #     sample("message" => "Bearer #{sampleJwt}") do
  #       expect(subject.get("customfield")).to eq({ "userId" => "1234567890" })
  #     end
  #   end
  # end

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
        expect(subject.get("user_uuid")).to eq("8a9acb2a-f60a-4564-a612-8018c44e5ae3")
      end
    end
  end

  # describe "With user defined access token pattern" do
  #   let(:config) do <<-CONFIG
  #     filter {
  #       jwt_decoder {
  #         token_pattern => "^CustomPrefix\s+(.+)$"
  #       }
  #     }
  #   CONFIG
  #   end
    
  #   context "should be able to decode the token" do
  #     sample("message" => "CustomPrefix #{sampleJwt}") do
  #       expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890" })
  #     end
  #   end
  # end

  # describe "With user defined access token pattern and capture group" do
  #   let(:config) do <<-CONFIG
  #     filter {
  #       jwt_decoder {
  #         token_pattern => "^(CustomPrefix)(\s+)(.+)$"
  #         match_group_index => 2
  #       }
  #     }
  #   CONFIG
  #   end
    
    # context "should be able to decode the token" do
    #   sample("message" => "CustomPrefix #{sampleJwt}") do
    #     print(subject.get("jwt_decoded"))
    #     expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890" })
    #   end
    # end
  # end


  # describe "With multiple fields to be extract" do
  #   let(:config) do <<-CONFIG
  #     filter {
  #       jwt_decoder {
  #         extract => {
  #           "userId" => "$..[0].sub"
  #           "name" => "$..[0].name"
  #         }
  #       }
  #     }
  #   CONFIG
  #   end
    
  #   context "should be able to decode the token" do
  #     sample("message" => "Bearer #{sampleJwt}") do
  #       expect(subject.get("jwt_decoded")).to eq({ "userId" => "1234567890", "name"=>"John Doe" })
  #     end
  #   end
  # end

end
