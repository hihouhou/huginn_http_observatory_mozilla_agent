require 'rails_helper'
require 'huginn_agent/spec_helper'

describe Agents::HttpObservatoryMozillaAgent do
  before(:each) do
    @valid_options = Agents::HttpObservatoryMozillaAgent.new.default_options
    @checker = Agents::HttpObservatoryMozillaAgent.new(:name => "HttpObservatoryMozillaAgent", :options => @valid_options)
    @checker.user = users(:bob)
    @checker.save!
  end

  pending "add specs here"
end
