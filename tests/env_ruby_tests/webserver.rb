require "cuba"
require "cuba/safe"

require 'tilt'
require 'slim'
require 'erb'

Cuba.plugin Cuba::Safe

Cuba.define do
  on get do
    on "reflect/:engine" do |engine|
      # Keep the formatting a-la-python
      on param("inj"), param("tpl", "%s") do |inj, tpl|
        
        tpl = tpl.gsub('%s', inj)
        
        case engine
        when "eval"
          res.write eval(tpl)
        when "slim"
          template = Tilt['slim'].new() {|x| tpl}
          res.write template.render
        when "erb"
          template = Tilt['erb'].new() {|x| tpl}
          res.write template.render
        else
          res.write "#{engine} #{inj} #{tpl}" 
        end
        
      end
    end
    on "blind/:engine" do |engine|
      # Keep the formatting a-la-python
      on param("inj"), param("tpl", "%s") do |inj, tpl|
        
        tpl = tpl.gsub('%s', inj)
        
        case engine
        when "eval"
          eval(tpl)
        when "slim"
          template = Tilt['slim'].new() {|x| tpl}
          template.render
        when "erb"
          template = Tilt['erb'].new() {|x| tpl}
          template.render
        else
          res.write "blind #{engine} #{inj} #{tpl}" 
        end
        
        res.write "ok"; # for set 200 response status code

      end
    end
    on 'shutdown' do
      exit!
    end
  end
end
