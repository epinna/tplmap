require "cuba"
require "cuba/safe"

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
        else
          res.write "#{engine} #{inj} #{tpl}" 
        end
        
      end
    end
    on 'shutdown' do
      exit!
    end
  end
end