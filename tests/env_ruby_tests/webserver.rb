require "cuba"
require "cuba/safe"

Cuba.plugin Cuba::Safe

Cuba.define do
  on get do
    on "reflect/:engine" do |engine|
      on param("inj"), param("tpl", "%s") do |inj, tpl|
        res.write "#{engine} #{inj} #{tpl}" 
      end
    end
    on 'shutdown' do
      exit!
    end
  end
end