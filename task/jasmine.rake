require 'jasmine'
require 'yaml'

load 'jasmine/tasks/jasmine.rake'

Rake::Task["jasmine:server"].clear

namespace :jasmine do

  task :server => "jasmine:require" do
    port = ENV['JASMINE_PORT'] || 8888
    puts "your tests are here:"
    puts "  http://localhost:#{port}/"
    Jasmine.load_configuration_from_yaml File.expand_path("../spec/jasmine.yaml", File.dirname(__FILE__))
    app = Jasmine::Application.app(Jasmine.config)
    Jasmine::Server.new(port, app).start
  end

end
