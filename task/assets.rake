require 'sprockets'

namespace :assets do

  ARTEFACT_FILENAME = File.expand_path("../artefacts/epd.js", File.dirname(__FILE__)).freeze unless defined?(ARTEFACT_FILENAME)

  desc "Build the assets"
  task :build do
    environment = Sprockets::Environment.new
    environment.append_path File.expand_path("../src", File.dirname(__FILE__))
    File.open ARTEFACT_FILENAME, "w" do |file|
      file.write environment["epd.js"].to_s
    end
  end

end
