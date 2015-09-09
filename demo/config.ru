
$LOAD_PATH.unshift File.expand_path('../lib',__dir__)

require_relative 'app'
require_relative 'app2'
require_relative 'notfound'

require 'sinarey/router'
appRouter = Sinarey::Router.new do
  mount Application
  mount Application2
  notfound NotfoundApp
end

run appRouter

#run Application
