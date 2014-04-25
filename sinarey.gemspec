# coding: utf-8
$LOAD_PATH.unshift('lib')
require 'sinarey/version'

Gem::Specification.new 'sinarey',Sinarey::VERSION do |spec|
  spec.authors       = ["Jeffrey"]
  spec.email         = ["jeffrey6052@163.com"]
  spec.description   = "add turbo_routes and a fast multi module router for sinatra."
  spec.summary       = "Sinarey, use for large rack project."
  spec.homepage      = "https://github.com/maymay25/sinarey"
  spec.license       = "MIT"

  spec.files         = ['lib/sinatra/sinarey_reloader.rb',
                        'lib/sinarey/version.rb',
                        'lib/sinarey/base.rb',
                        'lib/sinarey/router.rb',
                        'lib/sinarey.rb',
                        'demo/app.rb',
                        'demo/app2.rb',
                        'demo/notfound.rb',
                        'demo/config.ru',
                        'sinarey.gemspec',
                        'README.md']
  spec.add_dependency 'sinatra', '1.4.4'
                        
end
