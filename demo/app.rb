
#$LOAD_PATH.unshift File.expand_path('../lib',__dir__)
#require 'sinarey/base'

class Application < Sinatra::SinareyBase

  error do
    'error at app1'
  end

  get '/' do
    'index'
  end

  get '/app1' do
    p '123'
    'app1'
  end

  get '/error1' do
    1/0
    'error1'
  end

  get '/app1/:id' do
    "app1 # #{params[:id]}"
  end

end