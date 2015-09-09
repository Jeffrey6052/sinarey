
require 'sinarey/base'

class Application < Sinatra::SinareyBase

  before do
    puts "before at app1"
  end

  after do
    p env['rack.framework']
    p env['sinarey.common_params']
    p env['sinarey.regex_params']
  end

  error do
    'error at app1'
  end

  get '/' do

    'index'
  end

  get '/app1' do
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