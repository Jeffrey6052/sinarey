
require 'sinarey/base'

class Application2 < Sinatra::SinareyBase

  error do
    'error at app2'
  end

  get '/app1' do
    'this will never see.'
  end

  get '/app2' do
    'app2'
  end

  get '/error2' do
    1/0
    'error2'
  end

  get '/app2/:id' do
    "app2 # #{params[:id]}"
  end


end