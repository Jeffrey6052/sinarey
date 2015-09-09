
require 'sinarey/base'

class Application < Sinatra::SinareyBase

  before do
    puts "before at app1"
  end

  before "/app1/:id" do
    puts "before app1 # #{params[:id]}"
  end

  after do
    p env['sinarey.params']
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

  get '/app1/*.*' do

    "app1 # #{params[splat]}"
  end

  get %r{^/tracks/([\d]+)/([\d]+)$} do |id, track_id|
    params[:id] = id
    params[:track_id] = track_id
    "tracks #{params[:id]}"
  end

end