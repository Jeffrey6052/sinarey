
#$LOAD_PATH.unshift File.expand_path('../lib',__dir__)
#require 'sinarey/base'

class NotfoundApp < Sinatra::SinareyBase

  not_found do
    '404'
  end

end