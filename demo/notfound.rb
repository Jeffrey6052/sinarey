
require 'sinarey/base'

class NotfoundApp < Sinatra::SinareyBase

  not_found do
    '404'
  end

end