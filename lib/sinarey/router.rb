module Sinarey
  class Router
    def initialize(*args, &block)
      @notfound_app = lambda { |env| [404, {}, ['404']] }
      @apps         = {}
      @turbo_routes = {}
      @routes       = {}
      instance_eval(&block) if block
      build_routing_table
    end

    def call(env)
      route = env["PATH_INFO"]
      route.chop! if (char=route[-1]) and char=='/' # ignore last '/' char
      if response = apps_route(env["REQUEST_METHOD"], route, env)
        response
      else
        @notfound_app.call(env)
      end
    end

    def mount(app)
      app_id = @apps.size + 1
      @apps[app_id] = app
    end

    def notfound(app)
      @notfound_app = app
    end

    private

    def build_routing_table
      @apps.each do |app_id, app|
        regedit_turbo_routes(app_id, app)
        regedit_basic_routes(app_id, app)
      end
    end

    def regedit_turbo_routes(app_id, app)
      return unless app.respond_to?(:turbo_routes)
      app.turbo_routes.each do |verb, routes|
        routes.each do |path, route|
          route.tap do |block_id|
            tmp = @turbo_routes[verb] ||= {}
            tmp[path] = [block_id, app_id] unless tmp[path]
          end
        end
      end
    end

    def regedit_basic_routes(app_id, app)
      return unless app.respond_to?(:routes)
      app.routes.each do |verb, routes|
        routes.each do |pattern, keys, conditions, block_id|
          (@routes[verb] ||= []) << [pattern, keys, conditions, block_id, app_id]
        end
      end
    end

    case ENV["RACK_ENV"]
    when 'development'
      
      #development need support sinarey reloader.so here use dev logic.
      def apps_route(verb, path, env)

        #auto reload modified code
        @apps.each do |index,app|
          app.auto_reload if app.respond_to?(:auto_reload)
        end

        #rebuild route table
        @turbo_routes = {}
        @routes       = {}
        build_routing_table

        if turbo_route = (turbo_routes = @turbo_routes[verb]) && turbo_routes[path]
          turbo_route.tap do |block_id,app_id|
            env['sinarey.router'] = {type: :turbo, block_id: block_id}
            status, headers, response = @apps[app_id].call(env)
            return status, headers, response
          end
        elsif routes = @routes[verb]
          routes.each do |pattern, keys, conditions, block_id, app_id|
            if match = pattern.match(path)
              env['sinarey.router'] = {type: :normal, match: match, keys: keys, conditions: conditions, block_id: block_id}
              status, headers, response = @apps[app_id].call(env)
              return status, headers, response
            end
          end
        end
        nil
      end

    else

      def apps_route(verb, path, env)
        if turbo_route = (turbo_routes = @turbo_routes[verb]) && turbo_routes[path]
          turbo_route.tap do |block_id,app_id|
            env['sinarey.router'] = {type: :turbo, block_id: block_id}
            status, headers, response = @apps[app_id].call(env)
            return status, headers, response
          end
        elsif routes = @routes[verb]
          routes.each do |pattern, keys, conditions, block_id, app_id|
            if match = pattern.match(path)
              env['sinarey.router'] = {type: :normal, match: match, keys: keys, conditions: conditions, block_id: block_id}
              status, headers, response = @apps[app_id].call(env)
              return status, headers, response
            end
          end
        end
        nil
      end

    end

  end
end
