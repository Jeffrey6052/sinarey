require 'sinatra/base'

module Sinatra

  class SinareyBase
    include Rack::Utils
    include Helpers
    include Templates

    URI_INSTANCE = URI.const_defined?(:Parser) ? URI::Parser.new : URI

    attr_accessor :app, :env, :request, :response, :params
    attr_reader   :template_cache

    def initialize(app = nil)
      super()
      @app = app
      @template_cache = Tilt::Cache.new
      yield self if block_given?
    end

    # Rack call interface.
    def call(env)
      env['rack.framework'] = "Sinarey"
      dup.call!(env)
    end

    def call!(env) # :nodoc:
      @env      = env
      @request  = Request.new(env)
      @response = Response.new
      @params   = indifferent_params(@request.params)
      template_cache.clear if settings.reload_templates
      force_encoding(@params)

      route = @request.path_info
      route.chop! if (char=route[-1]) and char=='/' # ignore last '/' char

      #pjax request support
      if route.chomp!('.pjax')
        env["IS_PJAX_REQUEST"] = true
      end

      @response['Content-Type'] = nil
      invoke { dispatch! }
      invoke { error_block!(response.status) } unless @env['sinatra.error']

      unless @response['Content-Type']
        if Array === body and body[0].respond_to? :content_type
          content_type body[0].content_type
        else
          content_type :html
        end
      end

      @response.finish
    end

    # Access settings defined with Base.set.
    def self.settings
      self
    end

    # Access settings defined with Base.set.
    def settings
      self.class.settings
    end

    def options
      warn "Sinatra::Base#options is deprecated and will be removed, " \
        "use #settings instead."
      settings
    end

    # Exit the current block, halts any further processing
    # of the request, and returns the specified response.
    def halt(*response)
      response = response.first if response.length == 1
      throw :halt, response
    end

    # Forward the request to the downstream app -- middleware only.
    def forward
      fail "downstream app not set" unless @app.respond_to? :call
      status, headers, body = @app.call env
      @response.status = status
      @response.body = body
      @response.headers.merge! headers
      nil
    end

    private

    # Run filters defined on the class and all superclasses.
    def filter!(type, base = settings)
      filter! type, base.superclass if base.superclass.respond_to?(:filters)
      base.filters[type].each { |args| process_filter(*args) }
    end

    # Run routes defined on the class and all superclasses.
    def route!(base = settings)
      if router = env['sinarey.router']
        return mount_route!(router)
      end

      if turbo_route = (turbo_routes = base.turbo_routes[@request.request_method]) && (path_info = turbo_routes[@request.path_info])
        turbo_route.tap do |block_id|
          process_turbo_route do |*args|
            block = base.blocks[block_id]
            env['sinatra.route'] = block.instance_variable_get(:@route_name)
            route_eval { block[*args] }
          end
        end
      elsif routes = base.routes[@request.request_method]
        routes.each do |pattern, keys, conditions, block_id|
          process_route(pattern, keys, conditions) do |*args|
            block = base.blocks[block_id]
            env['sinatra.route'] = block.instance_variable_get(:@route_name)
            route_eval { block[*args] }
          end
        end
      end

      # Run routes defined in superclass.
      if base.superclass.respond_to?(:routes)
        return route!(base.superclass)
      end

      route_missing
    end

    def mount_route!(options,base = settings)
      type,block_id = options[:type],options[:block_id]
      case type
      when :turbo
        process_turbo_route do |*args|
          block = base.blocks[block_id]
          env['sinatra.route'] = block.instance_variable_get(:@route_name)
          route_eval { block[*args] }
        end
      when :normal
        match,keys,conditions = options[:match],options[:keys],options[:conditions]
        process_mount_route(match, keys, conditions) do |*args|
          block = base.blocks[block_id]
          env['sinatra.route'] = block.instance_variable_get(:@route_name)
          route_eval { block[*args] }
        end
      end

      route_missing
    end

    # Run a route block and throw :halt with the result.
    def route_eval
      throw :halt, yield
    end

    def process_mount_route(match, keys, conditions, block_id = nil, values = [], &callback)
      values += match.captures.map! { |v| force_encoding URI_INSTANCE.unescape(v) if v }

      if values.any?
        original, @params = params, params.merge('splat' => [], 'captures' => values)
        regex_params = {}
        keys.zip(values) do |k,v| 
          if Array === @params[k]
            regex_params[k] << v
            @params[k] << v 
          elsif v
            regex_params[k] = v
            @params[k] = v  
          end
        end
        env["sinarey.regex_params"] = regex_params
      end

      (block_id && (block = settings.blocks[block_id])) ? block[self, values] : yield(self, values)
    ensure
      @params = original if original
    end

    # If the current request matches pattern and conditions, fill params
    # with keys and call the given block.
    # Revert params afterwards.
    #
    # Returns pass block.

    def process_route(pattern, keys, conditions, block_id = nil, values = [], &callback)
      route = @request.path_info
      return unless match = pattern.match(route)

      process_mount_route(match, keys, conditions, block_id, values, &callback)
    end

    def process_turbo_route(block = nil)
      block ? block[self, []] : yield(self, [])
    end

    def process_filter(pattern, keys, conditions, block = nil, values = [])
      route = @request.path_info
      route = '/' if route.empty? and not settings.empty_path_info?
      return unless match = pattern.match(route)
      values += match.captures.map! { |v| force_encoding URI_INSTANCE.unescape(v) if v }

      if values.any?
        original, @params = params, params.merge('splat' => [], 'captures' => values)
        keys.zip(values) { |k,v| Array === @params[k] ? @params[k] << v : @params[k] = v if v }
      end

      block ? block[self, values] : yield(self, values)
    ensure
      @params = original if original
    end

    # No matching route was found. The default
    # implementation is to forward the request downstream when running
    # as middleware (@app is non-nil); when no downstream app is set, raise
    # a NotFound exception. Subclasses can override this method to perform
    # custom route miss logic.
    def route_missing
      if @app
        forward
      else
        raise NotFound
      end
    end

    # Attempt to serve static files from public directory. Throws :halt when
    # a matching file is found, returns nil otherwise.
    def static!
      return if (public_dir = settings.public_folder).nil?
      path = File.expand_path("#{public_dir}#{unescape(request.path_info)}" )
      return unless File.file?(path)

      env['sinatra.static_file'] = path
      cache_control(*settings.static_cache_control) if settings.static_cache_control?
      send_file path, :disposition => nil
    end

    # Enable string or symbol key access to the nested params hash.
    def indifferent_params(object)
      case object
      when Hash
        new_hash = indifferent_hash
        object.each { |key, value| new_hash[key] = indifferent_params(value) }
        new_hash
      when Array
        object.map { |item| indifferent_params(item) }
      else
        object
      end
    end

    # Creates a Hash with indifferent access.
    def indifferent_hash
      Hash.new {|hash,key| hash[key.to_s] if Symbol === key }
    end

    # Run the block with 'throw :halt' support and apply result to the response.
    def invoke
      res = catch(:halt) { yield }
      res = [res] if Fixnum === res or String === res
      if Array === res and Fixnum === res.first
        res = res.dup
        status(res.shift)
        body(res.pop)
        headers(*res)
      elsif res.respond_to? :each
        body res
      end
      nil # avoid double setting the same response tuple twice
    end

    # Dispatch a request with error handling.
    def dispatch!
      invoke do
        static! if settings.static? && (request.get? || request.head?)
        filter! :before
        route!
      end
    rescue ::Exception => boom
      invoke { handle_exception!(boom) }
    ensure
      begin
        filter! :after
      rescue ::Exception => boom
        invoke { handle_exception!(boom) } unless @env['sinatra.error']
      end
    end

    # Error handling during requests.
    def handle_exception!(boom)
      @env['sinatra.error'] = boom

      if boom.respond_to? :http_status
        status(boom.http_status)
      elsif settings.use_code? and boom.respond_to? :code and boom.code.between? 400, 599
        status(boom.code)
      else
        status(500)
      end

      status(500) unless status.between? 400, 599

      if server_error?
        dump_errors! boom if settings.dump_errors?
        raise boom if settings.show_exceptions? and settings.show_exceptions != :after_handler
      end

      if not_found?
        body '<h1>Not Found</h1>'
      end

      res = error_block!(boom.class, boom) || error_block!(status, boom)
      return res if res or not server_error?
      raise boom if settings.raise_errors? or settings.show_exceptions?
      error_block! Exception, boom
    end

    # Find an custom error block for the key(s) specified.
    def error_block!(key, *block_params)
      base = settings
      while base.respond_to?(:errors)
        next base = base.superclass unless args_array = base.errors[key]
        args_array.reverse_each do |args|
          first = args == args_array.first
          args += [block_params]
          resp = process_route(*args)
          return resp unless resp.nil? && !first
        end
      end
      return false unless key.respond_to? :superclass and key.superclass < Exception
      error_block!(key.superclass, *block_params)
    end

    def dump_errors!(boom)
      msg = ["#{boom.class} - #{boom.message}:", *boom.backtrace].join("\n\t")
      @env['rack.errors'].puts(msg)
    end

    class << self
      CALLERS_TO_IGNORE = [ # :nodoc:
        /\/sinatra(\/(base|main|showexceptions))?\.rb$/,    # all sinatra code
        /lib\/tilt.*\.rb$/,                                 # all tilt code
        /^\(.*\)$/,                                         # generated code
        /rubygems\/(custom|core_ext\/kernel)_require\.rb$/, # rubygems require hacks
        /active_support/,                                   # active_support require hacks
        /bundler(\/runtime)?\.rb/,                          # bundler require hacks
        /<internal:/,                                       # internal in ruby >= 1.9.2
        /src\/kernel\/bootstrap\/[A-Z]/                     # maglev kernel files
      ]

      # contrary to what the comment said previously, rubinius never supported this
      if defined?(RUBY_IGNORE_CALLERS)
        warn "RUBY_IGNORE_CALLERS is deprecated and will no longer be supported by Sinatra 2.0"
        CALLERS_TO_IGNORE.concat(RUBY_IGNORE_CALLERS)
      end

      attr_reader :blocks, :turbo_routes, :routes, :filters, :templates, :errors

      # Removes all routes, filters, middleware and extension hooks from the
      # current class (not routes/filters/... defined by its superclass).
      def reset!
        @conditions     = []
        @routes         = {}
        @turbo_routes   = {}
        @blocks         = {}
        @filters        = {:before => [], :after => []}
        @errors         = {}
        @middleware     = []
        @prototype      = nil
        @extensions     = []

        if superclass.respond_to?(:templates)
          @templates = Hash.new { |hash,key| superclass.templates[key] }
        else
          @templates = {}
        end
      end

      # Extension modules registered on this class and all superclasses.
      def extensions
        if superclass.respond_to?(:extensions)
          (@extensions + superclass.extensions).uniq
        else
          @extensions
        end
      end

      # Middleware used in this class and all superclasses.
      def middleware
        if superclass.respond_to?(:middleware)
          superclass.middleware + @middleware
        else
          @middleware
        end
      end

      # Sets an option to the given value.  If the value is a proc,
      # the proc will be called every time the option is accessed.
      def set(option, value = (not_set = true), ignore_setter = false, &block)
        raise ArgumentError if block and !not_set
        value, not_set = block, false if block

        if not_set
          raise ArgumentError unless option.respond_to?(:each)
          option.each { |k,v| set(k, v) }
          return self
        end

        if respond_to?("#{option}=") and not ignore_setter
          return __send__("#{option}=", value)
        end

        setter = proc { |val| set option, val, true }
        getter = proc { value }

        case value
        when Proc
          getter = value
        when Symbol, Fixnum, FalseClass, TrueClass, NilClass
          getter = value.inspect
        when Hash
          setter = proc do |val|
            val = value.merge val if Hash === val
            set option, val, true
          end
        end

        define_singleton("#{option}=", setter) if setter
        define_singleton(option, getter) if getter
        define_singleton("#{option}?", "!!#{option}") unless method_defined? "#{option}?"
        self
      end

      # Same as calling `set :option, true` for each of the given options.
      def enable(*opts)
        opts.each { |key| set(key, true) }
      end

      # Same as calling `set :option, false` for each of the given options.
      def disable(*opts)
        opts.each { |key| set(key, false) }
      end

      # Define a custom error handler. Optionally takes either an Exception
      # class, or an HTTP status code to specify which errors should be
      # handled.
      def error(*codes, &block)
        args  = compile! "ERROR", //, block
        codes = codes.map { |c| Array(c) }.flatten
        codes << Exception if codes.empty?
        codes.each { |c| (@errors[c] ||= []) << args }
      end

      # Sugar for `error(404) { ... }`
      def not_found(&block)
        error(404, &block)
        error(Sinatra::NotFound, &block)
      end

      # Define a named template. The block must return the template source.
      def template(name, &block)
        filename, line = caller_locations.first
        templates[name] = [block, filename, line.to_i]
      end

      # Define the layout template. The block must return the template source.
      def layout(name = :layout, &block)
        template name, &block
      end

      # Load embedded templates from the file; uses the caller's __FILE__
      # when no file is specified.
      def inline_templates=(file = nil)
        file = (file.nil? || file == true) ? (caller_files.first || File.expand_path($0)) : file

        begin
          io = ::IO.respond_to?(:binread) ? ::IO.binread(file) : ::IO.read(file)
          app, data = io.gsub("\r\n", "\n").split(/^__END__$/, 2)
        rescue Errno::ENOENT
          app, data = nil
        end

        if data
          if app and app =~ /([^\n]*\n)?#[^\n]*coding: *(\S+)/m
            encoding = $2
          else
            encoding = settings.default_encoding
          end
          lines = app.count("\n") + 1
          template = nil
          force_encoding data, encoding
          data.each_line do |line|
            lines += 1
            if line =~ /^@@\s*(.*\S)\s*$/
              template = force_encoding('', encoding)
              templates[$1.to_sym] = [template, file, lines]
            elsif template
              template << line
            end
          end
        end
      end

      # Lookup or register a mime type in Rack's mime registry.
      def mime_type(type, value = nil)
        return type      if type.nil?
        return type.to_s if type.to_s.include?('/')
        type = ".#{type}" unless type.to_s[0] == ?.
        return Rack::Mime.mime_type(type, nil) unless value
        Rack::Mime::MIME_TYPES[type] = value
      end

      # provides all mime types matching type, including deprecated types:
      #   mime_types :html # => ['text/html']
      #   mime_types :js   # => ['application/javascript', 'text/javascript']
      def mime_types(type)
        type = mime_type type
        type =~ /^application\/(xml|javascript)$/ ? [type, "text/#$1"] : [type]
      end

      # Define a before filter; runs before all requests within the same
      # context as route handlers and may access/modify the request and
      # response.
      def before(path = nil, options = {}, &block)
        add_filter(:before, path, options, &block)
      end

      # Define an after filter; runs after all requests within the same
      # context as route handlers and may access/modify the request and
      # response.
      def after(path = nil, options = {}, &block)
        add_filter(:after, path, options, &block)
      end

      # add a filter
      def add_filter(type, path = nil, options = {}, &block)
        path, options = //, path if path.respond_to?(:each_pair)
        filters[type] << compile_filter!(type, path || //, block, options)
      end

      # Add a route condition. The route is considered non-matching when the
      # block returns false.
      def condition(name = "#{caller.first[/`.*'/]} condition", &block)
        @conditions << generate_method(name, &block)
      end

      def public=(value)
        warn ":public is no longer used to avoid overloading Module#public, use :public_folder or :public_dir instead"
        set(:public_folder, value)
      end

      def public_dir=(value)
        self.public_folder = value
      end

      def public_dir
        public_folder
      end

      # Defining a `GET` handler also automatically defines
      # a `HEAD` handler.
      def get(path, opts = {}, &block)
        conditions = @conditions.dup
        route('GET', path, opts, &block)

        @conditions = conditions
        route('HEAD', path, opts, &block)
      end

      def put(path, opts = {}, &bk)     route 'PUT',     path, opts, &bk end
      def post(path, opts = {}, &bk)    route 'POST',    path, opts, &bk end
      def delete(path, opts = {}, &bk)  route 'DELETE',  path, opts, &bk end
      def head(path, opts = {}, &bk)    route 'HEAD',    path, opts, &bk end
      def options(path, opts = {}, &bk) route 'OPTIONS', path, opts, &bk end
      def patch(path, opts = {}, &bk)   route 'PATCH',   path, opts, &bk end
      def link(path, opts = {}, &bk)    route 'LINK',    path, opts, &bk end
      def unlink(path, opts = {}, &bk)  route 'UNLINK',  path, opts, &bk end

      # Makes the methods defined in the block and in the Modules given
      # in `extensions` available to the handlers and templates
      def helpers(*extensions, &block)
        class_eval(&block)   if block_given?
        include(*extensions) if extensions.any?
      end

      # Register an extension. Alternatively take a block from which an
      # extension will be created and registered on the fly.
      def register(*extensions, &block)
        extensions << Module.new(&block) if block_given?
        @extensions += extensions
        extensions.each do |extension|
          extend extension
          extension.registered(self) if extension.respond_to?(:registered)
        end
      end

      def development?; environment == :development end
      def production?;  environment == :production  end
      def test?;        environment == :test        end

      # Set configuration options for Sinatra and/or the app.
      # Allows scoping of settings for certain environments.
      def configure(*envs)
        yield self if envs.empty? || envs.include?(environment.to_sym)
      end

      # Use the specified Rack middleware
      def use(middleware, *args, &block)
        @prototype = nil
        @middleware << [middleware, args, block]
      end

      # Stop the self-hosted server if running.
      def quit!
        return unless running?
        # Use Thin's hard #stop! if available, otherwise just #stop.
        running_server.respond_to?(:stop!) ? running_server.stop! : running_server.stop
        $stderr.puts "== Sinatra has ended his set (crowd applauds)" unless handler_name =~/cgi/i
        set :running_server, nil
        set :handler_name, nil
      end

      alias_method :stop!, :quit!

      # Run the Sinatra app as a self-hosted server using
      # Thin, Puma, Mongrel, or WEBrick (in that order). If given a block, will call
      # with the constructed handler once we have taken the stage.
      def run!(options = {}, &block)
        return if running?
        set options
        handler         = detect_rack_handler
        handler_name    = handler.name.gsub(/.*::/, '')
        server_settings = settings.respond_to?(:server_settings) ? settings.server_settings : {}
        server_settings.merge!(:Port => port, :Host => bind)

        begin
          start_server(handler, server_settings, handler_name, &block)
        rescue Errno::EADDRINUSE
          $stderr.puts "== Someone is already performing on port #{port}!"
          raise
        ensure
          quit!
        end
      end

      alias_method :start!, :run!

      # Check whether the self-hosted server is running or not.
      def running?
        running_server?
      end

      # The prototype instance used to process requests.
      def prototype
        @prototype ||= new
      end

      # Create a new instance without middleware in front of it.
      alias new! new unless method_defined? :new!

      # Create a new instance of the class fronted by its middleware
      # pipeline. The object is guaranteed to respond to #call but may not be
      # an instance of the class new was called on.
      def new(*args, &bk)
        instance = new!(*args, &bk)
        Wrapper.new(build(instance).to_app, instance)
      end

      # Creates a Rack::Builder instance with all the middleware set up and
      # the given +app+ as end point.
      def build(app)
        builder = Rack::Builder.new
        setup_default_middleware builder
        setup_middleware builder
        builder.run app
        builder
      end

      def call(env)
        synchronize { prototype.call(env) }
      end

      # Like Kernel#caller but excluding certain magic entries and without
      # line / method information; the resulting array contains filenames only.
      def caller_files
        cleaned_caller(1).flatten
      end

      # Like caller_files, but containing Arrays rather than strings with the
      # first element being the file, and the second being the line.
      def caller_locations
        cleaned_caller 2
      end

      private

      # Starts the server by running the Rack Handler.
      def start_server(handler, server_settings, handler_name)
        handler.run(self, server_settings) do |server|
          unless handler_name =~ /cgi/i
            $stderr.puts "== Sinatra/#{Sinatra::VERSION} has taken the stage " +
            "on #{port} for #{environment} with backup from #{handler_name}"
          end

          setup_traps
          set :running_server, server
          set :handler_name,   handler_name
          server.threaded = settings.threaded if server.respond_to? :threaded=

          yield server if block_given?
        end
      end

      def setup_traps
        if traps?
          at_exit { quit! }

          [:INT, :TERM].each do |signal|
            old_handler = trap(signal) do
              quit!
              old_handler.call if old_handler.respond_to?(:call)
            end
          end

          set :traps, false
        end
      end

      # Dynamically defines a method on settings.
      def define_singleton(name, content = Proc.new)
        # replace with call to singleton_class once we're 1.9 only
        (class << self; self; end).class_eval do
          undef_method(name) if method_defined? name
          String === content ? class_eval("def #{name}() #{content}; end") : define_method(name, &content)
        end
      end

      # Condition for matching host name. Parameter might be String or Regexp.
      def host_name(pattern)
        condition { pattern === request.host }
      end

      # Condition for matching user agent. Parameter should be Regexp.
      # Will set params[:agent].
      def user_agent(pattern)
        condition do
          if request.user_agent.to_s =~ pattern
            @params[:agent] = $~[1..-1]
            true
          else
            false
          end
        end
      end
      alias_method :agent, :user_agent

      # Condition for matching mimetypes. Accepts file extensions.
      def provides(*types)
        types.map! { |t| mime_types(t) }
        types.flatten!
        condition do
          if type = response['Content-Type']
            types.include? type or types.include? type[/^[^;]+/]
          elsif type = request.preferred_type(types)
            params = (type.respond_to?(:params) ? type.params : {})
            content_type(type, params)
            true
          else
            false
          end
        end
      end

      def route(verb, path, options = {}, &block)
        if path.class == String
          return if path.empty?
          path.chop! if (char=path[-1]) and char=='/'
        end

        # Because of self.options.host
        host_name(options.delete(:host)) if options.key?(:host)

        if /^[a-zA-Z0-9\-\/_]*$/ === path
          turbo_signature = turbo_compile!(verb, path, block, options)
          @turbo_routes[verb] ||= {}
          @turbo_routes[verb][path] = turbo_signature
        else
          signature = compile!(verb, path, block, options)
          (@routes[verb] ||= []) << signature
        end
        invoke_hook(:route_added, verb, path, block)
        signature
      end

      def invoke_hook(name, *args)
        extensions.each { |e| e.send(name, *args) if e.respond_to?(name) }
      end

      def generate_method(method_name, &block)
        define_method(method_name, &block)
        method = instance_method method_name
        remove_method method_name
        method
      end

      def turbo_compile!(verb, path, block, options = {})
        method_name             = "#{verb} #{path}"
        unbound_method          = generate_method(method_name, &block)
        wrapper                 = block.arity != 0 ?
          proc { |a,p| unbound_method.bind(a).call(*p) } :
          proc { |a,p| unbound_method.bind(a).call }
        wrapper.instance_variable_set(:@route_name, method_name)
        @blocks ||= {}
        block_id = @blocks.size + 1
        @blocks[block_id] = wrapper
        block_id
      end

      def compile!(verb, path, block, options = {})
        options.each_pair { |option, args| send(option, *args) }
        method_name             = "#{verb} #{path}"
        unbound_method          = generate_method(method_name, &block)
        pattern, keys           = compile path
        conditions, @conditions = @conditions, []

        wrapper                 = block.arity != 0 ?
          proc { |a,p| unbound_method.bind(a).call(*p) } :
          proc { |a,p| unbound_method.bind(a).call }
        wrapper.instance_variable_set(:@route_name, method_name)
        @blocks ||= {}
        block_id = @blocks.size + 1
        @blocks[block_id] = wrapper
        [ pattern, keys, conditions, block_id ]
      end

      def compile_filter!(verb, path, block, options = {})
        options.each_pair { |option, args| send(option, *args) }
        method_name             = "#{verb} #{path}"
        unbound_method          = generate_method(method_name, &block)
        pattern, keys           = compile path
        conditions, @conditions = @conditions, []

        wrapper                 = block.arity != 0 ?
          proc { |a,p| unbound_method.bind(a).call(*p) } :
          proc { |a,p| unbound_method.bind(a).call }
        wrapper.instance_variable_set(:@route_name, method_name)

        [ pattern, keys, conditions, wrapper ]
      end


      def compile(path)
        if path.respond_to? :to_str
          keys = []

          # We append a / at the end if there was one.
          # Reason: Splitting does not split off an empty
          # string at the end if the split separator
          # is at the end.
          #
          postfix = '/' if path =~ /\/\z/

          # Split the path into pieces in between forward slashes.
          #
          segments = path.split('/').map! do |segment|
            ignore = []

            # Special character handling.
            #
            pattern = segment.to_str.gsub(/[^\?\%\\\/\:\*\w]/) do |c|
              ignore << escaped(c).join if c.match(/[\.@]/)
              patt = encoded(c)
              patt.gsub(/%[\da-fA-F]{2}/) do |match|
                match.split(//).map! {|char| char =~ /[A-Z]/ ? "[#{char}#{char.tr('A-Z', 'a-z')}]" : char}.join
              end
            end

            ignore = ignore.uniq.join

            # Key handling.
            #
            pattern.gsub(/((:\w+)|\*)/) do |match|
              if match == "*"
                keys << 'splat'
                "(.*?)"
              else
                keys << $2[1..-1]
                ignore_pattern = safe_ignore(ignore)

                ignore_pattern
              end
            end
          end

          # Special case handling.
          #
          if segment = segments.pop
            if segment.match(/\[\^\\\./)
              parts = segment.rpartition(/\[\^\\\./)
              parts[1] = '[^'
              segments << parts.join
            else
              segments << segment
            end
          end
          [/\A#{segments.join('/')}#{postfix}\z/, keys]
        elsif path.respond_to?(:keys) && path.respond_to?(:match)
          [path, path.keys]
        elsif path.respond_to?(:names) && path.respond_to?(:match)
          [path, path.names]
        elsif path.respond_to? :match
          [path, []]
        else
          raise TypeError, path
        end
      end

      def encoded(char)
        enc = URI_INSTANCE.escape(char)
        enc = "(?:#{escaped(char, enc).join('|')})" if enc == char
        enc = "(?:#{enc}|#{encoded('+')})" if char == " "
        enc
      end

      def escaped(char, enc = URI_INSTANCE.escape(char))
        [Regexp.escape(enc), URI_INSTANCE.escape(char, /./)]
      end

      def safe_ignore(ignore)
        unsafe_ignore = []
        ignore = ignore.gsub(/%[\da-fA-F]{2}/) do |hex|
          unsafe_ignore << hex[1..2]
          ''
        end
        unsafe_patterns = unsafe_ignore.map! do |unsafe|
          chars = unsafe.split(//).map! do |char|
            if char =~ /[A-Z]/
              char <<= char.tr('A-Z', 'a-z')
            end
            char
          end

          "|(?:%[^#{chars[0]}].|%[#{chars[0]}][^#{chars[1]}])"
        end
        if unsafe_patterns.length > 0
          "((?:[^#{ignore}/?#%]#{unsafe_patterns.join()})+)"
        else
          "([^#{ignore}/?#]+)"
        end
      end

      def setup_default_middleware(builder)
        builder.use ExtendedRack
        builder.use ShowExceptions       if show_exceptions?
        builder.use Rack::MethodOverride if method_override?
        builder.use Rack::Head
        setup_logging    builder
        setup_sessions   builder
        setup_protection builder
      end

      def setup_middleware(builder)
        middleware.each { |c,a,b| builder.use(c, *a, &b) }
      end

      def setup_logging(builder)
        if logging?
          setup_common_logger(builder)
          setup_custom_logger(builder)
        elsif logging == false
          setup_null_logger(builder)
        end
      end

      def setup_null_logger(builder)
        builder.use Rack::NullLogger
      end

      def setup_common_logger(builder)
        builder.use Sinatra::CommonLogger
      end

      def setup_custom_logger(builder)
        if logging.respond_to? :to_int
          builder.use Rack::Logger, logging
        else
          builder.use Rack::Logger
        end
      end

      def setup_protection(builder)
        return unless protection?
        options = Hash === protection ? protection.dup : {}
        protect_session  = options.fetch(:session) { sessions? }
        options[:except] = Array options[:except]
        options[:except] += [:session_hijacking, :remote_token] unless protect_session
        options[:reaction] ||= :drop_session
        builder.use Rack::Protection, options
      end

      def setup_sessions(builder)
        return unless sessions?
        options = {}
        options[:secret] = session_secret if session_secret?
        options.merge! sessions.to_hash if sessions.respond_to? :to_hash
        builder.use Rack::Session::Cookie, options
      end

      def detect_rack_handler
        servers = Array(server)
        servers.each do |server_name|
          begin
            return Rack::Handler.get(server_name.to_s)
          rescue LoadError, NameError
          end
        end
        fail "Server handler (#{servers.join(',')}) not found."
      end

      def inherited(subclass)
        subclass.reset!
        subclass.set :app_file, caller_files.first unless subclass.app_file?
        super
      end

      @@mutex = Mutex.new
      def synchronize(&block)
        if lock?
          @@mutex.synchronize(&block)
        else
          yield
        end
      end

      # used for deprecation warnings
      def warn(message)
        super message + "\n\tfrom #{cleaned_caller.first.join(':')}"
      end

      # Like Kernel#caller but excluding certain magic entries
      def cleaned_caller(keep = 3)
        caller(1).
          map!    { |line| line.split(/:(?=\d|in )/, 3)[0,keep] }.
          reject { |file, *_| CALLERS_TO_IGNORE.any? { |pattern| file =~ pattern } }
      end
    end

    # Fixes encoding issues by
    # * defaulting to UTF-8
    # * casting params to Encoding.default_external
    #
    # The latter might not be necessary if Rack handles it one day.
    # Keep an eye on Rack's LH #100.
    def force_encoding(*args) settings.force_encoding(*args) end
    if defined? Encoding
      def self.force_encoding(data, encoding = default_encoding)
        return if data == settings || data.is_a?(Tempfile)
        if data.respond_to? :force_encoding
          data.force_encoding(encoding).encode!
        elsif data.respond_to? :each_value
          data.each_value { |v| force_encoding(v, encoding) }
        elsif data.respond_to? :each
          data.each { |v| force_encoding(v, encoding) }
        end
        data
      end
    else
      def self.force_encoding(data, *) data end
    end

    reset!

    set :environment, (ENV['RACK_ENV'] || :development).to_sym
    set :raise_errors, Proc.new { test? }
    set :dump_errors, Proc.new { !test? }
    set :show_exceptions, Proc.new { development? }
    set :sessions, false
    set :logging, false
    set :protection, true
    set :method_override, false
    set :use_code, false
    set :default_encoding, "utf-8"
    set :x_cascade, true
    set :add_charset, %w[javascript xml xhtml+xml json].map { |t| "application/#{t}" }
    settings.add_charset << /^text\//

    # explicitly generating a session secret eagerly to play nice with preforking
    begin
      require 'securerandom'
      set :session_secret, SecureRandom.hex(64)
    rescue LoadError, NotImplementedError
      # SecureRandom raises a NotImplementedError if no random device is available
      set :session_secret, "%064x" % Kernel.rand(2**256-1)
    end

    class << self
      alias_method :methodoverride?, :method_override?
      alias_method :methodoverride=, :method_override=
    end

    set :run, false                       # start server via at-exit hook?
    set :running_server, nil
    set :handler_name, nil
    set :traps, true
    set :server, %w[HTTP webrick]
    set :bind, Proc.new { development? ? 'localhost' : '0.0.0.0' }
    set :port, Integer(ENV['PORT'] && !ENV['PORT'].empty? ? ENV['PORT'] : 4567)

    ruby_engine = defined?(RUBY_ENGINE) && RUBY_ENGINE

    if ruby_engine == 'macruby'
      server.unshift 'control_tower'
    else
      server.unshift 'reel'
      server.unshift 'mongrel'  if ruby_engine.nil?
      server.unshift 'puma'     if ruby_engine != 'rbx'
      server.unshift 'thin'     if ruby_engine != 'jruby'
      server.unshift 'puma'     if ruby_engine == 'rbx'
      server.unshift 'trinidad' if ruby_engine == 'jruby'
    end

    set :absolute_redirects, true
    set :prefixed_redirects, false
    set :empty_path_info, nil

    set :app_file, nil
    set :root, Proc.new { app_file && File.expand_path(File.dirname(app_file)) }
    set :views, Proc.new { root && File.join(root, 'views') }
    set :reload_templates, Proc.new { development? }
    set :lock, false
    set :threaded, true

    set :public_folder, Proc.new { root && File.join(root, 'public') }
    set :static, Proc.new { public_folder && File.exist?(public_folder) }
    set :static_cache_control, false

    error ::Exception do
      response.status = 500
      content_type 'text/html'
      '<h1>Internal Server Error</h1>'
    end

    after do
      env['sinarey.common_params'] = @params
    end

    configure :development do
      get '/__sinatra__/:image.png' do
        filename = File.dirname(__FILE__) + "/images/#{params[:image]}.png"
        content_type :png
        send_file filename
      end

      error NotFound do
        content_type 'text/html'

        if self.class == Sinatra::Application
          code = <<-RUBY.gsub(/^ {12}/, '')
            #{request.request_method.downcase} '#{request.path_info}' do
              "Hello World"
            end
          RUBY
        else
          code = <<-RUBY.gsub(/^ {12}/, '')
            class #{self.class}
              #{request.request_method.downcase} '#{request.path_info}' do
                "Hello World"
              end
            end
          RUBY

          file = settings.app_file.to_s.sub(settings.root.to_s, '').sub(/^\//, '')
          code = "# in #{file}\n#{code}" unless file.empty?
        end

        (<<-HTML).gsub(/^ {10}/, '')
          <!DOCTYPE html>
          <html>
          <head>
            <style type="text/css">
            body { text-align:center;font-family:helvetica,arial;font-size:22px;
              color:#888;margin:20px}
            #c {margin:0 auto;width:500px;text-align:left}
            </style>
          </head>
          <body>
            <h2>Sinatra doesn&rsquo;t know this ditty.</h2>
            <img src='#{uri "/__sinatra__/404.png"}'>
            <div id="c">
              Try this:
              <pre>#{code}</pre>
            </div>
          </body>
          </html>
        HTML
      end
    end
  end

end