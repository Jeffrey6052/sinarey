require 'sinatra/base'

module Sinatra

  module SinareyReloader

    class Watcher

      class Element < Struct.new(:type, :representation)
      end

      class List
        @app_list_map = Hash.new { |hash, key| hash[key] = new }

        def self.for(app)
          @app_list_map[app]
        end

        def initialize
          @path_watcher_map = Hash.new do |hash, key|
            hash[key] = Watcher.new(key)
          end
        end

        def watch(path, element)
          watcher_for(path).elements << element
        end

        def ignore(path)
          watcher_for(path).ignore
        end

        def watcher_for(path)
          @path_watcher_map[File.expand_path(path)]
        end
        alias watch_file watcher_for

        def watchers
          @path_watcher_map.values
        end

        def updated
          watchers.find_all(&:updated?)
        end
      end

      attr_reader :path, :elements, :mtime

      def initialize(path)
        @path, @elements = path, []
        update
      end

      def updated?
        !ignore? && !removed? && mtime != File.mtime(path)
      end

      def update
        @mtime = File.mtime(path)
      end

      def inline_templates?
        elements.any? { |element| element.type == :inline_templates }
      end

      def ignore
        @ignore = true
      end

      def ignore?
        !!@ignore
      end

      def removed?
        !File.exist?(path)
      end
    end

    def self.registered(klass)
      @reloader_loaded_in ||= {}
      return if @reloader_loaded_in[klass]

      @reloader_loaded_in[klass] = true

      klass.extend BaseMethods
      klass.extend ExtensionMethods
      klass.set(:reload_templates) { true }

      def klass.auto_reload
        SinareyReloader.perform(settings)
      end

      klass.before do
        SinareyReloader.perform(klass)
      end
      klass.set(:inline_templates, klass.app_file) if klass == Sinatra::Application
    end

    def self.perform(klass)
      updated_sum = 0
      Watcher::List.for(klass).updated.each do |watcher|
        updated_sum += 1
        klass.set(:inline_templates, watcher.path) if watcher.inline_templates?
        watcher.elements.each { |element|
          klass.deactivate(element) 
        }
        $LOADED_FEATURES.delete(watcher.path)
        require watcher.path
        watcher.update
      end
      return updated_sum
    end

    def self.thread_safe?
      Thread and Thread.list.size > 1 and Thread.respond_to?(:exclusive)
    end

    module BaseMethods
      def run!(*args)
        if settings.reloader?
          super unless running?
        else
          super
        end
      end

      def compile!(verb, path, block, options = {})
        source_location = block.respond_to?(:source_location) ?
          block.source_location.first : caller_files[1]
        signature = super
        watch_element(
          source_location, :route, { :verb => verb, :signature => signature }
        )
        signature
      end

      def turbo_compile!(verb, path, block, options = {})
        source_location = block.respond_to?(:source_location) ?
          block.source_location.first : caller_files[1]
        signature = super
        watch_element(
          source_location, :turbo_route, { :verb => verb, :path => path, :block_id => signature }
        )
        signature
      end

      def inline_templates=(file=nil)
        file = (file.nil? || file == true) ?
          (caller_files[1] || File.expand_path($0)) : file
        watch_element(file, :inline_templates)
        super
      end

      def use(middleware, *args, &block)
        path = caller_files[1] || File.expand_path($0)
        watch_element(path, :middleware, [middleware, args, block])
        super
      end

      def add_filter(type, path = nil, options = {}, &block)
        source_location = block.respond_to?(:source_location) ?
          block.source_location.first : caller_files[1]
        result = super
        watch_element(source_location, :"#{type}_filter", filters[type].last)
        result
      end

      def error(*codes, &block)
        path = caller_files[1] || File.expand_path($0)
        result = super
        codes.each do |c|
          watch_element(path, :error, :code => c, :handler => @errors[c])
        end
        result
      end

      def register(*extensions, &block)
        start_registering_extension
        result = super
        stop_registering_extension
        result
      end

      def inherited(subclass)
        result = super
        subclass.register Sinatra::SinareyReloader
        result
      end
    end

    module ExtensionMethods
      def deactivate(element)
        case element.type
        when :route then
          verb      = element.representation[:verb]
          signature = element.representation[:signature]
          block_id  = signature.last
          (blocks ||= {}).delete(block_id)
          (routes[verb] ||= []).delete(signature)
        when :turbo_route then
          verb      = element.representation[:verb]
          path      = element.representation[:path]
          block_id  = element.representation[:block_id]
          (blocks ||= {}).delete(block_id)
          (turbo_routes[verb] ||= {}).delete(path)
        when :middleware then
          @middleware.delete(element.representation)
        when :before_filter then
          filters[:before].delete(element.representation)
        when :after_filter then
          filters[:after].delete(element.representation)
        when :error then
          code    = element.representation[:code]
          handler = element.representation[:handler]
          @errors.delete(code) if @errors[code] == handler
        end
      end

      def also_reload(*glob)
        Dir[*glob].each { |path| Watcher::List.for(self).watch_file(path) }
      end

      def dont_reload(*glob)
        Dir[*glob].each { |path| Watcher::List.for(self).ignore(path) }
      end

    private

      attr_reader :register_path

      def start_registering_extension
        @register_path = caller_files[2]
      end

      def stop_registering_extension
        @register_path = nil
      end

      def registering_extension?
        !register_path.nil?
      end

      def watch_element(path, type, representation=nil)
        list = Watcher::List.for(self)
        element = Watcher::Element.new(type, representation)
        list.watch(path, element)
        list.watch(register_path, element) if registering_extension?
      end
    end
  end

  register SinareyReloader
  Delegator.delegate :also_reload, :dont_reload
end
