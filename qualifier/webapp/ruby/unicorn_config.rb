worker_processes 10
preload_app true

stderr_path File.expand_path('./../log/unicorn_stderr.log', __FILE__)
stdout_path File.expand_path('./../log/unicorn_stdout.log', __FILE__)
