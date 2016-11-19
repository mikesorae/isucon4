require 'sinatra/base'
require 'digest/sha2'
require 'mysql2-cs-bind'
require 'rack-flash'
require 'json'
require 'redis'

module Isucon4
  class App < Sinatra::Base
    @@redis = Redis.new
    
    use Rack::Session::Cookie, secret: ENV['ISU4_SESSION_SECRET'] || 'shirokane'
    use Rack::Flash
    set :public_folder, File.expand_path('../../public', __FILE__)

    helpers do

      def config
        @config ||= {
          user_lock_threshold: (ENV['ISU4_USER_LOCK_THRESHOLD'] || 3).to_i,
          ip_ban_threshold: (ENV['ISU4_IP_BAN_THRESHOLD'] || 10).to_i,
        }
      end

      def db
        Thread.current[:isu4_db] ||= Mysql2::Client.new(
          host: ENV['ISU4_DB_HOST'] || 'localhost',
          port: ENV['ISU4_DB_PORT'] ? ENV['ISU4_DB_PORT'].to_i : nil,
          username: ENV['ISU4_DB_USER'] || 'root',
          password: ENV['ISU4_DB_PASSWORD'],
          database: ENV['ISU4_DB_NAME'] || 'isu4_qualifier',
          reconnect: true,
        )
      end

      def init
        db.xquery('SELECT ip, user_id, login FROM login_log WHERE succeeded = 0').each do |row|
          login_log(0, row['login'], row['ip'])
          if row['user_id']
            login_log(0, row['login'], row['ip'], row['user_id'])
          end
        end
        
        @@redis.keys().each {|key|
          if key == 'ipbans' || key == 'userlocks'
            @@redis.smembers(key).each {|member|
              p 'sadd ' + key + ' ' + member
            }
          else
            p 'set ' + key + ' ' + @@redis.get(key)
          end
        }
      end

      def calculate_password_hash(password, salt)
        Digest::SHA256.hexdigest "#{password}:#{salt}"
      end

      def login_log(succeeded, login, ip, user_id = nil)
        if succeeded
          @@redis.del("ip:#{ip}")
          if user_id 
            @@redis.del("user:#{user_id.to_s}")
          end
        else
          if @@redis.incr('ip:' + ip) >= config[:ip_ban_threshold]
            @@redis.sadd('ipbans', ip)
          end
          
          if user_id 
            if @@redis.incr("user:#{user_id}") >= config[:user_lock_threshold]
              @@redis.sadd('userlocks', login)
            end
          end
        end
      end

      def user_locked?(user)
        return nil unless user
        config[:user_lock_threshold] <= (@@redis.get("user:#{user['id'].to_s}") && @@redis.get("user:#{user['id'].to_s}").to_i || 0)
      end

      def ip_banned?
        config[:ip_ban_threshold] <= (@@redis.get('ip:' + request.ip) && @@redis.get('ip:' + request.ip).to_i || 0)
      end

      def attempt_login(login, password)
        user = db.xquery('SELECT * FROM users WHERE login = ?', login).first

        if ip_banned?
          login_log(false, login, request.ip, user ? user['id'] : nil)
          return [nil, :banned]
        end

        if user_locked?(user)
          login_log(false, login, request.ip, user['id'])
          return [nil, :locked]
        end

        if user && calculate_password_hash(password, user['salt']) == user['password_hash']
          login_log(true, login, request.ip, user['id'])
          [user, nil]
        elsif user
          login_log(false, login, request.ip, user['id'])
          [nil, :wrong_password]
        else
          login_log(false, login, request.ip)
          [nil, :wrong_login]
        end
      end

      def current_user
        return @current_user if @current_user
        return nil unless session[:user_id]

        @current_user = db.xquery('SELECT usre_id FROM users WHERE id = ?', session[:user_id].to_i).first
        unless @current_user
          session[:user_id] = nil
          return nil
        end

        @current_user
      end

      def last_login #使われてないっぽい
        return nil unless current_user

        db.xquery('SELECT * FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2', current_user['id']).each.last
      end

      def banned_ips
        ips = []
        threshold = config[:ip_ban_threshold]

        @@redis.smembers('ipbans').each {|ip|
            ips << ip
        }

        ips
      end

      def locked_users
        user_names = []
        threshold = config[:user_lock_threshold]

        @@redis.smembers('userlocks').each {|user_name|
            user_names << user_name
        }

        user_names
      end
    end

    get '/' do
      init
      erb :index, layout: :base
    end 

    post '/login' do
      user, err = attempt_login(params[:login], params[:password])
      if user
        session[:user_id] = user['id']
        redirect '/mypage'
      else
        case err
        when :locked
          flash[:notice] = "This account is locked."
        when :banned
          flash[:notice] = "You're banned."
        else
          flash[:notice] = "Wrong username or password"
        end
        redirect '/'
      end
    end

    get '/mypage' do
      unless current_user
        flash[:notice] = "You must be logged in"
        redirect '/'
      end
      erb :mypage, layout: :base
    end

    get '/report' do
      content_type :json
      {
        banned_ips: banned_ips,
        locked_users: locked_users,
      }.to_json
    end
  end
end
