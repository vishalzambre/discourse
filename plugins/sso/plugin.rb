# require '../app/models/group'
module DiscourseSSO
  module ControllerExtensions
    def self.included(klass)
      klass.append_before_filter :sso_login
    end

    private

    def sso_login
      if request["sso"].present?

        # if we don't have a secret, create one
        secret = SiteSetting.sso_shared_secret
        unless secret.present?
          secret = SecureRandom.hex(32)
          SiteSetting.send('sso_shared_secret=', secret)
        end

        # get the payload and split it
        sso = Base64.decode64 request['sso']
        userid, group, ts, signature = sso.split(':')
        return if (secret != signature)

        # return if group is not present
        user_groups = Group.where(id: group)
        # quit if the timestamp is too far off
        tdiff = ts.to_i - Time.now.to_i
        return if tdiff.abs > 180

        # find out what kind of user data we have (email, id or username) and load
        if userid.include? '@'
          user = User.where(email: userid.downcase).first
        elsif userid.to_i.to_s == userid
          user = User.where(id: userid.to_i).first
        else
          user = User.where(username_lower: userid.downcase).first
        end

        # got it? log on and refresh
        unless user.present?
          # return if user_groups.blank?
          username = userid[/\w+[a-zA-Z0-9_.]+/].gsub('.', '')[0..19].downcase
          i = 1
          begin
            existing = User.find_by(username_lower: username)
            username = existing.present? ? "#{username}_#{i}" : username
            i += 1
          end while existing.present?

          user = User.new(email: userid.downcase, username: username)
          user.password = SecureRandom.hex if user.password.blank?
          user.save
          user.activate

          p "---------------#{group}"
          p "--------------#{user_groups.inspect}"
          p "------before ---------#{user.groups.inspect}"
          user.set_group(group)
          p "------after ---------#{user.groups.inspect}"
        end
        log_on_user(user)
        return
      end
    end

  end
end

after_initialize do

  User.class_eval do
    alias_method :old_create_email_token, :create_email_token
    alias_method :old_email_confirmed?, :email_confirmed?

    def active?
      if SiteSetting.sso_disable_activationmails?
        true
      else
        self.active
      end
    end
  
    def email_confirmed?
      if SiteSetting.sso_disable_activationmails?
        true
      else
        old_email_confirmed?
      end
    end

    def create_email_token
      if SiteSetting.sso_disable_activationmails?
        true
      else
        old_create_email_token
      end
    end
  end

end

ActiveSupport.on_load(:action_controller) do
  include DiscourseSSO::ControllerExtensions
end
