module PunditCustomErrors
  # Module created to override Pundit's 'authorize' function. It enables Pundit
  # to use the 'error_message' attribute (if existent) inside a Policy object,
  # displaying the given error message instead of a default error message.
  module Authorization
    def authorize(record, query = nil)
      query ||= params[:action].to_s + '?'

      @_pundit_policy_authorized = true

      policy = policy(record)

      unless policy.public_send(query)
        generate_error_for(policy, query, record)
      end

      record
    end

    protected

    def generate_error_for(policy, query, record)
      if policy.respond_to? :error_message
        message = policy.error_message
        policy.error_message = nil
      end

      message ||= translate_error_message_for_query(query, policy)
      message ||= "not allowed to #{query} this #{record}"

      raise Pundit::NotAuthorizedError, message: message, query: query, record: record, policy: policy
    end

    def translate_error_message_for_query(query, policy)
      t("#{policy.class.to_s.underscore}.#{query}",
        scope: 'pundit',
        default: :default) if self.respond_to?(:t)
    end
  end
end
