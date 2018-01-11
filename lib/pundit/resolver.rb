module Pundit
  class Resolver

    # Retrieves the policy for the given record, initializing it with the
    # record and user and finally throwing an error if the user is not
    # authorized to perform the given action.
    #
    # @param user [Object] the user that initiated the action
    # @param record [Object] the object we're checking permissions of
    # @param query [Symbol, String] the predicate method to check on the policy (e.g. `:show?`)
    # @raise [NotAuthorizedError] if the given query method returned false
    # @return [Object] Always returns the passed object record
    def authorize(user, record, query)
      policy = policy!(user, record)

      unless policy.public_send(query)
        raise NotAuthorizedError, query: query, record: record, policy: policy
      end

      record
    end

    # Retrieves the policy scope for the given record.
    #
    # @see https://github.com/elabs/pundit#scopes
    # @param user [Object] the user that initiated the action
    # @param scope [Object] the object we're retrieving the policy scope for
    # @return [Scope{#resolve}, nil] instance of scope class which can resolve to a scope
    def policy_scope(user, scope)
      policy_scope = policy_finder(scope).scope
      policy_scope.new(user, scope).resolve if policy_scope
    end

    # Retrieves the policy scope for the given record.
    #
    # @see https://github.com/elabs/pundit#scopes
    # @param user [Object] the user that initiated the action
    # @param scope [Object] the object we're retrieving the policy scope for
    # @raise [NotDefinedError] if the policy scope cannot be found
    # @return [Scope{#resolve}] instance of scope class which can resolve to a scope
    def policy_scope!(user, scope)
      policy_finder(scope).scope!.new(user, scope).resolve
    end

    # Retrieves the policy for the given record.
    #
    # @see https://github.com/elabs/pundit#policies
    # @param user [Object] the user that initiated the action
    # @param record [Object] the object we're retrieving the policy for
    # @return [Object, nil] instance of policy class with query methods
    def policy(user, record)
      policy = policy_finder(record).policy
      policy.new(user, record) if policy
    end

    # Retrieves the policy for the given record.
    #
    # @see https://github.com/elabs/pundit#policies
    # @param user [Object] the user that initiated the action
    # @param record [Object] the object we're retrieving the policy for
    # @raise [NotDefinedError] if the policy cannot be found
    # @return [Object] instance of policy class with query methods
    def policy!(user, record)
      policy_finder(record).policy!.new(user, record)
    end

    protected

    def policy_finder(object)
      PolicyFinder.new(object)
    end
  end
end
