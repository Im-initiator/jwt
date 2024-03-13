JWT
user -> register(dont have token) -> server -> token (generatoken by userEmail) -> client.
user -> login(dont have token) ->success -> token (generatoken by userEmail) -> client.
user(not login) -> accessAnyAPI (attached token) -> spring security auto login by token(get userEmail in token -> getUserByEmail -> if(UserNotEmplty) => login
