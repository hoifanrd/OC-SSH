require("ssh_const")
local os = require("os")
local term = require("term")

SSH_Auth = {}
SSH_Auth.__index = SSH_Auth

local GET_SERVER_METHODS = 0
local PASSWORD_AUTH = 1
local PUBKEY_AUTH = 2

local AUTH_SUCCESS = 5

function SSH_Auth.new(ssh_tran, priv_key_file)
  local obj = {}
  obj.stage = nil
  obj.ssh_tran = ssh_tran
  obj.client_methods = OPENOS_SSH_AUTH_SUPPORTED
  obj.priv_key_file = priv_key_file
  setmetatable(obj, SSH_Auth)
  return obj
end


function SSH_Auth:list_server_method_payload()

  self.stage = GET_SERVER_METHODS

  local next_serv_name = "ssh-connection"
  local method = "none"

  local payload = string.char(SSH_MSG_USERAUTH_REQUEST)
  payload = payload .. string.pack(">I4", #self.ssh_tran.username) .. self.ssh_tran.username
  payload = payload .. string.pack(">I4", #next_serv_name) .. next_serv_name
  payload = payload .. string.pack(">I4", #method) .. method

  return payload
  
end


function SSH_Auth:handle_failure(packet)
  
  packet = packet:sub(2)
  
  local name_list
  name_list, packet = parseNamelist(packet)
  local partial = string.byte(packet, 1)
  assert( #packet == 1 )

  local method = self:determine_auth_method(name_list)
  if method == nil then
    print("Client does not support authentication protocol requested by server: " .. table.concat(name_list, ","))
    os.exit()
  end

  local payload = nil
  if self.stage == GET_SERVER_METHODS then
    
    -- Must not be partial success
    assert( partial == 0 )

    payload = self:create_auth_method_payload(method)
    self.stage = method

  elseif self.stage == PASSWORD_AUTH or self.stage == PUBKEY_AUTH then

    if partial == 1 then

      print("Further authentication required.")

      payload = self:create_auth_method_payload(method)
      self.stage = method
    
    else

      if self.stage == PUBKEY_AUTH then
        print( "Invalid public ssh key." )
        self.client_methods["publickey"] = nil
      end

      local new_method = self:determine_auth_method(name_list)
      if new_method == nil then
        os.exit()
      end

      if self.stage == new_method and self.stage == PASSWORD_AUTH then
        print("Permission denied, please try again.")
      end
      
      payload = self:create_auth_method_payload(new_method)
      self.state = new_method

    end

  end

  return payload

end


function SSH_Auth:create_auth_method_payload(auth_method)

  local username = self.ssh_tran.username
  local next_serv_name = "ssh-connection"

  local payload
  if auth_method == PASSWORD_AUTH then
    
    local method_str = "password"

    local port_repr = ":" .. self.ssh_tran.port
    if self.ssh_tran.port == 22 then
      port_repr = ""
    end

    local hostname = username .. "@" .. self.ssh_tran.host .. port_repr
    term.write(hostname .. "'s password: ")
    -- TODO: Fix the bug that pressing backspace may erase the line
    local password = term.read({}, true, {}, "")
    print()
    password = password:sub(1, #password - 1)
    
    payload = string.char(SSH_MSG_USERAUTH_REQUEST)
    payload = payload .. string.pack(">I4", #username) .. username
    payload = payload .. string.pack(">I4", #next_serv_name) .. next_serv_name
    payload = payload .. string.pack(">I4", #method_str) .. method_str
    payload = payload .. string.char(0)
    payload = payload .. string.pack(">I4", #password) .. password

  elseif auth_method == PUBKEY_AUTH then
    
    -- TODO?

  end

  return payload

end


function SSH_Auth:set_auth_success()
  self.stage = AUTH_SUCCESS
end


function SSH_Auth:is_auth_auccess()
  return self.stage == AUTH_SUCCESS
end

function SSH_Auth:determine_auth_method(server_methods)

  if arrayContains(self.client_methods, "publickey") and 
    arrayContains(server_methods, "publickey") and self.priv_key_file ~= nil then
    
    return PUBKEY_AUTH
    
  elseif arrayContains(self.client_methods, "password") and arrayContains(server_methods, "password") then

    return PASSWORD_AUTH

  end

  return nil

end


return SSH_Auth