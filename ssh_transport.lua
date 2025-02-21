require("ssh_config")
require("ssh_const")
require("utils")

package.loaded.ssh_kex = nil
local SSH_Kex = require("ssh_kex")

package.loaded.ssh_auth = nil
local SSH_Auth = require("ssh_auth")

package.loaded.ssh_connection = nil
local SSH_Connection = require("ssh_connection")

package.loaded.ssh_socket = nil
local SSH_Socket = require("ssh_socket")

local os = require("os")
local component = require("component")

SSH_Transport = {}
SSH_Transport.__index = SSH_Transport

function SSH_Transport.new(host, port, username, debug)
  local obj = {}
  obj.host = host
  obj.port = port
  if #username == 0 then username = nil end
  obj.username = username or "root"
  obj.socket = SSH_Socket.new(host, port)

  obj.new_kex = nil    -- Kex to be applied
  obj.kex = nil        -- Kex using right now
  obj.auth = nil
  obj.connection = nil
  obj.debug = debug or false

  obj.packet_seq_no_client = string.char(0,0,0,0)
  obj.packet_seq_no_server = string.char(0,0,0,0)

  obj.identify_str_client = SSH_IDENTIFY_STRING
  obj.identify_str_server = nil
  obj.session_id = nil

  -- Make sure server reply message is only received if required
  obj.packet_sent = {}

  setmetatable(obj, SSH_Transport)
  obj.socket:setTimeout(CONNECT_TIMEOUT)
  return obj
end


function SSH_Transport:protoEx()
  self.identify_str_server = self.socket:read("*l")
  if self.debug then
    print(self.identify_str_server)
  end
  self.socket:write(self.identify_str_client .. "\13\10")
end


function SSH_Transport:readSSHPacket(blocking)

  blocking = blocking or false
  local payload
  
  if self.kex == nil then

    local init_bytes = self.socket:read(4, blocking)
    if #init_bytes == 0 then
      return init_bytes
    end

    local len = string.unpack(">I4", init_bytes)
    local pad_len = string.byte(self.socket:read(1))
    payload = self.socket:read(len - pad_len - 1)
    local pad = self.socket:read(pad_len)

  else

    local enc_algo_s2c = self.kex.algos["encryption_algorithms_server_to_client"].instance
    local mac_algo_s2c = self.kex.algos["mac_algorithms_server_to_client"].instance

    local enc_chunk1 = self.socket:read(enc_algo_s2c.get_chunk_len(), blocking)
    if #enc_chunk1 == 0 then
      return enc_chunk1
    end
    local chunk1 = enc_algo_s2c:decrypt(enc_chunk1)
    
    local len = string.unpack(">I4", chunk1:sub(1, 4))
    local pad_len = string.byte(chunk1:sub(5, 5))
    
    local payload_pad = chunk1:sub(6)
    local remain_len = len - 1 - #payload_pad
    if remain_len > 0 then
      payload_pad = payload_pad .. enc_algo_s2c:decrypt(self.socket:read(remain_len))
    end

    payload = payload_pad:sub(1, len - pad_len - 1)
    local pad = payload_pad:sub(len - pad_len)

    local mac = self.socket:read(mac_algo_s2c.get_hmac_len())
    local packet = string.pack(">I4", len) .. string.char(pad_len) .. payload .. pad
    local calc_mac = mac_algo_s2c:create_hmac(self.packet_seq_no_server .. packet)

    if mac ~= calc_mac then
      print("Connection corrupted: Invalid HMAC received.")
      os.exit()
    end
    
  end

  self.packet_seq_no_server = incr_bitstr(self.packet_seq_no_server)
  return payload

end

function SSH_Transport:sendSSHPacket(payload)

  if type(payload) == "table" then
    
    for _, p in ipairs(payload) do
      self:sendSSHPacket(p)
    end

  elseif type(payload) == "string" then

    local pad_len = PACKET_PADDING_LEN - ((4 + 1 + #payload) % PACKET_PADDING_LEN)
    if pad_len < 4 then
      pad_len = pad_len + PACKET_PADDING_LEN
    end

    local pad = component.data.random(pad_len)
    local len = #payload + 1 + pad_len

    local packet = string.pack(">I4", len) .. string.char(pad_len) .. payload .. pad

    local mac = ""
    if self.kex ~= nil then
      local mac_algo_c2s = self.kex.algos["mac_algorithms_client_to_server"].instance
      mac = mac_algo_c2s:create_hmac(self.packet_seq_no_client .. packet)
      
      local enc_algo_c2s = self.kex.algos["encryption_algorithms_client_to_server"].instance
      packet = enc_algo_c2s:encrypt(packet)
    end
    
    packet = packet .. mac

    self.socket:write(packet)

    self.packet_seq_no_client = incr_bitstr(self.packet_seq_no_client)
  
  end

end

function SSH_Transport:processPacket()

  --[[
  if #self.socket.bufferWrite > 0 then
    write_to_log("Sending: \n")
    write_to_log(#self.socket.bufferWrite)
    write_to_log("\n\n")
  end
  --]]
  self.socket:flush()

  local packet = self:readSSHPacket()
  if #packet == 0 then
    return
  end

  local packet_type = string.byte(packet:sub(1, 1))

  if packet_type == SSH_MSG_KEXINIT then

    -- Client: SSH_MSG_KEXINIT
    self.new_kex = SSH_Kex.new(self)
    local status, payload, skip_guessed_kex_server = pcall(self.new_kex.create_kex_client, self.new_kex, packet)

    if not status then
      print(payload)
      os.exit()
    end

    if skip_guessed_kex_server then
      self:readSSHPacket(true)
    end

    self:sendSSHPacket(payload)


    -- Client: SSH_MSG_KEX_ECDH_INIT
    local pubkey_client_bytes = self.new_kex.algos["kex_algorithms"].instance:get_pubkey_client_bytes()
    
    -- Octet string is followed by uint32 identifying the string len
    payload = string.char(SSH_MSG_KEX_ECDH_INIT) .. string.pack(">I4", #pubkey_client_bytes) .. pubkey_client_bytes
    self:sendSSHPacket(payload)

    self.packet_sent[SSH_MSG_KEX_ECDH_INIT] = true

  elseif packet_type == SSH_MSG_KEX_ECDH_REPLY then

    -- If the reply message is actually not required
    if not self.packet_sent[SSH_MSG_KEX_ECDH_INIT] then
      return
    end
    self.packet_sent[SSH_MSG_KEX_ECDH_INIT] = nil

    -- res = session_id
    local status, res = pcall(self.new_kex.receive_kex_server, self.new_kex, packet)
    if not status then
      print(res)
      os.exit()
    end

    -- Fixed for same conn even re-kex
    if self.session_id == nil then
      self.session_id = self.new_kex.algos["kex_algorithms"].instance.exchange_hash
    end

    -- Init encryption / mac instance (i.e. generate and setup init keys)
    self.new_kex:encryption_mac_instance_setkey(self.session_id)

  elseif packet_type == SSH_MSG_NEWKEYS then

    local payload = string.char(SSH_MSG_NEWKEYS)
    self:sendSSHPacket(payload)

    self.kex = self.new_kex
    if self.debug then
      print("kex_algorithms: Sent SSH_MSG_NEWKEYS packet.")
    end

    -- Perform ssh-userauth if it's the initial kex
    if not self.packet_sent[SSH_MSG_SERVICE_REQUEST] then
      
      local auth_name = "ssh-userauth"
      local payload = string.char(SSH_MSG_SERVICE_REQUEST)
      payload = payload .. string.pack(">I4", #auth_name) .. auth_name

      self:sendSSHPacket(payload)
      self.packet_sent[SSH_MSG_SERVICE_REQUEST] = true

    end

  elseif packet_type == SSH_MSG_SERVICE_ACCEPT then

    -- Can only accept if requested!
    if not self.packet_sent[SSH_MSG_SERVICE_REQUEST] then
      return
    end

    local content = packet:sub(2)
    local name_len = string.unpack(">I4", content:sub(1, 4))
    local service_name = content:sub(5, 5 + name_len - 1)

    if service_name == "ssh-userauth" then
      
      -- If SSH_MSG_SERVICE_ACCEPT ("ssh-userauth") is not required  
      if self.auth then
        return
      end

      self.auth = SSH_Auth.new(self, self.port)
      local payload = self.auth:list_server_method_payload()
      self:sendSSHPacket(payload)

    else

      print("Unsupported SSH service name received: " .. service_name .. ".")
      os.exit()

    end
  
  elseif packet_type == SSH_MSG_USERAUTH_FAILURE then
    
    if self.auth then
      
      local payload = self.auth:handle_failure(packet)
      if payload == nil then
        return
      end

      self:sendSSHPacket(payload)

    end

  elseif packet_type == SSH_MSG_USERAUTH_SUCCESS then
    
    if not self.auth:is_auth_auccess() then

      self.auth:set_auth_success()
      self.connection = SSH_Connection.new(self)
      
      -- TODO? If the user want to open channel type other type?
      local payload = self.connection:open_channel(REQUEST_PTY_TYPE)
      self:sendSSHPacket(payload)

    end

  elseif packet_type == SSH_MSG_USERAUTH_BANNER then
    
    -- Skip display of banner

  elseif packet_type == SSH_MSG_DISCONNECT then

    packet = packet:sub(2)
    local code = string.unpack(">I4", packet:sub(1, 4))
    local reason_len = string.unpack(">I4", packet:sub(5, 8))
    local reason = packet:sub(9, 9 + reason_len - 1)

    if self.debug then
      print("\nDisconnected with reason code: " .. code)
    end

    if #reason > 0 then
      print(reason)
    end

    os.exit()

  elseif packet_type == SSH_MSG_GLOBAL_REQUEST then

    packet = packet:sub(2)
    
    local req_name_len = string.unpack(">I4", packet:sub(1, 4))
    local req_name = packet:sub(5, 5 + req_name_len - 1)
    packet = packet:sub(5 + req_name_len)

    local want_reply = string.byte(packet, 1)
    packet = packet:sub(2)

    if self.debug then
      print("Received SSH_MSG_GLOBAL_REQUEST service request: " .. req_name)
    end

    -- Reject all global request :)
    if want_reply == 1 then
      self:sendSSHPacket(string.char(SSH_MSG_REQUEST_FAILURE))
    end

  elseif packet_type == SSH_MSG_CHANNEL_OPEN_CONFIRMATION then

    local payload = self.connection:channel_open_confirmation(packet)
    self:sendSSHPacket(payload)

  elseif packet_type == SSH_MSG_CHANNEL_SUCCESS then

    -- Disable debug message after opened connection
    self.debug = false
    local payload = self.connection:channel_success(packet)
    self:sendSSHPacket(payload)

  elseif packet_type == SSH_MSG_CHANNEL_WINDOW_ADJUST then

    local payload = self.connection:channel_window_adjust(packet)
    self:sendSSHPacket(payload)

  elseif packet_type == SSH_MSG_CHANNEL_DATA then

    -- no need to send return because channel is a stream?
    self.connection:channel_recv_data(packet)

  elseif packet_type == SSH_MSG_CHANNEL_REQUEST then

    local payload = self.connection:channel_recv_request(packet)
    self:sendSSHPacket(payload)

  elseif packet_type == SSH_MSG_CHANNEL_EOF then
    
    -- Just ignore it
  
  elseif packet_type == SSH_MSG_CHANNEL_CLOSE then

    local payload, exit = self.connection:channel_close(packet)
    self:sendSSHPacket(payload)

    if exit then
      self:terminate()
    end

  else

    -- print(packet_type)

  end

end


function SSH_Transport:terminate()
  if self.connection then
    self.connection:conn_close()
  end
  os.exit()
end


return SSH_Transport