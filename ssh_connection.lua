package.loaded.ssh_config = nil
require("ssh_config")

package.loaded.ssh_channel = nil
local SSH_Channel = require("ssh_channel")

local CHANNEL_INIT_ID = 0

SSH_Connection = {}
SSH_Connection.__index = SSH_Connection

function SSH_Connection.new(ssh_tran)
  local obj = {}
  obj.ssh_tran = ssh_tran
  obj.next_channel_id = CHANNEL_INIT_ID
  obj.channels = {}
  setmetatable(obj, SSH_Connection)
  return obj
end


function SSH_Connection:open_channel(request_type)

  local channel_type
  if request_type == REQUEST_COMMAND_TYPE or request_type == REQUEST_PTY_TYPE or request_type == REQUEST_TTY_TYPE then
    channel_type = "session"
  end

  local payload = string.char(SSH_MSG_CHANNEL_OPEN)
  payload = payload .. string.pack(">I4", #channel_type) .. channel_type
  payload = payload .. string.pack(">I4", self.next_channel_id)
  payload = payload .. string.pack(">I4", INIT_WINDOW_SIZE)
  payload = payload .. string.pack(">I4", MAX_PACKET_LEN)

  table.insert(self.channels,
    SSH_Channel.new_channel(request_type, self.next_channel_id, INIT_WINDOW_SIZE, 
  function(packet) self.ssh_tran:sendSSHPacket(packet) end))
  
  self.next_channel_id = self.next_channel_id + 1

  return payload

end


function SSH_Connection:channel_open_confirmation(packet)
  
  packet = packet:sub(2)
  local id_client = string.unpack(">I4", packet:sub(1, 4))
  local id_server = string.unpack(">I4", packet:sub(5, 8))
  local cur_window_server = string.unpack(">I4", packet:sub(9, 12))
  local max_packet_server = string.unpack(">I4", packet:sub(13, 16))

  local channel = self:get_channel(id_client)
  if channel == nil then
    return nil
  end

  return channel:confirm_open(id_server, cur_window_server, max_packet_server)

end


function SSH_Connection:channel_success(packet)

  packet = packet:sub(2)
  local id_client = string.unpack(">I4", packet:sub(1, 4))
  local channel = self:get_channel(id_client)

  if channel == nil then
    return nil
  end

  self.ssh_tran.socket:setTimeout(SSH_TIMEOUT)

  return channel:success()

end


function SSH_Connection:channel_failure(packet)

  packet = packet:sub(2)
  local id_client = string.unpack(">I4", packet:sub(1, 4))
  local channel = self:get_channel(id_client)

  if channel == nil then
    return nil
  end

  return channel:failure()

end


function SSH_Connection:channel_window_adjust(packet)

  packet = packet:sub(2)
  local id_client = string.unpack(">I4", packet:sub(1, 4))
  local bytes_to_add = string.unpack(">I4", packet:sub(5, 8))
  local channel = self:get_channel(id_client)

  if channel == nil then
    return nil
  end

  return channel:add_window_size(bytes_to_add)

end


function SSH_Connection:channel_recv_data(packet)

  packet = packet:sub(2)
  local id_client = string.unpack(">I4", packet:sub(1, 4))
  local data_len = string.unpack(">I4", packet:sub(5, 8))
  local data = packet:sub(9, 9 + data_len - 1)
  
  local channel = self:get_channel(id_client)

  if channel == nil then
    return nil
  end

  return channel:recv_data(data)

end



function SSH_Connection:channel_recv_request(packet)
    
    packet = packet:sub(2)
    local id_client = string.unpack(">I4", packet:sub(1, 4))
    local name_len = string.unpack(">I4", packet:sub(5, 8))
    local name = packet:sub(9, 9 + name_len - 1)
    local want_reply = string.byte(packet, 9 + name_len)
    local channel = self:get_channel(id_client)

    if channel == nil then
      return nil
    end

    if name == "exit-status" or name == "exit-signal" then
      return nil
    end

    if want_reply then
      return string.char(SSH_MSG_REQUEST_FAILURE)
    end

end


-- Called by processPaclet (server perform close of channel)
function SSH_Connection:channel_close(packet)

  packet = packet:sub(2)
  local id_client = string.unpack(">I4", packet:sub(1, 4))
  local channel, idx = self:get_channel(id_client)

  if channel == nil then
    return nil
  end

  table.remove(self.channels, idx)
  local payload, exit = channel:close()
  return payload, exit

end


-- Called by main (client perform close of all channel)
function SSH_Connection:conn_close()
  while #self.channels > 0 do
    local channel = self.channels[1]
    table.remove(self.channels, 1)

    local payload, _ = channel:close()
    self.ssh_tran:sendSSHPacket(payload)
  end
  self.ssh_tran.socket:flush()
end


function SSH_Connection:get_channel(id_client)
  for idx, channel in ipairs(self.channels) do
    if channel.id_client == id_client then
      return channel, idx
    end
  end
  return nil
end

return SSH_Connection