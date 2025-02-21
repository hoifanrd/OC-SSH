-- Acts as an abstract class

package.loaded.ssh_config = nil
require("ssh_config")

CHANNEL = {}
CHANNEL.__index = CHANNEL

function CHANNEL.new(id, cur_window, sendSSHPacket)

  local obj = {}
  obj.id_client = id
  obj.id_server = nil
  obj.cur_window_client = cur_window
  obj.cur_window_server = nil
  obj.max_packet_server = nil
  
  obj.sendSSHPacket = sendSSHPacket
  obj.data_buf = ""          -- Used for buf if window size not enough

  -- For subclass instance
  obj.req_type = nil
  obj.type_confirm_open = nil
  obj.type_success = nil
  obj.type_close = nil
  obj.type_recv_data = nil

  setmetatable(obj, CHANNEL)
  return obj

end


function CHANNEL:confirm_open(id_server, cur_window_server, max_packet_server)

  if self.id_server ~= nil then
    return nil
  end

  self.id_server = id_server
  self.cur_window_server = cur_window_server
  self.max_packet_server = max_packet_server

  if self.type_confirm_open then
    return self:type_confirm_open()
  end

  return nil
  
end


function CHANNEL:add_window_size(bytes_to_add)
  if self.cur_window_server == nil then
    return
  end

  self.cur_window_server = self.cur_window_server + bytes_to_add
  if #self.data_buf > 0 then
    local status, res = self:send_data(self.data_buf, false)
    if not status then
      self.data_buf = res
    end
  end

end


function CHANNEL:recv_data(data)

  self.cur_window_client = self.cur_window_client - #data

  if self.cur_window_client <= INIT_WINDOW_SIZE then
    
    local payload = string.char(SSH_MSG_CHANNEL_WINDOW_ADJUST)
    payload = payload .. string.pack(">I4", self.id_server)
    payload = payload .. string.pack(">I4", RESIZE_WINDOW_SIZE)

    self.sendSSHPacket(payload)

    self.cur_window_client = self.cur_window_client + RESIZE_WINDOW_SIZE
  end

  if self.type_recv_data then
    self:type_recv_data(data)
  end

end


-- Fail to add means not enough window size
function CHANNEL:send_data(data, append_to_buf)
  -- Whether to add to buffer if failed to send, avoid infinite func call from add_window_size
  -- Otherwise return the data failed to send
  append_to_buf = append_to_buf or true

  local num_data_to_send = math.min(self.cur_window_server, self.max_packet_server, #data)
  while num_data_to_send > 0 do
    local data_to_send = data:sub(1, num_data_to_send)
    data = data:sub(num_data_to_send + 1)

    local payload = string.char(SSH_MSG_CHANNEL_DATA)
    payload = payload .. string.pack(">I4", self.id_server)
    payload = payload .. string.pack(">I4", #data_to_send) .. data_to_send

    self.sendSSHPacket(payload)

    self.cur_window_server = self.cur_window_server - num_data_to_send
    num_data_to_send = math.min(self.cur_window_server, self.max_packet_server, #data)
  end
  
  if #data > 0 then
    
    if append_to_buf then
      self.data_buf = self.data_buf .. data
    end

    return false, data

  end

  return true

end


function CHANNEL:close()
  
  local exit = nil
  if self.type_close then
    exit = self:type_close()
  end

  local payload = string.char(SSH_MSG_CHANNEL_CLOSE)
  payload = payload .. string.pack(">I4", self.id_server)
  
  return payload, exit
end


function CHANNEL:success()
  if self.type_success then
    return self:type_success()
  end
  
  return nil
end


function CHANNEL:failure()
  if self.type_failure then
    return self:type_failure()
  end
  
  return nil
end


return CHANNEL
