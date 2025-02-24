package.loaded["channels.channel"] = nil
local CHANNEL = require("channels.channel")

package.loaded.ssh_tty = nil
local ssh_tty = require("ssh_tty")

local thread = require("thread")
local component = require("component")
local event = require("event")

local OPENED_CHANNEL = 0
local REQUESTED_PTY = 1
local REQUESTED_SHELL = 2
local REQUEST_DONE = 10

PTY = {}
PTY.__index = PTY

do
  
  function PTY.new(id, cur_window, sendSSHPacket)
    local obj = CHANNEL.new(id, cur_window, sendSSHPacket)
    obj.req_type = REQUEST_PTY_TYPE
    setmetatable(PTY, {__index = CHANNEL})
  
    obj.stage = OPENED_CHANNEL
    obj.tty_obj = nil
  
    setmetatable(obj, PTY)
    return obj
  end

  
  function PTY:type_confirm_open()
  
    if self.stage == OPENED_CHANNEL then
      
      local req_str = "pty-req"
      local term_env = "xterm-256color"    -- xterm-256color
  
      local resW, resH = component.gpu.getResolution()
  
      local payload = string.char(SSH_MSG_CHANNEL_REQUEST)
      payload = payload .. string.pack(">I4", self.id_server)
      payload = payload .. string.pack(">I4", #req_str) .. req_str
      payload = payload .. string.char(1)
      payload = payload .. string.pack(">I4", #term_env) .. term_env
      payload = payload .. string.pack(">I4", resW)
      payload = payload .. string.pack(">I4", resH)
      payload = payload .. string.pack(">I4", 0)
      payload = payload .. string.pack(">I4", 0)
      payload = payload .. string.pack(">I4", 0)
  
      self.stage = REQUESTED_PTY
  
      return payload
  
    end
  
  end
  
  
  function PTY:type_recv_data(data)
  
    if not self.tty_obj then
      error("no tty to print!")
    end

    self.tty_obj:write(data)
  
  end
  
  
  function PTY:type_success()
  
    if self.stage == REQUESTED_PTY then
      
      local req_str = "shell"
  
      local payload = string.char(SSH_MSG_CHANNEL_REQUEST)
      payload = payload .. string.pack(">I4", self.id_server)
      payload = payload .. string.pack(">I4", #req_str) .. req_str
      payload = payload .. string.char(1)
  
      self.stage = REQUESTED_SHELL
  
      return payload
  
    elseif self.stage == REQUESTED_SHELL then
      
      self.stage = REQUEST_DONE
      self.tty_obj = ssh_tty.open_tty(
        { processInput = function(_, data) self:send_data(data) end }
      )

      thread.create(function(handle_mouse_scroll)
        while true do
          handle_mouse_scroll(event.pull("scroll"))
        end
      end, self.tty_obj.handle_mouse_scroll)
  
      thread.create(function(handle_mouse_click)
        while true do
          handle_mouse_click(event.pull("touch"))
        end
      end, self.tty_obj.handle_mouse_click)

      thread.create(function(handle_mouse_release)
        while true do
          handle_mouse_release(event.pull("drop"))
        end
      end, self.tty_obj.handle_mouse_release)

      thread.create(function(handle_key_down)
        while true do
          handle_key_down(event.pull("key_down"))
        end
      end, self.tty_obj.handle_key_down)

      thread.create(function(handle_clipboard)
        local buffer = ""
        local kbd = nil
        while true do
          local status, tmp_kbd, str = event.pull(0.05, "clipboard")
          if tmp_kbd then
            kbd = tmp_kbd
          end
          if (not status) and #buffer > 0 then
            handle_clipboard(status, kbd, buffer)
            buffer = ""
          elseif status then
            buffer = buffer .. str
          end
        end
      end, self.tty_obj.handle_clipboard)
  
    end
  
  end


  -- Return value: exit ssh after closing?
  function PTY:type_close()
    
    if self.tty_obj then
      self.tty_obj.close_tty()
    end
    return true

  end
  
  
  function PTY:type_failure()
  
    error("pty allocation request failed on channel " .. self.id_client .. ".", 0)
  
  end
  

end

return PTY