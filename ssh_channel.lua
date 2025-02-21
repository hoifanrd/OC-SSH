package.loaded["channels.pty"] = nil
local PTY = require("channels.pty")

local TTY = require("channels.tty")
local COMMAND = require("channels.command")

SSH_Channel = {}

function SSH_Channel.new_channel(req_type, ...)

  if req_type == REQUEST_PTY_TYPE then
    return PTY.new(...)
  elseif req_type == REQUEST_TTY_TYPE then
    return TTY.new(...)
  elseif req_type == REQUEST_COMMAND_TYPE then
    return COMMAND.new(...)
  end

end

return SSH_Channel