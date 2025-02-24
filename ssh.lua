local os = require("os")
local shell = require("shell")
local text = require("text")
local filesystem = require("filesystem")

package.loaded.ssh_transport = nil
local SSH_Transport = require("ssh_transport")

local args, options = shell.parse(...)
local debug = options.v

if #args < 1 then
  io.write("Usage: ssh <host> [port]")
  return
end

local user_host = text.trim(args[1])
local tab_list = {}
for word in string.gmatch(user_host, '([^@]+)') do
  table.insert(tab_list, word)
end

local username = table.concat(tab_list, "@", 1, #tab_list - 1)
local host = tab_list[#tab_list]

local port = 22
if #args > 1 then
  port = tonumber(args[2])
end

if not filesystem.exists(SSH_BASE_FOLDER) then
  local res, error = filesystem.makeDirectory(SSH_BASE_FOLDER)
  if not res then
    print("Cannot create folder " .. SSH_BASE_FOLDER .. "!")
    print(error)
    os.exit()
  end

end

local ssh_tran = SSH_Transport.new(host, port, username, debug)

ssh_tran:protoEx()

while true do
  
  local status, res = pcall(ssh_tran.processPacket, ssh_tran)
  if not status then
    ssh_tran:terminate(res)
  end
  
  local status = pcall(os.sleep, 0.02)
  if not status then
    ssh_tran:terminate("Connection to " .. host .. " closed.")
  end
end

