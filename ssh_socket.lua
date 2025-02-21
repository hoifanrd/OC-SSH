local internet = require("internet")
local buffer = require("buffer")
local os = require("os")
local computer = require("computer")

SSH_Socket = {}
SSH_Socket.__index = SSH_Socket

do

  function SSH_Socket.new(host, port)
    local soc = internet.open(host, port)
    soc.read = override_read(soc.read)

    local obj = {}

    obj.start_no_recv = nil
    obj.host = host

    setmetatable(obj, {__index = soc})
    return obj
  end

  function override_read(ori_read)

    local function readChunk(self)
      local star = computer.uptime()
      local result, reason = self.stream:read(math.max(1, self.bufferSize))

      if result then
        --[[
        if #result > 0 then
          write_to_log("Receiving: \n")
          write_to_log(computer.uptime() - star)
          write_to_log("\n")
          write_to_log(tostring(#result))
          write_to_log("\n\n")
        end
        --]]
        self.bufferRead = self.bufferRead .. result
        return self
      else -- error or eof
        if reason then
          print("\nDisconnected from " .. self.host)
          os.exit()
        end
        return result
      end
    end


    local function read(self, arg, blocking)

      if blocking == nil then
        blocking = true
      end
    
      local data = ""
      if not blocking then
    
        assert( type(arg) == "number" )
      
        while true do
          local current_data_len = #data
          local needed = arg - current_data_len
          if needed == 0 then
            break
          end
          -- if the buffer is empty OR there is only 1 char left, read next chunk
          -- this is to protect that last byte from bad unicode
          if #self.bufferRead == 0 then
            local res = readChunk(self)
            if not res then    -- eof
              os.exit()
            end
          end
          local splice = self.bufferRead
          if #self.bufferRead > needed then
            splice = string.sub(self.bufferRead, 1, needed)
          end
    
          -- Added for non-blocking
          if #splice == 0 then
            if self.start_no_recv == nil then
              self.start_no_recv = computer.uptime()
            elseif computer.uptime() - self.start_no_recv > self.readTimeout then
              print("\nDisconnected from " .. self.host)
              os.exit()
            end
            self.bufferRead = data .. self.bufferRead
            data = ""
            break
          end
          
          self.start_no_recv = nil
          data = data .. splice
          self.bufferRead = string.sub(self.bufferRead, #splice + 1)
        
        end
    
      else
    
        local status
        status, data = pcall(ori_read, self, arg)
        if not status then
          print("\nDisconnected from " .. self.host)
          os.exit()
        end
    
      end

      return data
    
    end

    return read

  end
  

end


return SSH_Socket