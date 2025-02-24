--- The SHA256 cryptographic hash function.
--- From ccryptolib

local bit32 = require("bit32")
local str_xor = require "cryptolib.internal.util".str_xor
local packing = require "cryptolib.internal.packing"

local rol = bit32.lrotate
local shr = bit32.rshift
local bxor = bit32.bxor
local bnot = bit32.bnot
local band = bit32.band
local unpack = unpack or table.unpack
local p1x8, fmt1x8 = packing.compilePack(">I8")
local p16x4, fmt16x4 = packing.compilePack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")
local u16x4 = packing.compileUnpack(fmt16x4)
local p8x4, fmt8x4 = packing.compilePack(">I4I4I4I4I4I4I4I4")
local u8x4 = packing.compileUnpack(fmt8x4)

local function primes(n, exp)
    local out = {}
    local p = 2
    for i = 1, n do
        out[i] = math.floor((p ^ exp % 1) * 2 ^ 32)
        repeat p = p + 1 until 2 ^ p % p == 2
    end
    return out
end

local K = primes(64, 1 / 3)

local h0 = primes(8, 1 / 2)

local function compress(h, w)
    local h0, h1, h2, h3, h4, h5, h6, h7 = unpack(h)
    local K = K

    -- Message schedule.
    for j = 17, 64 do
        local wf = w[j - 15]
        local w2 = w[j - 2]
        local s0 = bxor(rol(wf, 25), rol(wf, 14), shr(wf, 3))
        local s1 = bxor(rol(w2, 15), rol(w2, 13), shr(w2, 10))
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % 2 ^ 32
    end

    -- Block.
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for j = 1, 64 do
        local s1 = bxor(rol(e, 26), rol(e, 21), rol(e, 7))
        local ch = bxor(band(e, f), band(bnot(e), g))
        local temp1 = h + s1 + ch + K[j] + w[j]
        local s0 = bxor(rol(a, 30), rol(a, 19), rol(a, 10))
        local maj = bxor(band(a, b), band(a, c), band(b, c))
        local temp2 = s0 + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2
    end

    return {
        (h0 + a) % 2 ^ 32,
        (h1 + b) % 2 ^ 32,
        (h2 + c) % 2 ^ 32,
        (h3 + d) % 2 ^ 32,
        (h4 + e) % 2 ^ 32,
        (h5 + f) % 2 ^ 32,
        (h6 + g) % 2 ^ 32,
        (h7 + h) % 2 ^ 32,
    }
end

--- Hashes data using SHA256.
--- @param data string Input bytes.
--- @return string hash The 32-byte hash value.
local function digest(data)

    -- Pad input.
    local bitlen = #data * 8
    local padlen = -(#data + 9) % 64
    data = data .. "\x80" .. ("\0"):rep(padlen) .. p1x8(fmt1x8, bitlen)

    -- Digest.
    local h = h0
    for i = 1, #data, 64 do
        h = compress(h, {u16x4(fmt16x4, data, i)})
    end

    return p8x4(fmt8x4, unpack(h))
end

-- HMAC
local b_size = 64

local function hmac(data, key)
    if #key > b_size then
        key = digest(key)
    end

    if #key < b_size then
        key = key .. string.rep("\0", b_size - #key)
    end

    local o_key_pad = str_xor(key, string.rep("\x5c", b_size))
    local i_key_pad = str_xor(key, string.rep("\x36", b_size))

    return digest(o_key_pad .. digest(i_key_pad .. data))

end

return {
    digest = digest,
    hmac = hmac
}