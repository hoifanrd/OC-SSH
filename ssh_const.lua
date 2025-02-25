SSH_IDENTIFY_STRING = "SSH-2.0-openosSSH_1.0.0"
PACKET_PADDING_LEN = 32

OPENOS_SSH_SUPPORRTED_ALGO = {
{"ecdh-sha2-nistp256"},
{"ecdsa-sha2-nistp256"},
{"aes128-ctr"},
{"aes128-ctr"},
{"hmac-sha2-256"},
{"hmac-sha2-256"},
{"none"},
{"none"},
{},
{}}

-- TODO? Support for "publickey" - More security concerns
-- OPENOS_SSH_AUTH_SUPPORTED = { "publickey", "password" }
OPENOS_SSH_AUTH_SUPPORTED = { "password" }


REQUEST_PTY_TYPE = 100
REQUEST_TTY_TYPE = 101
REQUEST_COMMAND_TYPE = 102

SSH_MSG_DISCONNECT = 1
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6

SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31

SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_BANNER = 53

SSH_MSG_GLOBAL_REQUEST = 80
SSH_MSG_REQUEST_FAILURE = 82
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_OPEN_FAILURE = 92
SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
SSH_MSG_CHANNEL_DATA = 94

SSH_MSG_CHANNEL_EOF = 96
SSH_MSG_CHANNEL_CLOSE = 97
SSH_MSG_CHANNEL_REQUEST = 98
SSH_MSG_CHANNEL_SUCCESS = 99
SSH_MSG_CHANNEL_FAILURE = 100


SSH_ERR_SIGNAL_INVALID_HMAC = 1
