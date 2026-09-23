"""
    Transport module for Redis.jl abstracts the connection to the Redis server.

Each transport implementation must provide the following methods:
- `read_line(t::RedisTransport)`: Read one line from the transport, similar to `readline`. Return a `String`.
- `read_nbytes(t::RedisTransport, m::Int)`: Read `m` bytes from the transport, similar to `read`. Return a `Vector{UInt8}`.
- `write_bytes(t::RedisTransport, b::Vector{UInt8})`: Write bytes to the transport, similar to `write`. Return the number of bytes written.
- `close(t::RedisTransport)`: Close the transport. Return `nothing`.
- `is_connected(t::RedisTransport)`: Whether the transport is connected or not. Return a boolean.
- `set_props!(t::RedisTransport)`: Set any properties required. For example, disable nagle and enable quickack to speed up the usually small exchanges. Return `nothing`.
- `get_sslconfig(t::RedisTransport)`: Get the SSL configuration for the transport if applicable. Return a `TLSConfig` or `nothing`.
- `io_lock(f, t::RedisTransport)`: Lock the transport for IO operations and execute `f`. Return the result of `f`.

"""
module Transport

using Sockets
using OpenSSL

import Sockets.connect, Sockets.TCPSocket, Base.StatusActive, Base.StatusOpen, Base.StatusPaused

abstract type RedisTransport end

include("tls.jl")
include("tcp.jl")

function transport(host::AbstractString, port::Integer, sslconfig::SSLConfigArg=nothing)
    socket = connect(host, port)
    (sslconfig === nothing) && return TCPTransport(socket)
    try
        return TLSTransport(host, socket, as_tlsconfig(sslconfig))
    catch
        close(socket)
        rethrow()
    end
end

end # module Transport