"""
    TLSConfig(; cacert=nothing, clientcert=nothing, clientkey=nothing, verify=true)
    TLSConfig(ctx::OpenSSL.SSLContext; verify=true)

TLS settings for a Redis connection. Pass an instance as the `sslconfig` keyword
argument of `RedisConnection`, `SentinelConnection` or `RedisClusterConnection`.

- `cacert`: path to a PEM file holding the CA certificates the server certificate
  is verified against. Defaults to OpenSSL.jl's default CA bundle.
- `clientcert`, `clientkey`: paths to a PEM client certificate (with any
  intermediate certificates after it) and private key, for servers that require
  client authentication (`tls-auth-clients yes`).
- `verify`: whether to verify the server certificate. When `true`, the server
  certificate must chain to `cacert` and, when the connection host is a
  hostname rather than an IP address, match that hostname.

The second form wraps an already configured `OpenSSL.SSLContext`. A bare
`OpenSSL.SSLContext` is also accepted wherever a `TLSConfig` is, with `verify=true`.
"""
struct TLSConfig
    ctx::OpenSSL.SSLContext
    verify::Bool
end

TLSConfig(ctx::OpenSSL.SSLContext; verify::Bool=true) = TLSConfig(ctx, verify)

function TLSConfig(;
    cacert::Union{Nothing,AbstractString}=nothing,
    clientcert::Union{Nothing,AbstractString}=nothing,
    clientkey::Union{Nothing,AbstractString}=nothing,
    verify::Bool=true,
)
    if (clientcert === nothing) != (clientkey === nothing)
        throw(ArgumentError("clientcert and clientkey must be given together"))
    end
    # OpenSSL reports a missing file as an opaque error (an `AssertionError` for
    # `cacert`), so check the paths up front.
    for (name, path) in (("cacert", cacert), ("clientcert", clientcert), ("clientkey", clientkey))
        (path === nothing) || isfile(path) || throw(ArgumentError("$name: no such file: $path"))
    end

    method = OpenSSL.TLSClientMethod()
    ctx = (cacert === nothing) ? OpenSSL.SSLContext(method) : OpenSSL.SSLContext(method, String(cacert))
    if clientcert !== nothing
        use_certificate_chain_file!(ctx, clientcert)
        OpenSSL.ssl_use_private_key(ctx, OpenSSL.EvpPKey(read(clientkey, String)))
    end
    return TLSConfig(ctx, verify)
end

# Load the client certificate together with any intermediate certificates that follow
# it in the file. `OpenSSL.ssl_use_certificate` takes a single parsed certificate, and
# `OpenSSL.X509Certificate(pem)` only parses the first one in `pem`, so a chain would be
# silently truncated to the leaf. Argument passing mirrors OpenSSL.jl's own ccalls.
function use_certificate_chain_file!(ctx::OpenSSL.SSLContext, certfile::AbstractString)
    ret = ccall(
        (:SSL_CTX_use_certificate_chain_file, OpenSSL.libssl),
        Cint,
        (OpenSSL.SSLContext, Cstring),
        ctx,
        String(certfile),
    )
    ret == 1 || throw(OpenSSL.OpenSSLError())
    return nothing
end

const SSLConfigArg = Union{Nothing,TLSConfig,OpenSSL.SSLContext}

as_tlsconfig(::Nothing) = nothing
as_tlsconfig(c::TLSConfig) = c
as_tlsconfig(ctx::OpenSSL.SSLContext) = TLSConfig(ctx)

# SNI and hostname verification only make sense for a DNS name (RFC 6066 forbids
# an IP literal in the server name). Only `ArgumentError` means "not an address".
function sni_hostname(host::AbstractString)
    return try
        parse(IPAddr, host)
        nothing
    catch ex
        ex isa ArgumentError || rethrow()
        String(host)
    end
end

struct TLSTransport <: RedisTransport
    sock::TCPSocket
    ssl::OpenSSL.SSLStream
    sslconfig::TLSConfig
    # Decrypted bytes received but not yet consumed by `read_line` / `read_nbytes`.
    buff::IOBuffer
    # Number of unread newlines in `buff`, so `read_line` knows when a full line is
    # buffered without inspecting the IOBuffer's internals.
    newlines::Base.RefValue{Int}
    lock::ReentrantLock

    function TLSTransport(host::AbstractString, sock::TCPSocket, sslconfig::TLSConfig)
        ssl = OpenSSL.SSLStream(sslconfig.ctx, sock)
        try
            hostname = sni_hostname(host)
            (hostname === nothing) || OpenSSL.hostname!(ssl, hostname)
            connect(ssl; require_ssl_verification=sslconfig.verify)
        catch
            close(ssl)
            rethrow()
        end
        return new(sock, ssl, sslconfig, PipeBuffer(), Ref(0), ReentrantLock())
    end
end

# Pull decrypted bytes into `buff` until `cond` holds. `eof` blocks until at least one
# decrypted byte is available (or the peer is gone), and `readavailable` then returns
# what has been decrypted so far, so a short reply is never held up waiting for bytes
# that belong to the next one.
#
# Reaching EOF with `cond` unmet means the peer went away mid-reply. That has to
# throw, otherwise `read_line` would return a partial line and `read_nbytes` fewer
# bytes than asked for.
function read_into_buffer_until(cond::Function, t::TLSTransport)
    while !cond(t)
        eof(t.ssl) && break
        chunk = readavailable(t.ssl)
        isempty(chunk) && break
        t.newlines[] += count(==(UInt8('\n')), chunk)
        write(t.buff, chunk)
    end
    cond(t) || throw(EOFError())
    return nothing
end

function read_line(t::TLSTransport)
    read_into_buffer_until(t -> t.newlines[] > 0, t)
    line = readline(t.buff)
    t.newlines[] -= 1
    return line
end
function read_nbytes(t::TLSTransport, m::Int)
    read_into_buffer_until(t -> bytesavailable(t.buff) >= m, t)
    bytes = read(t.buff, m)
    t.newlines[] -= count(==(UInt8('\n')), bytes)
    return bytes
end
write_bytes(t::TLSTransport, b::Vector{UInt8}) = write(t.ssl, b)
# `close(::SSLStream)` sends close_notify and closes the socket, but does the latter
# asynchronously in OpenSSL.jl >= 1.5. Closing the socket here as well makes
# `disconnect` synchronous, so `is_connected` and the socket's fd reflect it at once.
function Base.close(t::TLSTransport)
    close(t.ssl)
    close(t.sock)
    return nothing
end
function set_props!(t::TLSTransport)
    # disable nagle and enable quickack to speed up the usually small exchanges
    Sockets.nagle(t.sock, false)
    Sockets.quickack(t.sock, true)
end
get_sslconfig(t::TLSTransport) = t.sslconfig
io_lock(f, t::TLSTransport) = lock(f, t.lock)
function is_connected(t::TLSTransport)
    # `isopen(t.ssl)` turns false on a local `close`, and once OpenSSL.jl has processed a
    # close_notify from the peer (it closes the stream on SSL_ERROR_ZERO_RETURN). A peer
    # that only dropped the TCP connection shows up in the socket status below, exactly
    # as for `TCPTransport`.
    isopen(t.ssl) || return false
    status = t.sock.status
    status == StatusActive || status == StatusOpen || status == StatusPaused
end
