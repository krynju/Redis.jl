"""
    TLSConfig(; cacert=nothing, clientcert=nothing, clientkey=nothing, verify=true)
    TLSConfig(ctx::OpenSSL.SSLContext; verify=true)

TLS settings for a Redis connection. Pass an instance as the `sslconfig` keyword
argument of `RedisConnection`, `SentinelConnection` or `RedisClusterConnection`.

- `cacert`: path to a PEM file, or a directory of PEM files, holding the CA
  certificates the server certificate is verified against. Defaults to the
  system CA roots (see `NetworkOptions.ca_roots`).
- `clientcert`, `clientkey`: paths to a PEM client certificate and private key,
  for servers that require client authentication (`tls-auth-clients yes`).
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
    method = OpenSSL.TLSClientMethod()
    ctx = (cacert === nothing) ? OpenSSL.SSLContext(method) : OpenSSL.SSLContext(method, String(cacert))
    if (clientcert === nothing) != (clientkey === nothing)
        throw(ArgumentError("clientcert and clientkey must be given together"))
    end
    if clientcert !== nothing
        OpenSSL.ssl_use_certificate(ctx, OpenSSL.X509Certificate(read(clientcert, String)))
        OpenSSL.ssl_use_private_key(ctx, OpenSSL.EvpPKey(read(clientkey, String)))
    end
    return TLSConfig(ctx, verify)
end

const SSLConfigArg = Union{Nothing,TLSConfig,OpenSSL.SSLContext}

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

TLSTransport(host::AbstractString, sock::TCPSocket, ctx::OpenSSL.SSLContext) =
    TLSTransport(host, sock, TLSConfig(ctx))

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
Base.close(t::TLSTransport) = close(t.ssl)
function set_props!(t::TLSTransport)
    # disable nagle and enable quickack to speed up the usually small exchanges
    Sockets.nagle(t.sock, false)
    Sockets.quickack(t.sock, true)
end
get_sslconfig(t::TLSTransport) = t.sslconfig
io_lock(f, t::TLSTransport) = lock(f, t.lock)
function is_connected(t::TLSTransport)
    isopen(t.ssl) || return false
    status = t.sock.status
    status == StatusActive || status == StatusOpen || status == StatusPaused
end
