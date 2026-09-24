using Redis
import DataStructures: OrderedSet
using Random
using Dates
using Test
using Base

include("client_tests.jl")
include("redis_tests.jl")

client_tests()

# TCP connection
redis_tests(RedisConnection())

# TLS connection
const CERTS = joinpath(@__DIR__, "certs")
redis_tests(RedisConnection(;host="redisjltest", port=16379, sslconfig=TLSConfig(cacert=joinpath(CERTS, "ca.crt"))))

# TLS with a client certificate (the test server runs with `tls-auth-clients optional`,
# so any certificate signed by the test CA is accepted; the server's own will do).
@testset "TLS client certificate" begin
    tls_client = RedisConnection(;
        host="redisjltest", port=16379,
        sslconfig=TLSConfig(
            cacert=joinpath(CERTS, "ca.crt"),
            clientcert=joinpath(CERTS, "server.crt"),
            clientkey=joinpath(CERTS, "server.key"),
        ),
    )
    @test ping(tls_client) == "PONG"
    disconnect(tls_client)
    @test !is_connected(tls_client)
    @test_throws ArgumentError TLSConfig(clientcert=joinpath(CERTS, "server.crt"))
    @test_throws ArgumentError TLSConfig(cacert=joinpath(CERTS, "does-not-exist.crt"))
end

# Cluster connection
cluster = RedisClusterConnection(
    startup_nodes=[("127.0.0.1", 7000), ("127.0.0.1", 7001), ("127.0.0.1", 7002)]
)
redis_tests(cluster)
