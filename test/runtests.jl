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
redis_tests(RedisConnection(;host="redisjltest", port=16379, sslconfig=TLSConfig(cacert=joinpath(@__DIR__, "certs", "ca.crt"))))

# Cluster connection
cluster = RedisClusterConnection(
    startup_nodes=[("127.0.0.1", 7000), ("127.0.0.1", 7001), ("127.0.0.1", 7002)]
)
redis_tests(cluster)
