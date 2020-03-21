cc_library(
    name = "roughtime_logging",
    hdrs = ["logging.h"],
    deps = ["@com_google_protobuf//:protobuf"],
)

cc_library(
    name = "protocol",
    srcs = ["protocol.cc"],
    hdrs = ["protocol.h"],
    deps = [
        ":roughtime_logging",
        "@boringssl//:crypto",
    ],
)

cc_test(
    name = "protocol_test",
    srcs = ["protocol_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":protocol",
        "@gtest//:main",
    ],
)

cc_library(
    name = "client",
    srcs = ["client.cc"],
    hdrs = ["client.h"],
    deps = [
        ":protocol",
        ":roughtime_logging",
    ],
)

cc_test(
    name = "client_test",
    srcs = ["client_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":client",
        ":open_source_fillins",
        "@gtest//:main",
    ],
)

cc_library(
    name = "time_source",
    hdrs = ["time_source.h"],
    deps = [":protocol"],
)

cc_library(
    name = "server",
    srcs = ["server.cc"],
    hdrs = ["server.h"],
    deps = [
        ":protocol",
        ":time_source",
        ":roughtime_logging",
        "@boringssl//:crypto",
    ],
)

cc_proto_library(
    name = "config_cc_proto",
    deps = [":config_proto"],
)

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
)

cc_binary(
    name = "simple_client",
    srcs = [
        "clock_linux.cc",
        "clock_macos.cc",
        "simple_client.cc",
    ],
    deps = [
        ":client",
        ":config_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "simple_server_lib",
    srcs = ["simple_server.cc"],
    hdrs = ["simple_server.h"],
    deps = [
        ":server",
        ":sys_time",
        ":udp_processor",
    ],
)

cc_binary(
    name = "simple_server",
    srcs = ["simple_server_main.cc"],
    deps = [":simple_server_lib"],
)

cc_library(
    name = "open_source_fillins",
    hdrs = ["open_source_fillins.h"],
    deps = [":roughtime_logging"],
    defines = ["ROUGHTIME_OPEN_SOURCE"],
)

cc_test(
    name = "server_test",
    srcs = ["server_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":open_source_fillins",
        ":server",
        "@boringssl//:crypto",
        "@gtest//:main",
    ],
)

cc_library(
    name = "udp_processor",
    srcs = ["udp_processor.cc"],
    hdrs = ["udp_processor.h"],
    deps = [
        ":open_source_fillins",
        ":protocol",
        ":server",
        ":time_source",
        ":roughtime_logging",
    ],
)

cc_library(
    name = "sys_time",
    srcs = ["sys_time.cc"],
    hdrs = ["sys_time.h"],
    deps = [
        ":time_source",
        ":roughtime_logging",
    ],
)
