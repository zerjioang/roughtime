workspace(name = "roughtime")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "boringssl",
    commit = "e534d74f5732e1aeebd514f05271d089c530c2f9", # April 11th, 2019.
    remote = "https://boringssl.googlesource.com/boringssl",
)

git_repository(
    name = "com_google_protobuf",
    commit = "v3.7.1",
    remote = "https://github.com/protocolbuffers/protobuf",
)

# protobuf requires bazel-skylib and zlib.

# bazel-skylib 0.8.0 released 2019.03.20 (https://github.com/bazelbuild/bazel-skylib/releases/tag/0.8.0)
skylib_version = "0.8.0"
http_archive(
    name = "bazel_skylib",
    type = "tar.gz",
    url = "https://github.com/bazelbuild/bazel-skylib/releases/download/{}/bazel-skylib.{}.tar.gz".format (skylib_version, skylib_version),
    sha256 = "2ef429f5d7ce7111263289644d233707dba35e39696377ebab8b0bc701f7818e",
)

bind(
    name = "zlib",
    actual = "@net_zlib//:zlib",
)
http_archive(
    name = "net_zlib",
    build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
    strip_prefix = "zlib-1.2.11",
    urls = ["https://zlib.net/zlib-1.2.11.tar.gz"],
)

http_archive(
    name = "gtest",
    url = "https://github.com/google/googletest/archive/release-1.7.0.tar.gz",
    sha256 = "f73a6546fdf9fce9ff93a5015e0333a8af3062a152a9ad6bcb772c96687016cc",
    build_file = "@//:gtest.BUILD",
    strip_prefix = "googletest-release-1.7.0",
)
