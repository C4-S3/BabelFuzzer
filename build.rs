fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use vendored protoc from protobuf-src
    std::env::set_var("PROTOC", protobuf_src::protoc());

    tonic_prost_build::configure()
        .compile_protos(&["protos/echo.proto"], &["protos"])?;
    Ok(())
}
