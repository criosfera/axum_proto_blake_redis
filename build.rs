fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["src/auth.proto"], &["src/"])?;
    Ok(())
}