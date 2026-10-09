fn main() {
    println!("cargo:rerun-if-changed=assets/netplus.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    winresource::WindowsResource::new()
        .set_icon("assets/netplus.ico")
        .set("ProductName", "netplus")
        .set("FileDescription", "Process Traffic Forwarder")
        .set("LegalCopyright", "Copyright (c) netplus contributors")
        .compile()
        .expect("failed to compile Windows resources");
}
