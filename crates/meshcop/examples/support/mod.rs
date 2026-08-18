use meshcop::dataset::{
    Dataset, TLV_EXTENDED_PAN_ID, TLV_MESH_LOCAL_PREFIX, TLV_NETWORK_KEY, TLV_PSKC,
};

mod args;
pub use args::show_secrets_requested;

pub fn print_dataset_summary(
    label: &str,
    dataset: &Dataset,
    show_secrets: bool,
) -> meshcop::Result<()> {
    println!("{label}_encoded_len={}", dataset.to_bytes()?.len());
    for entry in dataset.entries() {
        let value = if show_secrets || !is_sensitive_tlv(entry.ty) {
            hex::encode(&entry.value)
        } else {
            "<redacted>".to_string()
        };
        println!(
            "{label}_tlv type=0x{:02x} len={} value={}",
            entry.ty,
            entry.value.len(),
            value
        );
    }

    if let Some(name) = dataset.network_name()? {
        println!("{label}_network_name={name}");
    }
    if let Some(channel) = dataset.channel()? {
        println!(
            "{label}_channel_page={} {label}_channel={}",
            channel.page, channel.channel
        );
    }
    if let Some(pan_id) = dataset.pan_id()? {
        println!("{label}_pan_id=0x{pan_id:04x}");
    }
    Ok(())
}

fn is_sensitive_tlv(ty: u8) -> bool {
    matches!(
        ty,
        TLV_PSKC | TLV_NETWORK_KEY | TLV_MESH_LOCAL_PREFIX | TLV_EXTENDED_PAN_ID
    )
}
