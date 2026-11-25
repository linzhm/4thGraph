use std::env;
use std::fs;

use risc0_binfmt::ProgramBinary;
use risc0_zkos_v1compat::V1COMPAT_ELF;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let [guest_path, image_path]: [String; 2] = env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "usage: checkpoint-image GUEST_ELF IMAGE")?;
    let guest = fs::read(guest_path)?;
    let image = ProgramBinary::new(&guest, V1COMPAT_ELF);
    fs::write(image_path, image.encode())?;
    Ok(())
}
