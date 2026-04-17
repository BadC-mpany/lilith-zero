// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// A parsed Windows PE (Portable Executable) file.
pub struct PeFile {
    /// The open file handle.
    pub file: File,
    /// The preferred load address declared in the PE optional header.
    pub image_base: u64,
    /// The section table entries.
    pub sections: Vec<Section>,
    /// `true` for PE32+ (64-bit), `false` for PE32 (32-bit).
    pub is_64bit: bool,
}

/// A single section entry from the PE section table.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (up to 8 bytes, null-padded).
    pub name: String,
    /// Virtual address of the section relative to the image base.
    pub virtual_address: u32,
    /// Size of the section in virtual memory.
    pub virtual_size: u32,
    /// File offset of the raw section data.
    pub raw_data_ptr: u32,
    /// Size of the raw section data on disk.
    pub raw_data_size: u32,
}

impl PeFile {
    /// Open and parse the PE headers of the file at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = [0u8; 1024];
        file.read_exact(&mut buffer)
            .context("Failed to read header")?;

        if buffer[0] != b'M' || buffer[1] != b'Z' {
            return Err(anyhow!("Missing MZ signature"));
        }

        let pe_offset = u32::from_le_bytes(
            buffer
                .get(0x3C..0x40)
                .context("Buffer too small for PE offset")?
                .try_into()?,
        ) as u64;
        file.seek(SeekFrom::Start(pe_offset))?;

        let mut pe_sig = [0u8; 4];
        file.read_exact(&mut pe_sig)
            .context("Failed to read PE signature")?;
        if pe_sig != [b'P', b'E', 0, 0] {
            return Err(anyhow!("Missing PE signature"));
        }

        let mut image_header = [0u8; 20];
        file.read_exact(&mut image_header)
            .context("Failed to read image header")?;

        let num_sections = u16::from_le_bytes(image_header[2..4].try_into()?);
        let optional_header_size = u16::from_le_bytes(image_header[16..18].try_into()?);

        let mut optional_header = vec![0u8; optional_header_size as usize];
        file.read_exact(&mut optional_header)
            .context("Failed to read optional header")?;

        if optional_header.len() < 2 {
            return Err(anyhow!("Optional header too small"));
        }
        let magic = u16::from_le_bytes(optional_header[0..2].try_into()?);
        let (is_64bit, image_base) = match magic {
            0x20B => {
                if optional_header.len() < 32 {
                    return Err(anyhow!("PE64 optional header too small"));
                }
                (
                    true,
                    u64::from_le_bytes(optional_header[24..32].try_into()?),
                )
            }
            0x10B => {
                if optional_header.len() < 32 {
                    return Err(anyhow!("PE32 optional header too small"));
                }
                (
                    false,
                    u32::from_le_bytes(optional_header[28..32].try_into()?) as u64,
                )
            }
            _ => return Err(anyhow!("Unknown PE magic: {:#X}", magic)),
        };

        let mut sections = Vec::new();
        file.seek(SeekFrom::Start(
            pe_offset + 4 + 20 + optional_header_size as u64,
        ))?;

        for _ in 0..num_sections {
            let mut s_buf = [0u8; 40];
            file.read_exact(&mut s_buf)?;

            let name = String::from_utf8_lossy(&s_buf[0..8])
                .trim_matches(char::from(0))
                .to_string();

            sections.push(Section {
                name,
                virtual_size: u32::from_le_bytes(s_buf[8..12].try_into()?),
                virtual_address: u32::from_le_bytes(s_buf[12..16].try_into()?),
                raw_data_size: u32::from_le_bytes(s_buf[16..20].try_into()?),
                raw_data_ptr: u32::from_le_bytes(s_buf[20..24].try_into()?),
            });
        }

        Ok(PeFile {
            file,
            image_base,
            sections,
            is_64bit,
        })
    }
}

/// Convert a relative virtual address (RVA) to a file offset using the section table.
///
/// Returns `None` if no section contains the given RVA.
pub fn rva_to_offset(sections: &[Section], rva: u32) -> Option<u64> {
    for s in sections {
        if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
            return Some((rva - s.virtual_address) as u64 + s.raw_data_ptr as u64);
        }
    }
    None
}

/// Return the list of DLL names declared in the import and delay-import tables of `path`.
pub fn get_dependencies<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let mut pe = PeFile::open(path)?;
    let mut deps = Vec::new();

    if let Ok(import_deps) = extract_deps_from_dir(&mut pe.file, pe.is_64bit, &pe.sections, 1) {
        deps.extend(import_deps);
    }

    if let Ok(delay_deps) = extract_deps_from_dir(&mut pe.file, pe.is_64bit, &pe.sections, 13) {
        for d in delay_deps {
            if !deps.contains(&d) {
                deps.push(d);
            }
        }
    }

    Ok(deps)
}

fn extract_deps_from_dir(
    file: &mut File,
    is_64bit: bool,
    sections: &[Section],
    dir_index: usize,
) -> Result<Vec<String>> {
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = [0u8; 1024];
    file.read_exact(&mut buffer)?;

    let pe_offset = u32::from_le_bytes(
        buffer
            .get(0x3C..0x40)
            .context("Buffer too small")?
            .try_into()?,
    ) as u64;
    let opt_header_start = pe_offset + 4 + 20;
    let dd_start = if is_64bit {
        opt_header_start + 112
    } else {
        opt_header_start + 96
    };
    let dir_entry_off = dd_start + (dir_index as u64 * 8);

    file.seek(SeekFrom::Start(dir_entry_off))?;
    let mut dir_entry = [0u8; 8];
    file.read_exact(&mut dir_entry)?;

    let rva = u32::from_le_bytes(dir_entry[0..4].try_into()?);
    let size = u32::from_le_bytes(dir_entry[4..8].try_into()?);

    if rva == 0 || size == 0 {
        return Ok(vec![]);
    }

    let offset = rva_to_offset(sections, rva)
        .ok_or_else(|| anyhow!("Failed to map DataDirectory[{}] RVA {:#X}", dir_index, rva))?;

    file.seek(SeekFrom::Start(offset))?;
    let mut deps = Vec::new();

    if dir_index == 1 {
        loop {
            let mut desc = [0u8; 20];
            if file.read(&mut desc)? < 20 {
                break;
            }

            let name_rva = u32::from_le_bytes(desc[12..16].try_into()?);
            if name_rva == 0 {
                break;
            }

            let saved_pos = file.stream_position()?;
            if let Some(name_off) = rva_to_offset(sections, name_rva) {
                if let Ok(name) = read_null_terminated_string(file, name_off) {
                    deps.push(name);
                }
            }
            file.seek(SeekFrom::Start(saved_pos))?;
        }
    } else if dir_index == 13 {
        loop {
            let mut desc = [0u8; 32];
            if file.read(&mut desc)? < 32 {
                break;
            }

            let name_rva = u32::from_le_bytes(desc[4..8].try_into()?);
            if name_rva == 0 {
                break;
            }

            let saved_pos = file.stream_position()?;
            if let Some(name_off) = rva_to_offset(sections, name_rva) {
                if let Ok(name) = read_null_terminated_string(file, name_off) {
                    deps.push(name);
                }
            }
            file.seek(SeekFrom::Start(saved_pos))?;
        }
    }

    Ok(deps)
}

fn read_null_terminated_string(file: &mut File, offset: u64) -> Result<String> {
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if file.read(&mut b)? == 0 {
            break;
        }
        if b[0] == 0 {
            break;
        }
        bytes.push(b[0]);
        if bytes.len() > 256 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}
