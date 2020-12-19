use std::io::prelude::*;
use clap::{App, Arg};
use std::path::{Path, PathBuf};
use std::convert::TryInto;
use widestring::U16String;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use anyhow::{bail, Result, Context};
use std::fs::{OpenOptions, File};
use std::io::{SeekFrom, BufReader};
use num_traits::FromPrimitive;

#[derive(Debug)]
struct Header {
    signature: u32,
    magic2: u16,
    version: u16,
    streams_count: u32,
    streams_offset: u32,
    checksum: u32,
    timestamp: u32,
    flags: u64,
}

impl Header {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Header {
            signature: reader.read_u32::<LittleEndian>()?,
            magic2: reader.read_u16::<LittleEndian>()?,
            version: reader.read_u16::<LittleEndian>()?,
            streams_count: reader.read_u32::<LittleEndian>()?,
            streams_offset: reader.read_u32::<LittleEndian>()?,
            checksum: reader.read_u32::<LittleEndian>()?,
            timestamp: reader.read_u32::<LittleEndian>()?,
            flags: reader.read_u64::<LittleEndian>()?,
        })
    }
}

#[derive(num_derive::FromPrimitive, Debug)]
enum KnownStreamType {
    Unused,
    Reserved0,
    Reserved1,
    ThreadListStream,
    ModuleListStream,
    MemoryListStream,
    ExceptionStream,
    SystemInfoStream,
    ThreadExListStream,
    Memory64ListStream,
    CommentStreamA,
    CommentStreamW,
    HandleDataStream,
    FunctionTableStream,
    UnloadedModuleListStream,
    MiscInfoStream,
    MemoryInfoListStream,
    ThreadInfoListStream,
    HandleOperationListStream,
    TokenStream,
    JavaScriptDataStream,
    SystemMemroyInfoStream,
    ProcessVmCounterStream,
    IptTraceStream,
    ThreadNameStream,
    CeStreamNull,
    CeStreamSystemInfo,
    CeStreamException,
    CeStreamModuleList,
    CeStreamProcessList,
    CeStreamThreadList,
    CeStreamThreadContextList,
    CeStreamThreadCallStackList,
    CeStreamMemoryVirtualList,
    CeStreamMemroyPhysicalList,
    CeStreamBucketParameters,
    CeStreamProcessModuleMap,
    CeStreamDiagnosisList,
    LastReservedStream,
}

#[derive(Debug)]
enum StreamType {
    Known(KnownStreamType),
    Unknown(u32),
}

#[derive(Debug)]
struct StreamHeader {
    ty: StreamType,
    data_len: u32,
    data_offset: u32,
}

impl StreamHeader {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        let ty = reader.read_u32::<LittleEndian>()?;
        let data_len = reader.read_u32::<LittleEndian>()?;
        let data_offset = reader.read_u32::<LittleEndian>()?;

        let ty = KnownStreamType::from_u32(ty)
            .map(StreamType::Known)
            .unwrap_or_else(|| StreamType::Unknown(ty));

        Ok(StreamHeader {
            ty,
            data_len,
            data_offset,
        })
    }
}

#[derive(Debug)]
struct ThreadListStream {
    threads: Vec<ThreadListThread>,
}

impl ThreadListStream {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        let thread_count =reader.read_u32::<LittleEndian>()?;
        let threads = (0..thread_count).into_iter().map(|_| ThreadListThread::read(reader)).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { threads
        })
    }
}

#[derive(Debug)]
struct ThreadListThread {
    thread_id: u32,
    suspend_count: u32,
    priority_class: u32,
    priority: u32,
    teb: u64,
    stack: MemoryDescriptor,
    context: LocationDescriptor,
}

impl ThreadListThread {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            thread_id: reader.read_u32::<LittleEndian>()?,
            suspend_count: reader.read_u32::<LittleEndian>()?,
            priority_class: reader.read_u32::<LittleEndian>()?,
            priority: reader.read_u32::<LittleEndian>()?,
            teb: reader.read_u64::<LittleEndian>()?,
            stack: MemoryDescriptor::read(reader)?,
            context: LocationDescriptor::read(reader)?,
        })
    }
}

#[derive(Debug)]
struct MemoryDescriptor {
    addr_memory_range: u64,
    memory: LocationDescriptor,
}

impl MemoryDescriptor {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            addr_memory_range: reader.read_u64::<LittleEndian>()?,
            memory: LocationDescriptor::read(reader)?,
        })
    }
}

#[derive(Debug)]
struct LocationDescriptor {
    data_len: u32,
    data_offset: u32,
}

impl LocationDescriptor {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            data_len: reader.read_u32::<LittleEndian>()?,
            data_offset: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct FunctionTableStream {
    header_size: u32,
    descriptor_size: u32,
    native_descriptor_size: u32,
    function_entry_size: u32,
    descriptor_count: u32,
    align_pad_size: u32,
}


impl FunctionTableStream {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            header_size: reader.read_u32::<LittleEndian>()?,
            descriptor_size: reader.read_u32::<LittleEndian>()?,
            native_descriptor_size: reader.read_u32::<LittleEndian>()?,
            function_entry_size: reader.read_u32::<LittleEndian>()?,
            descriptor_count: reader.read_u32::<LittleEndian>()?,
            align_pad_size: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct FunctionTableDescriptor {
    minimum_address: u64,
    maximum_address: u64,
    base_address: u64,
    entry_count: u32,
    align_pad: u32,
}

impl FunctionTableDescriptor {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            minimum_address: reader.read_u64::<LittleEndian>()?,
            maximum_address: reader.read_u64::<LittleEndian>()?,
            base_address: reader.read_u64::<LittleEndian>()?,
            entry_count: reader.read_u32::<LittleEndian>()?,
            align_pad: reader.read_u32::<LittleEndian>()?,
        })
    }
}

struct ModuleList {
    modules: Vec<Module>,
}

impl ModuleList {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        let modules_count = reader.read_u32::<LittleEndian>()?;
        let modules = (0..modules_count).into_iter().map(|_| Module::read(reader)).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { modules
        })
    }
}

#[derive(Debug)]
struct Module {
    image_base: u64,
    image_len: u32,
    checksum: u32,
    timestamp: u32,
    module_name_offset: u32,
    file_info: FixedFileInfo,
    cv_record: LocationDescriptor,
    misc_record: LocationDescriptor,
    reserved0: u64,
    reserved1: u64,
}

impl Module {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            image_base: reader.read_u64::<LittleEndian>()?,
            image_len: reader.read_u32::<LittleEndian>()?,
            checksum: reader.read_u32::<LittleEndian>()?,
            timestamp: reader.read_u32::<LittleEndian>()?,
            module_name_offset: reader.read_u32::<LittleEndian>()?,
            file_info: FixedFileInfo::read(reader)?,
            cv_record: LocationDescriptor::read(reader)?,
            misc_record: LocationDescriptor::read(reader)?,
            reserved0: reader.read_u64::<LittleEndian>()?,
            reserved1: reader.read_u64::<LittleEndian>()?,
        })
    }
}

struct MdString(U16String);

impl MdString {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        let len = reader.read_u32::<LittleEndian>()?;
        if (len % 2) == 1 {
            bail!("Odd number of bytes in UTF16 string data");
        }

        let mut buffer = Vec::new();
        buffer.resize(len as usize / 2, 0u16);
        reader.read_u16_into::<LittleEndian>(&mut buffer)?;

        Ok(MdString(U16String::from_vec(buffer)))
    }
}

#[derive(Debug)]
struct Memory64List {
    memory_data_start: u64,
    ranges: Vec<Memory64Descriptor>,
}

impl Memory64List {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        let range_count = reader.read_u64::<LittleEndian>()?;
        let memory_data_start = reader.read_u64::<LittleEndian>()?;
        let mut memory_start = memory_data_start;
        let mut ranges = (0..range_count).into_iter().map(|_| {
            let descriptor = Memory64Descriptor::read(reader, memory_start)?;
            memory_start += descriptor.memory_size;
            Ok(descriptor)
        }).collect::<Result<Vec<_>, anyhow::Error>>()?;
        ranges.push(Memory64Descriptor {
            data_offset: memory_data_start,
            memory_base_address: 0,
            memory_size: 0
        });
        ranges.sort_by_key(|f| f.memory_base_address);
        Ok(Self {
            memory_data_start,
            ranges,
        })
    }

    fn read_memory(&self, reader: &mut dyn Read, addr: u64, length: u64) -> bytes::BytesMut {
        let buffer = bytes::BytesMut::with_capacity(length as _);

        let start = self.ranges.binary_search_by_key(&addr, |m| m.memory_base_address);
        let segment = match start {
            Ok(s) => s,
            Err(u) => u-1,
        };

        buffer
    }

    fn write_image<R, W>(&self, reader: &mut R, start: u64, len: u64, writer: &mut W) -> Result<()>
    where R: Read + Seek, W: Write
    {
        let mut written = 0;
        while written < len {
            let remaining = len - written;
            let tail = start + written;

            // Get the next memory segment.
            let mut next = None;
            for r in &self.ranges {
                let start = r.memory_base_address;
                let end = start + r.memory_size;
                if start <= tail && tail < end {
                    next = Some(r);
                    break;
                }
            }

            let next = next.context(format!("Memory not included in the minidump: {} + {} bytes", tail, remaining)
                )?;
            let tail_offset = tail - next.memory_base_address;
            reader.seek(SeekFrom::Start(next.data_offset + tail_offset))?;

            let data_in_segment = next.memory_size - tail_offset;
            let data_taken = remaining.min(data_in_segment);
            let mut limited = reader.take(data_taken);

            let copied = std::io::copy(&mut limited, writer)?;
            // println!("Copying from DMP: 0x{:08X} .. 0x{:08X} (0x{:08X} + {} bytes) -> 0x{:08X} ..\t 0x{:08X} ({} bytes)", next.data_offset + tail_offset, next.data_offset + tail_offset + data_taken, next.memory_base_address, data_taken, written, written + copied, copied);
            written += data_taken;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Memory64Descriptor {
    data_offset: u64,
    memory_base_address: u64,
    memory_size: u64,
}

impl Memory64Descriptor {
    fn read(reader: &mut dyn Read, data_offset: u64) -> Result<Self> {
        Ok(Self {
            data_offset,
            memory_base_address: reader.read_u64::<LittleEndian>()?,
            memory_size: reader.read_u64::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct FixedFileInfo {
    signature: u32,
    struct_version: u32,
    file_version: u64,
    product_version: u64,
    file_flags_mask: u32,
    file_flags: u32,
    file_os: u32,
    file_type: u32,
    file_subtype: u32,
    file_date_ms: u32,  // Can't use u64 due to alignment.
    file_date_ls: u32,
}

impl FixedFileInfo {
    fn read(reader: &mut dyn Read) -> Result<Self> {
        Ok(Self {
            signature: reader.read_u32::<LittleEndian>()?,
            struct_version: reader.read_u32::<LittleEndian>()?,
            file_version: reader.read_u64::<LittleEndian>()?,
            product_version: reader.read_u64::<LittleEndian>()?,
            file_flags_mask: reader.read_u32::<LittleEndian>()?,
            file_flags: reader.read_u32::<LittleEndian>()?,
            file_os: reader.read_u32::<LittleEndian>()?,
            file_type: reader.read_u32::<LittleEndian>()?,
            file_subtype: reader.read_u32::<LittleEndian>()?,
            file_date_ms: reader.read_u32::<LittleEndian>()?,
            file_date_ls: reader.read_u32::<LittleEndian>()?,
        })
    }
}

fn main() -> Result<()> {
    let matches = App::new("Waste")
        .arg(Arg::with_name("file").index(1).required(true))
        .get_matches();

    let file = File::open(matches.value_of("file").expect("Required argument missing"))?;
    let mut reader = BufReader::new(file);

    let header = Header::read(&mut reader)?;
    println!("{:#?}", header);

    let expected_signature = u32::from_le_bytes(b"MDMP"[..].try_into().unwrap());
    if header.signature != u32::from_le_bytes(b"MDMP"[..].try_into().unwrap()) {
        bail!("Bad signature: {:?}, expected: {}", header.signature, expected_signature);
    }

    reader.seek(SeekFrom::Start(header.streams_offset as _))?;
    let streams = (0..header.streams_count)
        .into_iter()
        .map(|_| StreamHeader::read(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;

    let mut memory = None;
    let mut modules = None;
    for s in &streams {
        println!("- Stream: {:?}", s);
        match s.ty {
            StreamType::Known(KnownStreamType::ModuleListStream) => {
                reader.seek(SeekFrom::Start(s.data_offset as _))?;
                let mods = ModuleList::read(&mut reader)?;
                modules = Some(mods.modules);
            }
            StreamType::Known(KnownStreamType::Memory64ListStream) => {
                reader.seek(SeekFrom::Start(s.data_offset as _))?;
                memory = Some(Memory64List::read(&mut reader)?);
            }
            _ => {}
        }
    }

    let memory = memory.context("No memory in Minidump")?;
    let modules = modules.context("No modules in Minidump")?;

    println!("Program memory dump starts at 0x{:x}", memory.memory_data_start);
    println!("Total dump size: 0x{:X}", reader.seek(SeekFrom::End(0))?);

    for m in modules {
        reader.seek(SeekFrom::Start(m.module_name_offset as _))?;
        let mdstr = MdString::read(&mut reader)?;
        let module_name = mdstr.0.to_string_lossy();

        let path = PathBuf::from(&module_name);
        let file_name = path.file_name().context("No module file name")?;
        let target_file = Path::new("./modules-2").join(file_name);

        println!("- Module: {}", module_name);
        println!("  - image_base: {} + {} bytes", m.image_base, m.image_len);
        println!("  - image output: {}", target_file.to_string_lossy());

        let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(target_file)?;
        if let Err(_) = memory.write_image(&mut reader, m.image_base, m.image_len as _, &mut f) {
            continue;
        }

        println!("  - Patching PE...");

        // Patch the PE sections.
        println!("    - Finding PE header...");
        f.seek(SeekFrom::Start(0x3c))?;
        let lfa_new_offset = f.read_u32::<LittleEndian>()? as u64;
        f.seek(SeekFrom::Start(lfa_new_offset + 0x06))?;
        let section_count = f.read_u16::<LittleEndian>()? as u64;
        f.seek(SeekFrom::Start(lfa_new_offset + 0x14))?;
        let optional_header_size = f.read_u16::<LittleEndian>()? as u64;

        println!("    - Found {} sections.", section_count);
        let sections_base_addr = lfa_new_offset + 24 + optional_header_size;
        for s in 0..section_count {
            let section_offset = sections_base_addr + 40 * s;

            f.seek(SeekFrom::Start(section_offset + 0x08))?;
            let virtual_size = f.read_u32::<LittleEndian>()?;
            f.seek(SeekFrom::Start(section_offset + 0x0c))?;
            let virtual_address = f.read_u32::<LittleEndian>()?;

            f.seek(SeekFrom::Start(section_offset + 0x10))?;
            f.write_u32::<LittleEndian>(virtual_size)?;
            f.seek(SeekFrom::Start(section_offset + 0x14))?;
            f.write_u32::<LittleEndian>(virtual_address)?;

        }

        println!();
    }

    Ok(())
}
