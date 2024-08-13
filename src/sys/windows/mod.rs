use std::ffi::OsString;
use std::io::{IoSlice, IoSliceMut};
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows_registry::{Key, LOCAL_MACHINE};
use windows_sys::Win32::Devices::Communication::{EscapeCommFunction, GetCommModemStatus, GetCommState, GetCommTimeouts, PurgeComm, SetCommState, SetCommTimeouts, CLRDTR, CLRRTS, EVENPARITY, MS_CTS_ON, MS_DSR_ON, MS_RING_ON, MS_RLSD_ON, NOPARITY, ODDPARITY, ONESTOPBIT, PURGE_RXCLEAR, PURGE_TXCLEAR, SETDTR, SETRTS, TWOSTOPBITS};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, ERROR_IO_PENDING};
use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
use windows_sys::Win32::System::Threading::CreateEventA;
use windows_sys::Win32::System::WindowsProgramming::{DTR_CONTROL_DISABLE, RTS_CONTROL_DISABLE, RTS_CONTROL_TOGGLE};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::{Devices::Communication::{COMMTIMEOUTS, DCB}, Storage::FileSystem::FILE_FLAG_OVERLAPPED};

macro_rules! BITFIELD {
    ($base:ident $inner:ident $field:ident: $fieldtype:ty [
        $($thing:ident $set_thing:ident[$r:expr],)+
    ]) => {
        impl $base {$(
            #[inline]
            pub fn $thing(&self) -> $fieldtype {
                let size = std::mem::size_of::<$fieldtype>() * 8;
                self.$inner.$field << (size - $r.end) >> (size - $r.end + $r.start)
            }
            #[inline]
            pub fn $set_thing(&mut self, val: $fieldtype) {
                let mask = ((1 << ($r.end - $r.start)) - 1) << $r.start;
                self.$inner.$field &= !mask;
                self.$inner.$field |= (val << $r.start) & mask;
            }
        )+}
    }
}

BITFIELD!{Settings dcb _bitfield: u32 [
    fBinary set_fBinary[0..1],
    fParity set_fParity[1..2],
    fOutxCtsFlow set_fOutxCtsFlow[2..3],
    fOutxDsrFlow set_fOutxDsrFlow[3..4],
    fDtrControl set_fDtrControl[4..6],
    fDsrSensitivity set_fDsrSensitivity[6..7],
    fTXContinueOnXoff set_fTXContinueOnXoff[7..8],
    fOutX set_fOutX[8..9],
    fInX set_fInX[9..10],
    fErrorChar set_fErrorChar[10..11],
    fNull set_fNull[11..12],
    fRtsControl set_fRtsControl[12..14],
    fAbortOnError set_fAbortOnError[14..15],
    fDummy2 set_fDummy2[15..32],
]}

pub struct SerialPort {
	pub file: std::fs::File,
}

#[derive(Clone)]
pub struct Settings {
	pub dcb: DCB,
}

impl SerialPort {
	pub fn open(name: &Path) -> std::io::Result<Self> {
		use std::os::windows::fs::OpenOptionsExt;

		// Use the win32 device namespace, otherwise we're limited to COM1-9.
		// This also works with higher numbers.
		// https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#win32-device-namespaces
		let mut path = OsString::from("\\\\.\\");
		path.push(name.as_os_str());

		let file = std::fs::OpenOptions::new()
			.read(true)
			.write(true)
			.create(false)
			.custom_flags(FILE_FLAG_OVERLAPPED)
			.open(path)?;

		unsafe {
			let mut timeouts: COMMTIMEOUTS = std::mem::zeroed();
			check_bool(GetCommTimeouts(file.as_raw_handle(), &mut timeouts))?;
			// Mimic POSIX behaviour for reads.
			// For more details, see:
			// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-commtimeouts#remarks
			timeouts.ReadIntervalTimeout = u32::MAX;
			timeouts.ReadTotalTimeoutMultiplier = u32::MAX;
			timeouts.ReadTotalTimeoutConstant = super::DEFAULT_TIMEOUT_MS;
			timeouts.WriteTotalTimeoutMultiplier = 0;
			timeouts.WriteTotalTimeoutConstant = super::DEFAULT_TIMEOUT_MS;
			check_bool(SetCommTimeouts(file.as_raw_handle(), &mut timeouts))?;
		}
		Ok(Self::from_file(file))
	}

	pub fn from_file(file: std::fs::File) -> Self {
		Self { file }
	}

	pub fn try_clone(&self) -> std::io::Result<Self> {
		Ok(Self {
			file: self.file.try_clone()?,
		})
	}

	pub fn get_configuration(&self) -> std::io::Result<Settings> {
		unsafe {
			let mut dcb: DCB = std::mem::zeroed();
			check_bool(GetCommState(self.file.as_raw_handle(), &mut dcb))?;
			Ok(Settings { dcb })
		}
	}

	pub fn set_configuration(&mut self, settings: &Settings) -> std::io::Result<()> {
		unsafe {
			let mut settings = settings.clone();
			check_bool(SetCommState(self.file.as_raw_handle(), &mut settings.dcb))
		}
	}

	pub fn set_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
		unsafe {
			let mut timeouts = std::mem::zeroed();
			// Mimic POSIX behaviour for reads.
			// Timeout must be > 0 and < u32::MAX, so clamp it.
			// For more details, see:
			// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-commtimeouts#remarks
			let timeout_ms = timeout
				.as_millis()
				.try_into()
				.unwrap_or(u32::MAX)
				.clamp(1, u32::MAX - 1);
			check_bool(GetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))?;
			timeouts.ReadIntervalTimeout = u32::MAX;
			timeouts.ReadTotalTimeoutMultiplier = u32::MAX;
			timeouts.ReadTotalTimeoutConstant = timeout_ms;
			check_bool(SetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))
		}
	}

	pub fn get_read_timeout(&self) -> std::io::Result<Duration> {
		unsafe {
			let mut timeouts = std::mem::zeroed();
			check_bool(GetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))?;
			Ok(Duration::from_millis(timeouts.ReadTotalTimeoutConstant.into()))
		}
	}

	pub fn set_write_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
		unsafe {
			let mut timeouts = std::mem::zeroed();
			let timeout_ms = timeout.as_millis().try_into().unwrap_or(u32::MAX);
			check_bool(GetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))?;
			timeouts.WriteTotalTimeoutMultiplier = 0;
			timeouts.WriteTotalTimeoutConstant = timeout_ms;
			check_bool(SetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))
		}
	}

	pub fn get_write_timeout(&self) -> std::io::Result<Duration> {
		unsafe {
			let mut timeouts = std::mem::zeroed();
			check_bool(GetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))?;
			Ok(Duration::from_millis(timeouts.WriteTotalTimeoutConstant.into()))
		}
	}

	#[cfg(any(feature = "doc", all(feature = "windows", windows)))]
	pub fn get_windows_timeouts(&self) -> std::io::Result<crate::os::windows::CommTimeouts> {
		unsafe {
			let mut timeouts = std::mem::zeroed();
			check_bool(GetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))?;
			Ok(crate::os::windows::CommTimeouts {
				read_interval_timeout: timeouts.ReadIntervalTimeout,
				read_total_timeout_multiplier: timeouts.ReadTotalTimeoutMultiplier,
				read_total_timeout_constant: timeouts.ReadTotalTimeoutConstant,
				write_total_timeout_multiplier: timeouts.WriteTotalTimeoutMultiplier,
				write_total_timeout_constant: timeouts.WriteTotalTimeoutConstant,
			})
		}
	}

	#[cfg(any(feature = "doc", all(feature = "windows", windows)))]
	pub fn set_windows_timeouts(&self, timeouts: &crate::os::windows::CommTimeouts) -> std::io::Result<()> {
		let mut timeouts = COMMTIMEOUTS {
			ReadIntervalTimeout: timeouts.read_interval_timeout,
			ReadTotalTimeoutMultiplier: timeouts.read_total_timeout_multiplier,
			ReadTotalTimeoutConstant: timeouts.read_total_timeout_constant,
			WriteTotalTimeoutMultiplier: timeouts.write_total_timeout_multiplier,
			WriteTotalTimeoutConstant: timeouts.write_total_timeout_constant,
		};
		unsafe {
			check_bool(SetCommTimeouts(self.file.as_raw_handle(), &mut timeouts))?;
			Ok(())
		}
	}

	pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
		unsafe {
			let len = buf.len().try_into().unwrap_or(u32::MAX);
			let event = Event::create(false, false)?;
			let mut read = 0;
			let mut overlapped: OVERLAPPED = std::mem::zeroed();
			overlapped.hEvent = event.handle;
			let ret = check_bool(ReadFile(
				self.file.as_raw_handle(),
				buf.as_mut_ptr().cast(),
				len,
				&mut read,
				&mut overlapped,
			));
			match ret {
				// Windows reports timeouts as a succesfull transfer of 0 bytes.
				Ok(()) if read == 0 => return Err(std::io::ErrorKind::TimedOut.into()),
				Ok(()) => return Ok(read as usize),
				// BrokenPipe with reads means EOF on Windows.
				Err(ref e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(0),
				Err(ref e) if e.raw_os_error() == Some(ERROR_IO_PENDING as i32) => (),
				Err(e) => return Err(e),
			}

			wait_async_transfer(&self.file, &mut overlapped).or_else(map_broken_pipe)
		}
	}

	pub fn read_vectored(&self, buf: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
		if buf.is_empty() {
			self.read(&mut [])
		} else {
			self.read(&mut buf[0])
		}
	}

	pub fn is_read_vectored(&self) -> bool {
		false
	}

	pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
		unsafe {
			let len = buf.len().try_into().unwrap_or(u32::MAX);
			let event = Event::create(false, false)?;
			let mut written = 0;
			let mut overlapped: OVERLAPPED = std::mem::zeroed();
			overlapped.hEvent = event.handle;
			let ret = check_bool(WriteFile(
				self.file.as_raw_handle(),
				buf.as_ptr().cast(),
				len,
				&mut written,
				&mut overlapped,
			));
			match ret {
				// Windows reports timeouts as a succesfull transfer of 0 bytes.
				Ok(()) if written == 0 => return Err(std::io::ErrorKind::TimedOut.into()),
				Ok(()) => return Ok(written as usize),
				Err(ref e) if e.raw_os_error() == Some(ERROR_IO_PENDING as i32) => (),
				Err(e) => return Err(e),
			}

			wait_async_transfer(&self.file, &mut overlapped)
		}
	}

	pub fn write_vectored(&self, buf: &[IoSlice<'_>]) -> std::io::Result<usize> {
		if buf.is_empty() {
			self.write(&[])
		} else {
			self.write(&buf[0])
		}
	}

	pub fn is_write_vectored(&self) -> bool {
		false
	}

	pub fn flush_output(&self) -> std::io::Result<()> {
		unsafe { check_bool(FlushFileBuffers(self.file.as_raw_handle())) }
	}

	pub fn discard_buffers(&self, discard_input: bool, discard_output: bool) -> std::io::Result<()> {
		unsafe {
			let mut flags = 0;
			if discard_input {
				flags |= PURGE_RXCLEAR;
			}
			if discard_output {
				flags |= PURGE_TXCLEAR;
			}
			check_bool(PurgeComm(self.file.as_raw_handle(), flags))
		}
	}

	pub fn set_rts(&self, state: bool) -> std::io::Result<()> {
		if state {
			escape_comm_function(&self.file, SETRTS)
		} else {
			escape_comm_function(&self.file, CLRRTS)
		}
	}

	pub fn read_cts(&self) -> std::io::Result<bool> {
		read_pin(&self.file, MS_CTS_ON)
	}

	pub fn set_dtr(&self, state: bool) -> std::io::Result<()> {
		if state {
			escape_comm_function(&self.file, SETDTR)
		} else {
			escape_comm_function(&self.file, CLRDTR)
		}
	}

	pub fn read_dsr(&self) -> std::io::Result<bool> {
		read_pin(&self.file, MS_DSR_ON)
	}

	pub fn read_ri(&self) -> std::io::Result<bool> {
		read_pin(&self.file, MS_RING_ON)
	}

	pub fn read_cd(&self) -> std::io::Result<bool> {
		// RLSD or Receive Line Signal Detect is the same as Carrier Detect.
		//
		// I think.
		read_pin(&self.file, MS_RLSD_ON)
	}
}

struct Event {
	handle: RawHandle,
}

impl Event {
	fn create(manual_reset: bool, initially_signalled: bool) -> std::io::Result<Self> {
		unsafe {
			let manual_reset = if manual_reset { 1 } else { 0 };
			let initially_signalled = if initially_signalled { 1 } else { 0 };
			let handle = check_handle(CreateEventA(
				std::ptr::null_mut(), // security attributes
				manual_reset,
				initially_signalled,
				std::ptr::null(), // name
			))?;
			Ok(Self { handle })
		}
	}
}

impl Drop for Event {
	fn drop(&mut self) {
		unsafe {
			CloseHandle(self.handle);
		}
	}
}

fn map_broken_pipe(error: std::io::Error) -> std::io::Result<usize> {
	if error.kind() == std::io::ErrorKind::BrokenPipe {
		Ok(0)
	} else {
		Err(error)
	}
}

fn wait_async_transfer(file: &std::fs::File, overlapped: &mut OVERLAPPED) -> std::io::Result<usize> {
	unsafe {
		let mut transferred = 0;
		let ret = check_bool(GetOverlappedResult(
			file.as_raw_handle(),
			overlapped,
			&mut transferred,
			1,
		));
		match ret {
			// Windows reports timeouts as a succesfull transfer of 0 bytes.
			Ok(_) if transferred == 0 => Err(std::io::ErrorKind::TimedOut.into()),
			Ok(_) => Ok(transferred as usize),
			Err(e) => Err(e),
		}
	}
}

fn escape_comm_function(file: &std::fs::File, function: u32) -> std::io::Result<()> {
	unsafe { check_bool(EscapeCommFunction(file.as_raw_handle(), function)) }
}

fn read_pin(file: &std::fs::File, pin: u32) -> std::io::Result<bool> {
	unsafe {
		let mut bits: u32 = 0;
		check_bool(GetCommModemStatus(file.as_raw_handle(), &mut bits))?;
		Ok(bits & pin != 0)
	}
}

/// Check the return value of a syscall for errors.
fn check_bool(ret: BOOL) -> std::io::Result<()> {
	if ret == 0 {
		Err(std::io::Error::last_os_error())
	} else {
		Ok(())
	}
}

/// Check the return value of a syscall for errors.
fn check_handle(ret: RawHandle) -> std::io::Result<RawHandle> {
	if ret.is_null() {
		Err(std::io::Error::last_os_error())
	} else {
		Ok(ret)
	}
}

/// Create an std::io::Error with custom message.
fn other_error<E>(msg: E) -> std::io::Error
where
	E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
	std::io::Error::new(std::io::ErrorKind::Other, msg)
}

impl Settings {
	pub fn set_raw(&mut self) {
		self.set_char_size(crate::CharSize::Bits8);
		self.set_stop_bits(crate::StopBits::One);
		self.set_parity(crate::Parity::None);
		self.set_flow_control(crate::FlowControl::None);
		self.set_fBinary(1);
		self.set_fErrorChar(0);
		self.set_fNull(0);
	}

	pub fn set_baud_rate(&mut self, baud_rate: u32) -> std::io::Result<()> {
		self.dcb.BaudRate = baud_rate;
		Ok(())
	}

	pub fn get_baud_rate(&self) -> std::io::Result<u32> {
		Ok(self.dcb.BaudRate)
	}

	pub fn set_char_size(&mut self, char_size: crate::CharSize) {
		self.dcb.ByteSize = match char_size {
			crate::CharSize::Bits5 => 5,
			crate::CharSize::Bits6 => 6,
			crate::CharSize::Bits7 => 7,
			crate::CharSize::Bits8 => 8,
		};
	}

	pub fn get_char_size(&self) -> std::io::Result<crate::CharSize> {
		match self.dcb.ByteSize {
			5 => Ok(crate::CharSize::Bits5),
			6 => Ok(crate::CharSize::Bits6),
			7 => Ok(crate::CharSize::Bits7),
			8 => Ok(crate::CharSize::Bits8),
			_ => Err(other_error("unsupported char size")),
		}
	}

	pub fn set_stop_bits(&mut self, stop_bits: crate::StopBits) {
		self.dcb.StopBits = match stop_bits {
			crate::StopBits::One => ONESTOPBIT,
			crate::StopBits::Two => TWOSTOPBITS,
		};
	}

	pub fn get_stop_bits(&self) -> std::io::Result<crate::StopBits> {
		match self.dcb.StopBits {
			ONESTOPBIT => Ok(crate::StopBits::One),
			TWOSTOPBITS => Ok(crate::StopBits::Two),
			_ => Err(other_error("unsupported stop bits")),
		}
	}

	pub fn set_parity(&mut self, parity: crate::Parity) {
		match parity {
			crate::Parity::None => {
				self.set_fParity(0);
				self.dcb.Parity = NOPARITY;
			},
			crate::Parity::Odd => {
				self.set_fParity(1);
				self.dcb.Parity = ODDPARITY;
			},
			crate::Parity::Even => {
				self.set_fParity(1);
				self.dcb.Parity = EVENPARITY;
			},
		}
	}

	pub fn get_parity(&self) -> std::io::Result<crate::Parity> {
		let parity_enabled = self.fParity() != 0;
		match self.dcb.Parity {
			NOPARITY => Ok(crate::Parity::None),
			ODDPARITY if parity_enabled => Ok(crate::Parity::Odd),
			EVENPARITY if parity_enabled => Ok(crate::Parity::Even),
			_ => Err(other_error("unsupported parity configuration")),
		}
	}

	pub fn set_flow_control(&mut self, flow_control: crate::FlowControl) {
		match flow_control {
			crate::FlowControl::None => {
				self.set_fInX(0);
				self.set_fOutX(0);
				self.set_fDtrControl(DTR_CONTROL_DISABLE);
				self.set_fDsrSensitivity(0);
				self.set_fOutxDsrFlow(0);
				self.set_fRtsControl(RTS_CONTROL_DISABLE);
				self.set_fOutxCtsFlow(0);
			},
			crate::FlowControl::XonXoff => {
				self.set_fInX(1);
				self.set_fOutX(1);
				self.set_fDtrControl(DTR_CONTROL_DISABLE);
				self.set_fDsrSensitivity(0);
				self.set_fOutxDsrFlow(0);
				self.set_fRtsControl(RTS_CONTROL_DISABLE);
				self.set_fOutxCtsFlow(0);
			},
			crate::FlowControl::RtsCts => {
				self.set_fInX(0);
				self.set_fOutX(0);
				self.set_fDtrControl(DTR_CONTROL_DISABLE);
				self.set_fDsrSensitivity(0);
				self.set_fOutxDsrFlow(0);
				self.set_fRtsControl(RTS_CONTROL_TOGGLE);
				self.set_fOutxCtsFlow(1);
			},
		}
	}

	#[rustfmt::skip]
	pub fn get_flow_control(&self) -> std::io::Result<crate::FlowControl> {
		let in_x = self.fInX() != 0;
		let out_x = self.fOutX() != 0;
		let out_cts = self.fOutxCtsFlow() != 0;
		let out_dsr = self.fOutxDsrFlow() != 0;

		match (in_x, out_x, out_cts, out_dsr, self.fDtrControl(), self.fRtsControl()) {
			(false, false, false, false, DTR_CONTROL_DISABLE, RTS_CONTROL_DISABLE) => {
				Ok(crate::FlowControl::None)
			},
			(true, true, false, false, DTR_CONTROL_DISABLE, RTS_CONTROL_DISABLE) => {
				Ok(crate::FlowControl::XonXoff)
			},
			(false, false, true, false, DTR_CONTROL_DISABLE, RTS_CONTROL_TOGGLE) => {
				Ok(crate::FlowControl::RtsCts)
			},
			_ => Err(other_error("unsupported flow control configuration")),
		}
	}
}

pub fn enumerate() -> std::io::Result<Vec<PathBuf>> {
	let subkey = "Hardware\\DEVICEMAP\\SERIALCOMM";
	let device_map = match Key::open(LOCAL_MACHINE, subkey) {
		Ok(x) => x,
		Err(e) => {
			let std_error = std::io::Error::from(e);
			if std_error.kind() == std::io::ErrorKind::NotFound {
			    // The registry key doesn't exist until a serial port was available at-least once.
			    return Ok(Vec::new());
			} else {
				return Err(std_error);
			}
		},
	};

	let values_iter = device_map.values()?;

	let mut entries = Vec::with_capacity(16);
	for (_name, value) in values_iter {
		let path = PathBuf::from(String::try_from(value)?);
		entries.push(path);
	}

	Ok(entries)
}
