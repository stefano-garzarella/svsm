// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Red Hat, Inc. All rights reserved.
//
// Author: Stefano Garzarella <sgarzare@redhat.com>

use crate::error::SvsmError;

use crate::serial::{SerialPort, Terminal};

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError>;
    fn flush(&mut self) -> Result<(), SvsmError>;
}

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, SvsmError>;
}

pub trait Connection: Write + Read {}

pub struct Proxy {
    conn: *mut (dyn Connection),
}

impl Proxy {
    pub fn new(conn: *mut dyn Connection) -> Self {
        Proxy { conn }
    }
}

impl Write for Proxy {
    fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError> {
        unsafe { (*self.conn).write(buf) }
    }

    fn flush(&mut self) -> Result<(), SvsmError> {
        unsafe { (*self.conn).flush() }
    }
}

impl Read for Proxy {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        unsafe { (*self.conn).read(buf) }
    }
}

impl<'a> Write for SerialPort<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError> {
        let mut count = 0usize;

        for byte in buf {
            self.put_byte(*byte);
            count += 1;
        }

        Ok(count)
    }

    fn flush(&mut self) -> Result<(), SvsmError> {
        Ok(())
    }
}

impl<'a> Read for SerialPort<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        let mut count = 0usize;

        for byte in buf {
            *byte = self.get_byte();
            count += 1;
        }

        Ok(count)
    }
}

impl<'a> Connection for SerialPort<'a> {}
