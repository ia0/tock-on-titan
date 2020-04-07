// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// NOTE: The code uses asserts and expect to ease debugging.

use core::convert::TryFrom;
use h1::hil::flash::{Client, Flash};
use kernel::common::cells::OptionalCell;
use kernel::{AppId, AppSlice, Callback, Driver, Grant, ReturnCode, Shared};

pub const DRIVER_NUM: usize = 0x50004;

type WORD = u32;
const WORD_SIZE: usize = core::mem::size_of::<WORD>();
const PAGE_SIZE: usize = 2048;
const MAX_WRITE_COUNT: usize = 2;
const MAX_ERASE_COUNT: usize = 10000;
const MAX_WRITE_LENGTH: usize = 32;

#[derive(Default)]
pub struct AppData {
    callback: Option<Callback>,
    slice: Option<AppSlice<Shared, u8>>,
}

// To avoid allocating in the kernel, we use this static buffer.
static mut WRITE_BUFFER: [WORD; MAX_WRITE_LENGTH] = [0; MAX_WRITE_LENGTH];

pub struct OpenskSyscall<'c, C: Flash<'c>> {
    flash: &'c C,
    grant: Grant<AppData>,
    app: OptionalCell<AppId>,
}

impl<'c, C: Flash<'c>> OpenskSyscall<'c, C> {
    pub fn new(flash: &'c C, grant: Grant<AppData>) -> Self {
        OpenskSyscall { flash, grant, app: OptionalCell::empty() }
    }

    fn start(&self, app: AppId) -> bool {
        if self.app.is_some() {
            return false;
        }
        assert!(self.app.replace(app).is_none(), "Is the kernel concurrent?");
        true
    }

    fn write_slice(&self, app: AppId, ptr: usize, slice: &[u8]) -> ReturnCode {
        let data_length = slice.len() / WORD_SIZE;
        if ptr % WORD_SIZE != 0 || slice.len() % WORD_SIZE != 0 || data_length > MAX_WRITE_LENGTH {
            return ReturnCode::EINVAL;
        }
        if !self.start(app) {
            return ReturnCode::EBUSY;
        }
        let data = unsafe { &mut WRITE_BUFFER[.. data_length] };
        for (dst, src) in data.iter_mut().zip(slice.chunks(WORD_SIZE)) {
            // `unwrap` cannot fail because `slice.len()` is word-aligned (see above).
            *dst = WORD::from_ne_bytes(<[u8; WORD_SIZE]>::try_from(src).unwrap());
        }
        self.flash.write(ptr / WORD_SIZE, data).0
    }

    fn erase_page(&self, app: AppId, ptr: usize) -> ReturnCode {
        if ptr % PAGE_SIZE != 0 {
            return ReturnCode::EINVAL;
        }
        if !self.start(app) {
            return ReturnCode::EBUSY;
        }
        self.flash.erase(ptr / WORD_SIZE)
    }

    fn done(&self, status: ReturnCode) {
        let app = self.app.take().expect("There is always an app when an operation is ongoing.");
        self.grant
            .enter(app, |data, _| {
                if let Some(mut callback) = data.callback.take() {
                    callback.schedule(status.into(), 0, 0);
                }
            })
            .expect("Did the app died before the operation was done?");
    }
}

impl<'c, C: Flash<'c>> Driver for OpenskSyscall<'c, C> {
    fn command(&self, cmd: usize, arg: usize, _: usize, app: AppId) -> ReturnCode {
        match (cmd, arg) {
            (0, _) => ReturnCode::SUCCESS,

            (1, 0) => ReturnCode::SuccessWithValue { value: WORD_SIZE },
            (1, 1) => ReturnCode::SuccessWithValue { value: PAGE_SIZE },
            (1, 2) => ReturnCode::SuccessWithValue { value: MAX_WRITE_COUNT },
            (1, 3) => ReturnCode::SuccessWithValue { value: MAX_ERASE_COUNT },
            (1, 4) => ReturnCode::SuccessWithValue { value: MAX_WRITE_LENGTH * WORD_SIZE },
            (1, _) => ReturnCode::EINVAL,

            // Can only write up to 32 words.
            (2, ptr) => self
                .grant
                .enter(app, |data, _| {
                    let slice = match data.slice.take() {
                        None => return ReturnCode::EINVAL,
                        Some(slice) => slice,
                    };
                    self.write_slice(app, ptr, slice.as_ref())
                })
                .expect("Did the app died before the syscall could execute?"),

            (3, ptr) => self.erase_page(app, ptr),

            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn allow(&self, app: AppId, cmd: usize, slice: Option<AppSlice<Shared, u8>>) -> ReturnCode {
        match cmd {
            0 => self
                .grant
                .enter(app, |data, _| {
                    data.slice = slice;
                    ReturnCode::SUCCESS
                })
                .expect("Did the app died before the syscall could execute?"),

            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn subscribe(&self, cmd: usize, callback: Option<Callback>, app: AppId) -> ReturnCode {
        match cmd {
            0 => self
                .grant
                .enter(app, |data, _| {
                    data.callback = callback;
                    ReturnCode::SUCCESS
                })
                .expect("Did the app died before the syscall could execute?"),

            _ => ReturnCode::ENOSUPPORT,
        }
    }
}

impl<'c, C: Flash<'c>> Client<'c> for OpenskSyscall<'c, C> {
    fn erase_done(&self, status: ReturnCode) {
        self.done(status);
    }

    fn write_done(&self, _: &'c mut [u32], status: ReturnCode) {
        self.done(status);
    }
}
