// Copyright 2019 Google LLC
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

pub struct MockAlarm {
    current_time: core::cell::Cell<u32>,
    setpoint: core::cell::Cell<Option<u32>>,
}

impl MockAlarm {
    pub fn new() -> MockAlarm {
        MockAlarm {
            current_time: Default::default(),
            setpoint: Default::default()
        }
    }

    pub fn set_time(&self, new_time: u32) { self.current_time.set(new_time); }
}

impl kernel::hil::time::Time for MockAlarm {
    type Frequency = kernel::hil::time::Freq16MHz;
    fn now(&self) -> u32 { self.current_time.get() }
    fn max_tics(&self) -> u32 { u32::max_value() }
}

impl<'a> kernel::hil::time::Alarm<'a> for MockAlarm {
    fn set_alarm(&self, tics: u32) { self.setpoint.set(Some(tics)); }
    fn get_alarm(&self) -> u32 { self.setpoint.get().unwrap_or(0) }

    // Ignored -- the test should manually trigger the client.
    fn set_client(&'a self, _client: &'a dyn kernel::hil::time::AlarmClient) {}

    fn is_enabled(&self) -> bool { self.setpoint.get().is_some() }

    fn enable(&self) {
        if self.setpoint.get().is_none() { self.setpoint.set(Some(0)); }
    }

    fn disable(&self) { self.setpoint.set(None); }
}
