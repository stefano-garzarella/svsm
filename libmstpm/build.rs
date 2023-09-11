// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

use std::process::Command;

fn main() {
    Command::new("make").status().unwrap();
}
