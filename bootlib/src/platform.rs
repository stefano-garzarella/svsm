// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

/// Defines the underlying platform type on which the SVSM will run.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub enum SvsmPlatformType {
    Native = 0,
    Snp = 1,
    Tdp = 2,
}

impl SvsmPlatformType {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Native => 0,
            Self::Snp => 1,
            Self::Tdp => 2,
        }
    }

    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Snp,
            2 => Self::Tdp,
            _ => Self::Native,
        }
    }
}
