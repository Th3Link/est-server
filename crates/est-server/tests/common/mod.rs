//! What the end-to-end tests share: `Setup` starts a server for one test
//! (own ports, own state, own namespace in the cluster), `Est` is the
//! client side, a gateway-like device talking EST over reqwest.

// Every test binary uses its own part of this.
#![allow(dead_code)]

pub mod cluster;
pub mod est;
pub mod helper;
pub mod setup;
