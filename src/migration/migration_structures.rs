use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::types::EventCategory;

#[derive(Debug, Deserialize, Serialize)]
pub struct FtpEventFieldsV0_41 {
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
    pub user: String,
    pub password: String,
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
    pub confidence: f32,
    pub category: EventCategory,
}

impl From<FtpEventFieldsV0_41> for crate::event::FtpEventFields {
    fn from(value: FtpEventFieldsV0_41) -> Self {
        let command = crate::event::FtpCommand {
            command: value.command,
            reply_code: value.reply_code,
            reply_msg: value.reply_msg,
            data_passive: value.data_passive,
            data_orig_addr: value.data_orig_addr,
            data_resp_addr: value.data_resp_addr,
            data_resp_port: value.data_resp_port,
            file: value.file,
            file_size: value.file_size,
            file_id: value.file_id,
        };

        Self {
            sensor: value.sensor,
            src_addr: value.src_addr,
            src_port: value.src_port,
            dst_addr: value.dst_addr,
            dst_port: value.dst_port,
            proto: value.proto,
            end_time: value.end_time,
            user: value.user,
            password: value.password,
            commands: vec![command],
            confidence: value.confidence,
            category: value.category,
        }
    }
}
