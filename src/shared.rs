use anyhow::{Result, Error};

pub const CONTROL_PORT: u16 = 7835;
pub const SAFE_MAX_SIZE: usize = 512;
pub const CONN_LIFETIME: u8 = 65;
pub const MAX_RETRY: u8 = 3;

pub struct Header {
    pub packet_num: u8,
    pub msg_type: u8,
    pub auth_type: u8,
    pub fragment: u8,
    pub conn_id: u16,
    pub data_len: u16,
}

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

pub enum Message {
    SERVERHELLO = 1,
    CLIENTHELLO = 2,
    DATA = 3,
    ERRCODE = 4,
    HEARTBEAT = 5,
}

impl Message {
    pub fn from_num(num: u8) -> Message {
        match num {
            1 => Message::SERVERHELLO,
            2 => Message::CLIENTHELLO,
            3 => Message::DATA,
            5 => Message::HEARTBEAT,
            4 | _ => Message::ERRCODE,
        }
    }

}

impl Header {
    pub fn new(packet_num: u8, msg: u8, auth: u8, frag: u8, id: u16, len: u16) -> Header {
        Header {
            packet_num,
            msg_type: msg,
            auth_type: auth,
            fragment: frag,
            conn_id: id,
            data_len: len,
        }
    }

    pub fn to_bytes(&self) -> Result<[u8; 8]> {
        let mut res = [0u8; 8];
        let mut pos: usize = 0;
        res[pos] = self.packet_num;
        pos += 1;
        res[pos] = self.msg_type;
        pos += 1;
        res[pos] = self.auth_type;
        pos += 1;
        res[pos] = self.fragment;
        pos += 1;
        res[pos] = (self.conn_id >> 8) as u8;
        pos += 1;
        res[pos] = (self.conn_id & 0xFF) as u8;
        pos += 1;
        res[pos] = (self.data_len >> 8) as u8;
        pos += 1;
        res[pos] = (self.data_len & 0xFF) as u8;
        Ok(res)
    }
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0;512],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(Error::msg("End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    pub fn read_header(&mut self) -> Result<Header> {
        if self.pos > 0 {
            Err(Error::msg("Fail to read Header, it might already been read"))
        } else {
            let pack_num = self.read()?;
            let msg_type = self.read()?;
            let auth_type = self.read()?;
            let fragment = self.read()?;
            let conn_id = self.read_u16()?;
            let data_len = self.read_u16()?;
            let res = Header::new(pack_num,msg_type,auth_type,fragment,conn_id,data_len);
            Ok(res)
        }
    }

    pub fn read_data(&mut self, length: u16) -> Result<&[u8]> {
        if self.pos > 7 {
            Err(Error::msg("Fail to read data, it might already been read"))
        } else if self.pos == 7 {
            let end = self.pos + length as usize;
            let res = &self.buf[self.pos + 1..end + 2];
            Ok(res)
        } else {
            Err(Error::msg("Fail to read data, Header have not finished reading yet"))
        }
    }

}