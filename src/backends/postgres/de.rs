use std::{fmt, ops::Deref};

use bb8_postgres::tokio_postgres::{
    types::{FromSql, Type},
    Row,
};
use chrono::NaiveDateTime;
use fallible_iterator::FallibleIterator;
use serde::{
    de::{self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor},
    Deserialize,
};

use super::error::{Error, Result};

pub struct Deserializer<'de> {
    input: &'de Row,
    index: usize,
}

impl<'de> Deserializer<'de> {
    pub fn from_row(input: &'de Row) -> Self {
        Self { input, index: 0 }
    }
}

pub fn from_row<'de, T>(row: &'de Row) -> Result<T>
where
    T: Deserialize<'de>,
{
    let mut deserializer = Deserializer::from_row(row);
    T::deserialize(&mut deserializer)
}

impl<'a, 'de> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bool(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i8(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i16(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let value: i64 = self
            .input
            .try_get::<'_, _, i64>(self.index)
            .or_else(|e| {
                self.input
                    .try_get::<'_, _, NaiveDateTime>(self.index)
                    .map(|t| t.and_utc().timestamp_nanos_opt().unwrap_or(i64::MAX))
                    .map_err(|_| e)
            })
            .map_err(|e| Error::Type(e.to_string()))?;
        visitor.visit_i64(value)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(
            #[allow(clippy::cast_sign_loss)] // preserves bits
            self.input
                .try_get::<'_, _, i8>(self.index)
                .map(|v| v as u8)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u16(
            #[allow(clippy::cast_sign_loss)] // preserves bits
            self.input
                .try_get::<'_, _, i16>(self.index)
                .map(|v| v as u16)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(
            #[allow(clippy::cast_sign_loss)] // preserves bits
            self.input
                .try_get::<'_, _, i32>(self.index)
                .map(|v| v as u32)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(
            #[allow(clippy::cast_sign_loss)] // preserves bits
            self.input
                .try_get::<'_, _, i64>(self.index)
                .map(|v| v as u64)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f32(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f64(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_str(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_string(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bytes(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_byte_buf(
            self.input
                .try_get(self.index)
                .map_err(|e| Error::Type(e.to_string()))?,
        )
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match self
            .input
            .try_get::<_, Option<Raw>>(self.index)
            .map_err(|e| Error::Type(e.to_string()))?
        {
            Some(_) => visitor.visit_some(self),
            None => visitor.visit_none(),
        }
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let raw = self
            .input
            .try_get::<_, Raw<'de>>(self.index)
            .map_err(|e| Error::Type(e.to_string()))?;
        let array = postgres_protocol::types::array_from_sql(raw.0)
            .map_err(|e| Error::Type(e.to_string()))?;
        let element_type = Type::from_oid(array.element_type()).unwrap();
        let ret = visitor.visit_seq(ArrayDeserializer::new(array.values(), element_type));
        ret
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(self)
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

impl<'de> MapAccess<'de> for Deserializer<'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        if self.index >= self.input.columns().len() {
            return Ok(None);
        }

        self.input
            .columns()
            .get(self.index)
            .ok_or(Error::Unsupported)
            .map(|c| c.name().to_owned().into_deserializer())
            .and_then(|n| seed.deserialize(n).map(Some))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        let result = seed.deserialize(&mut *self);
        self.index += 1;
        if let Err(Error::Type(e)) = result {
            let name = self
                .input
                .columns()
                .get(self.index - 1)
                .expect("valid index")
                .name();
            Err(Error::Type(format!("{name} {e}")))
        } else {
            result
        }
    }
}

#[derive(Debug)]
struct Raw<'de>(pub &'de [u8]);

impl<'de> FromSql<'de> for Raw<'de> {
    fn from_sql(
        _ty: &Type,
        raw: &'de [u8],
    ) -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Raw(raw))
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }
}

impl<'de> Deref for Raw<'de> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

struct ArrayDeserializer<I> {
    iter: I,
    element_type: Type,
}

impl<I> ArrayDeserializer<I>
where
    I: FallibleIterator,
{
    fn new(iter: I, element_type: Type) -> Self {
        Self { iter, element_type }
    }
}

impl<'seed, 'de: 'seed, I> SeqAccess<'seed> for ArrayDeserializer<I>
where
    I: FallibleIterator<Item = Option<&'de [u8]>>,
    I::Error: fmt::Display,
{
    type Error = Error;

    fn next_element_seed<V>(
        &mut self,
        seed: V,
    ) -> std::result::Result<Option<V::Value>, Self::Error>
    where
        V: DeserializeSeed<'seed>,
    {
        match self.iter.next() {
            Ok(Some(value)) => match value {
                Some(value) => seed
                    .deserialize(ElementDeserializer::new(value, &self.element_type))
                    .map(Some),
                None => Err(Error::Message("invalid value".to_string())),
            },
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Message(e.to_string())),
        }
    }
}

/// Deserializes an element of a PostgreSQL array.
///
/// It supports `i32`, `i64`, and `String` only.
struct ElementDeserializer<'de, 't> {
    input: &'de [u8],
    element_type: &'t Type,
}

impl<'de, 't> ElementDeserializer<'de, 't> {
    fn new(input: &'de [u8], element_type: &'t Type) -> Self {
        Self {
            input,
            element_type,
        }
    }
}

impl<'de, 't> de::Deserializer<'de> for ElementDeserializer<'de, 't> {
    type Error = Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if *self.element_type == Type::BOOL {
            visitor.visit_bool(
                postgres_protocol::types::bool_from_sql(self.input)
                    .map_err(|e| Error::Type(format!("not bool: {e}")))?,
            )
        } else {
            Err(Error::Type(format!(
                "expecting bool, found {}",
                self.element_type
            )))
        }
    }

    fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_i16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if *self.element_type == Type::INT4 {
            visitor.visit_i32(
                postgres_protocol::types::int4_from_sql(self.input)
                    .map_err(|e| Error::Type(format!("not i32: {e}")))?,
            )
        } else {
            Err(Error::Type(format!(
                "expecting i32, found {}",
                self.element_type
            )))
        }
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if *self.element_type == Type::INT8 {
            visitor.visit_i64(
                postgres_protocol::types::int8_from_sql(self.input)
                    .map_err(|e| Error::Type(format!("not i64: {e}")))?,
            )
        } else {
            Err(Error::Type(format!(
                "expecting i64, found {}",
                self.element_type
            )))
        }
    }

    fn deserialize_u8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_u16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_u32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_u64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_str<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if *self.element_type == Type::TEXT {
            visitor.visit_string(
                postgres_protocol::types::text_from_sql(self.input)
                    .map_err(|e| Error::Type(format!("not UTF-8 string: {e}")))?
                    .to_owned(),
            )
        } else {
            Err(Error::Type(format!(
                "expecting String, found {}",
                self.element_type
            )))
        }
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Unsupported)
    }
}
