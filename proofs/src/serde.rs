use base64::{decode, encode};
use hex::{FromHex, ToHex};

use ark_serialize::*;
use serde::{Deserialize, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

pub struct SerdeAsBytes;

impl<T> serde_with::SerializeAs<T> for SerdeAsBytes
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serde_with::Bytes::serialize_as(&bytes, serializer)
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAsBytes
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        T::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

pub struct SerdeAsBase64;

impl<T> serde_with::SerializeAs<T> for SerdeAsBase64
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(&encode(&bytes[..]))
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAsBase64
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        let bytes: Vec<u8> = decode(s).map_err(serde::de::Error::custom)?;
        T::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

pub struct SerdeAsHex;

impl<T> serde_with::SerializeAs<T> for SerdeAsHex
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(&bytes.encode_hex::<String>())
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAsHex
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        let bytes: Vec<u8> = Vec::<u8>::from_hex(s).map_err(serde::de::Error::custom)?;
        T::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}
