use curv::arithmetic::*;
use std::borrow::Borrow;
use std::{fmt};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize};
use serde::de::{MapAccess, Visitor};
use super::*;

impl Serialize for PrecomputeTable {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut table = Vec::new();
        for row in &self.table {
            let mut row_ser = Vec::new();
            for item in row {
                row_ser.push(item.to_str_radix(16));
            }
            table.push(row_ser);
        }

        let mut state = serializer.serialize_struct("PrecomputeTable", 4)?;
        state.serialize_field("block_size", &self.block_size)?;
        state.serialize_field("pow_size", &self.pow_size)?;
        state.serialize_field("modulo", &self.modulo.to_str_radix(16))?;
        state.serialize_field("table", &table)?;
        state.end()
    }

}

impl<'de> Deserialize<'de> for PrecomputeTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,  // This line still uses the 'de lifetime
    {
        struct PrecomputeTableVisitor;

        impl<'de> Visitor<'de> for PrecomputeTableVisitor {
            type Value = PrecomputeTable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct PrecomputeTable")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut block_size = None;
                let mut pow_size = None;
                let mut modulo = None;
                let mut table = None;

                while let Some(key) = map.next_key()? {
                    println!("key: {}", key);
                    match key {
                        "block_size" => {
                            if block_size.is_some() {
                                return Err(serde::de::Error::duplicate_field("block_size"));
                            }
                            block_size = Some(map.next_value()?);
                        }
                        "pow_size" => {
                            if pow_size.is_some() {
                                return Err(serde::de::Error::duplicate_field("pow_size"));
                            }
                            pow_size = Some(map.next_value()?);
                        }
                        "modulo" => {
                            if modulo.is_some() {
                                return Err(serde::de::Error::duplicate_field("modulo"));
                            }
                            let modulo_str = map.next_value::<String>()?;
                            modulo = Some(BigInt::from_str_radix(&modulo_str, 16).unwrap());
                        }
                        "table" => {
                            if table.is_some() {
                                return Err(serde::de::Error::duplicate_field("table"));
                            }
                            let table_str: Vec<Vec<String>> = map.next_value()?;
                            let mut table_vec = Vec::new();
                            for row in table_str {
                                let mut row_vec = Vec::new();
                                for item in row {
                                    row_vec.push(BigInt::from_str_radix(&item, 16).unwrap());
                                }
                                table_vec.push(row_vec);
                            }
                            table = Some(table_vec);
                        }
                        _ => {
                            println!("not matched");
                            return Err(serde::de::Error::unknown_field(key, &["block_size", "pow_size", "modulo", "table"]));
                        }
                    }
                }

                let block_size = block_size.ok_or_else(|| serde::de::Error::missing_field("block_size"))?;
                let pow_size = pow_size.ok_or_else(|| serde::de::Error::missing_field("pow_size"))?;
                let modulo = modulo.ok_or_else(|| serde::de::Error::missing_field("modulo"))?;
                let table = table.ok_or_else(|| serde::de::Error::missing_field("table"))?;

                Ok(PrecomputeTable {
                    block_size,
                    pow_size,
                    modulo,
                    table,
                })
            }
        }

        deserializer.deserialize_map(PrecomputeTableVisitor)
    }
}
