use crate::IndexedSet;

#[derive(Default)]
pub struct Tag {
    pub id: u32,
    pub name: String,
}

pub struct TagSet<'a> {
    set: IndexedSet<'a>, // will be needed when we implement write operations
    tags: Vec<Tag>,
}

impl<'a> TagSet<'a> {
    pub(crate) fn new(set: IndexedSet<'a>) -> anyhow::Result<Self> {
        use anyhow::Context;

        let index = set.index()?;
        let mut tags = Vec::new();
        for (id, name) in index.iter() {
            tags.push(Tag {
                id,
                name: String::from_utf8(name.to_vec()).context("invalid data")?,
            });
        }
        Ok(Self { set, tags })
    }

    /// Inserts a new tag into the set, returning its ID.
    ///
    /// # Errors
    ///
    /// Returns an error if any database operation fails.
    pub fn insert(&mut self, name: &str) -> anyhow::Result<u32> {
        // TODO: Reject a duplicate name. Not implemented yet, because it
        // requires searching the name in the set. We need to convert the format
        // so that keys are stored as actual RocksDB keys.
        self.set.insert(name.as_bytes())
    }

    /// Removes a tag from the set, returning its name.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is invalid or any database operation fails.
    pub fn remove(&mut self, id: u32) -> anyhow::Result<String> {
        let key = self.set.remove(id)?;
        let name = String::from_utf8(key)?;
        Ok(name)
    }

    /// Updates an old tag name to a new one for the given ID.
    ///
    /// It returns `true` if the name was updated successfully, and `false` if
    /// the old name was different from what was stored or not found.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is invalid or any database operation fails.
    pub fn update(&mut self, id: u32, old: &str, new: &str) -> anyhow::Result<bool> {
        self.set.update(id, old.as_bytes(), new.as_bytes())
    }

    /// Returns an iterator over the tags in the set.
    pub fn tags(&self) -> Tags {
        Tags {
            tags: self.tags.as_slice(),
            index: 0,
        }
    }
}

/// An iterator over the tags in a `TagSet`.
pub struct Tags<'a> {
    tags: &'a [Tag],
    index: usize,
}

impl<'a> Iterator for Tags<'a> {
    type Item = &'a Tag;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.tags.len() {
            let tag = &self.tags[self.index];
            self.index += 1;
            Some(tag)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TagSet;
    use crate::test;

    #[test]
    fn tag_set() {
        let db = test::Store::new();
        let set = db.indexed_set();
        let mut tag_set = TagSet::new(set).unwrap();

        let id = tag_set.insert("tag1").unwrap();
        assert_eq!(id, 0);
        let id = tag_set.insert("tag2").unwrap();
        assert_eq!(id, 1);
        let id = tag_set.insert("tag3").unwrap();
        assert_eq!(id, 2);

        assert!(tag_set.remove(5).is_err());
        let removed_name = tag_set.remove(1).unwrap();
        assert_eq!(removed_name, "tag2");
        assert!(tag_set.remove(1).is_err());

        let updated = tag_set.update(2, "tag3", "tag3.1").unwrap();
        assert_eq!(updated, true);
        let updated = tag_set.update(2, "tag3", "tag3.2").unwrap();
        assert_eq!(updated, false);
        let updated = tag_set.update(2, "tag5", "tag5.1").unwrap();
        assert_eq!(updated, false);
    }
}
