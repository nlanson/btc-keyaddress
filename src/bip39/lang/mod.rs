pub mod en;

pub enum Language {
    English
}

impl Language {
    pub fn word_list(&self) -> [&str; 2048] {
        match self {
            Language::English => en::WORDS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Language;

    #[test]
    fn en_word_list_is_2048() {
        //Tests if the word list consists of 2048 words.
        assert_eq!(2048, Language::English.word_list().len());
    }
}