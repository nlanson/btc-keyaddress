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