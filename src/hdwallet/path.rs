/*  
    This module helps with parsing deriveration paths passed in as strings
    as vectors of ChildOptions that can be used to derive a child key.
*/

use crate::{
    hdwallet::{
        ChildOptions,
        HDWError
    }
};


#[derive(Clone)]
pub struct Path {
    pub children: Vec<ChildOptions>
}

impl Path {
    pub fn from_str(path: &str) -> Result<Self, HDWError> {
        let mut p: Vec<ChildOptions> = vec![];
        let mut children: Vec<&str> = path.split('/').map(|x| x).collect();
        if children[0] == "m" {
            children.remove(0);
        } else {
            return Err(HDWError::BadPath(path.to_string()))
        }

        for i in 0..children.len() {
            let option: ChildOptions = match children[i].parse() {
                //If the provided index can be parsed without errors, it will be a normal child
                Ok(x) => ChildOptions::Normal(x),

                //If the provided index cant be parsed, check if it can be parsed with the last char removed.
                //If this works, then it will be a hardened child. Else return an error.
                Err(_) => {
                    let hardened_index = &children[i][0..children[i].len()-1];
                    match hardened_index.parse() {
                        Ok(x) => ChildOptions::Hardened(x),
                        Err(_) => return Err(HDWError::BadPath("".to_string()))
                    }
                }
            };

            p.push(option);
        }

       
        Ok(Self {
            children: p
        })
    }

    pub fn to_string(&self) -> String {
        let mut path: Vec<String> = vec!["m".to_string()];
        for i in 0..self.children.len() {
            path.push (match self.children[i] {
                ChildOptions::Normal(x) => format!("{}", x),
                ChildOptions::Hardened(x) => format!("{}'", x)
            });

        }

        path.join("/")
    }

    pub fn empty() -> Self {
        Self {
            children: vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChildOptions,
        Path
    };

    #[test]
    fn path_test() {
        let path_str = "m/84'/0'/0'/0/0";
        let path_struct = Path {
            children: vec![
                ChildOptions::Hardened(84),
                ChildOptions::Hardened(0),
                ChildOptions::Hardened(0),
                ChildOptions::Normal(0),
                ChildOptions::Normal(0)
            ]
        };
    
        assert_eq!(path_str, path_struct.to_string());
    }   
}
