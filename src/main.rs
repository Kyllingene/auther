use std::{           
    fs::read_to_string,path::Path,
                      process::exit
                    
                    
                    
                    };

// use auther_lib::*;
use dirs::home_dir;
use sarge::*;

fn get_passfile(parser: &ArgumentParser) -> String {
    let config = if let Some(arg) = get_arg!(parser, long, "config") {
        read_to_string(
            arg.val
                .clone()
                .map(ArgValue::get_str)
                .unwrap_or(String::new()),
        )
        .unwrap_or("".to_string())
    } else {
        String::new()
    }
    .lines()
    .next()
    .map(str::to_string);

    let filename;
    if let Some(ArgValue::String(f)) = get_val!(parser, both, 'f', "file") {
        println!("{f}");
        filename = f;
    } else if Path::new("auther.toml").exists() {
        filename = String::from("auther.toml");
    } else if let Some(path) = config {
        filename = path;
    } else {
        let mut path = home_dir().unwrap_or_else(|| {
            eprintln!("error: failed to get home directory");
            exit(1);
        });
        path.push("auther.toml");

        filename = path.display().to_string();
    }

    filename
}

fn main() {
    let mut parser = ArgumentParser::new();
    parser.add(arg!(flag, both, 'h', "help"));
    parser.add(arg!(str, both, 'n', "new"));
    parser.add(arg!(str, both, 'c', "complete"));
    parser.add(arg!(flag, both, 'l', "list"));
    parser.add(arg!(str, both, 'f', "file"));
    parser.add(arg!(str, long, "config"));

    let remainder = match parser.parse() {
        Err(e) => {
            eprintln!("error (while parsing arguments): {e}");
            exit(1);
        }
        Ok(r) => r,
    };

    let _key = remainder.get(0).unwrap_or_else(|| {
        eprintln!("error: must pass a key");
        exit(1);
    });

    if get_flag!(parser, both, 'h', "help") {
        println!(
            "{} [options]\n\
        \x20     --help / -h        : prints this help message\n\
        \x20      --new / -n <todo> : creates a new todo, with the given text\n\
        \x20                          parses all metadata tags\n\
        \x20 --complete / -c <todo> : completes the todo, specified by the given text\n\
        \x20                          if no todo matches the text, looks for a todo with\n\
        \x20                          that id (using the `id:` tag)\n\
        \x20     --list / -l        : prints this help message\n\
        \x20   --config      <file> : specifies the config file\n\
        \x20                          defaults to ~/.todo-cfg.txt\n\
        \x20  --project      <tag>  : filters by project tag\n\
        \x20  --context      <tag>  : filters by context tag\n\
        \x20  --archive / -a        : archives completed tasks\n\
        \x20                          default archive file is source + .archive\n\
        \x20     --file / -f <file> : specifies the source file\n\
        \x20                          if todo.txt exists in the current directory,\n\
        \x20                          defaults to that; otherwise, defaults to config\n\
        \n\
        Config is minimal for now, consisting of just one line defining\n\
        the default password file.\n\
        ",
            parser.binary.unwrap_or("todo".to_string())
        );

        exit(0);
    }

    let _passfile = get_passfile(&parser);
}
