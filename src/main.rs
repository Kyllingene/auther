use std::fs::read_to_string;
use std::io::{Read, Write};
use std::{fs::File, path::Path, process::exit};

use auther_lib::{Data, PassManager, Passkey, Password};
use dirs::home_dir;
use eframe::egui;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
// use sarge::*;

fn get_passfile(/*parser: &ArgumentParser*/) -> String {
    // let config = if let Some(arg) = get_arg!(parser, long, "config") {
    //     read_to_string(
    //         arg.val
    //             .clone()
    //             .map(ArgValue::get_str)
    //             .unwrap_or(String::new()),
    //     )
    //     .unwrap_or("".to_string())
    // } else {
    //     String::new()
    // }
    // .lines()
    // .next()
    // .map(str::to_string);

    /*if let Some(ArgValue::String(f)) = get_val!(parser, both, 'f', "file") {
        println!("{f}");
        filename = f;
    } else */
    if Path::new("auther.toml").exists() {
        String::from("auther.toml")
    // } else if let Some(path) = config {
    //     filename = path;
    } else {
        let mut path = home_dir().unwrap_or_else(|| {
            eprintln!("error: failed to get home directory");
            exit(1);
        });
        path.push("auther.toml");

        path.display().to_string()
    }
}

fn decrypt(key: String, file: String) -> Result<String, &'static str> {
    let mc = new_magic_crypt!(key, 256);

    if let Ok(mut file) = File::open(file) {
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|_| "Failed to read file")?;

        let decrypted = mc
            .decrypt_bytes_to_bytes(&data)
            .map_err(|_| "Failed to decrypt data")?;
        Ok(String::from_utf8(decrypted).map_err(|_| "Failed to decrypt data")?)
    } else {
        Err("Failed to open file")
    }
}

fn encrypt(key: String, file: String, data: &PassManager) -> Result<(), &'static str> {
    let mc = new_magic_crypt!(key, 256);
    let encrypted = mc.encrypt_str_to_bytes(toml::to_string(data).unwrap());

    if let Ok(mut file) = File::create(file) {
        file.write_all(&encrypted)
            .map_err(|_| "Failed to write to file")?;
    } else {
        return Err("Failed to open file");
    }

    Ok(())
}

struct Passwords {
    passwords: PassManager,
    key: String,

    location: String,
    email: String,
    username: String,
    password: String,
    passkey: String,

    dec_passkey: String,

    save_error: Option<String>,
    read_error: Option<String>,
}

impl Default for Passwords {
    fn default() -> Self {
        Self {
            passwords: PassManager::new(),
            key: String::new(),

            location: String::new(),
            email: String::new(),
            username: String::new(),
            password: String::new(),
            passkey: String::new(),

            dec_passkey: String::new(),

            save_error: None,
            read_error: None,
        }
    }
}

impl eframe::App for Passwords {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label(egui::RichText::new("Auther").heading());
                ui.label(egui::RichText::new("Password Manager").italics());

                ui.separator();

                ui.label("New Password");
                ui.text_edit_singleline(&mut self.password);

                ui.label("Location");
                ui.text_edit_singleline(&mut self.location);

                ui.label("Email");
                ui.text_edit_singleline(&mut self.email);

                ui.label("Username");
                ui.text_edit_singleline(&mut self.username);

                ui.label("Encryption key (optional)");
                ui.text_edit_singleline(&mut self.passkey);

                if ui.button("Create").clicked() {
                    let pass = self.password.clone();
                    self.password.clear();

                    let location = self.location.clone();
                    self.location.clear();

                    let email = self.email.clone();
                    self.email.clear();

                    let username = self.username.clone();
                    self.username.clear();

                    let key = self.passkey.clone();
                    self.passkey.clear();

                    let mut data = Data {
                        location,
                        email: None,
                        username: None,
                    };

                    if !email.is_empty() {
                        data.email = Some(email);
                    }

                    if !username.is_empty() {
                        data.username = Some(username);
                    }

                    if key.is_empty() {
                        let mut pass = Password::plain(pass);
                        pass.add(data);

                        self.passwords.add_password(pass);
                    } else {
                        let mut pass = Password::new(Passkey::Plain(pass).encrypt(&key).unwrap());
                        pass.add(data);

                        self.passwords.add_password(pass);
                    }
                }

                ui.separator();

                ui.label("Passkey (to decrypt encrypted passwords)");
                ui.text_edit_singleline(&mut self.dec_passkey);

                ui.separator();

                ui.vertical(|ui| {
                    for password in self.passwords.passwords() {
                        for data in password.data() {
                            ui.label(format!("Location: {}", data.location));
                            if let Some(email) = data.email {
                                ui.label(format!("Email: {email}"));
                            }
                            if let Some(username) = data.username {
                                ui.label(format!("Username: {username}"));
                            }

                            ui.add_space(10.0);
                        }

                        if ui.label("Hover to reveal password").hovered() {
                            match password.pass {
                                Passkey::Plain(pass) => {
                                    ui.label(pass);
                                }
                                Passkey::Hash(..) => {
                                    ui.label("This password is hashed, can't be displayed");
                                }
                                Passkey::Encrypted(_) => {
                                    if self.dec_passkey.is_empty() {
                                        ui.label(
                                            "This password is encrypted, please provide the key",
                                        );
                                    }

                                    if let Some(Passkey::Plain(pass)) =
                                        password.pass.decrypt(&self.dec_passkey)
                                    {
                                        ui.label(pass);
                                    }
                                }
                            }
                        }

                        ui.separator();
                    }
                });

                ui.label("Encryption key");
                ui.text_edit_singleline(&mut self.key);

                if ui.button("Save to file").clicked() {
                    self.save_error = None;
                    let file = get_passfile();

                    if self.key.is_empty() {
                        match File::create(file) {
                            Ok(mut file) => match toml::to_string_pretty(&self.passwords) {
                                Ok(pass) => {
                                    match file.write_all(&pass.bytes().collect::<Vec<u8>>()) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            self.save_error = Some(e.to_string());
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.save_error = Some(e.to_string());
                                }
                            },
                            Err(e) => {
                                self.save_error = Some(e.to_string());
                            }
                        }
                    } else {
                        let key = self.key.clone();
                        match encrypt(key, file, &self.passwords) {
                            Ok(_) => {}
                            Err(e) => {
                                self.save_error = Some(e.to_owned());
                            }
                        }
                    }
                }

                if let Some(e) = self.save_error.clone() {
                    ui.label(e);
                }

                if ui.button("Read from file").clicked() {
                    self.read_error = None;
                    let file = get_passfile();
                    if self.key.is_empty() {
                        match read_to_string(file) {
                            Ok(p) => match PassManager::try_from(p) {
                                Ok(p) => {
                                    self.passwords = p;
                                }
                                Err(e) => {
                                    self.read_error = Some(e.to_string());
                                }
                            },
                            Err(e) => {
                                self.read_error = Some(e.to_string());
                            }
                        }
                    } else {
                        let key = self.key.clone();
                        match decrypt(key, file) {
                            Ok(decrypted) => match PassManager::try_from(decrypted) {
                                Ok(p) => {
                                    self.passwords = p;
                                }
                                Err(e) => {
                                    self.read_error = Some(e.to_string());
                                }
                            },
                            Err(e) => {
                                self.read_error = Some(e.to_owned());
                            }
                        }
                    }
                }

                if let Some(e) = self.read_error.clone() {
                    ui.label(e);
                }

                if ui.button("Quit").clicked() {
                    exit(0);
                }
            });
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    // let passfile = get_passfile(/*&parser*/);

    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(460.0, 320.0)),
        ..Default::default()
    };

    eframe::run_native(
        "Auther",
        options,
        Box::new(|_cc| Box::<Passwords>::default()),
    )
}
