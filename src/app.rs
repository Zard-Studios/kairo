//! Main application state and UI

use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use serde::{Deserialize, Serialize};
use directories::ProjectDirs;

// Note: crate::keys and crate::wux are unused - using external wux crate

/// Configuration persisted to disk
#[derive(Default, Serialize, Deserialize)]
struct AppConfig {
    input_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    common_key_path: Option<PathBuf>,
    common_key_hex: String,
    title_key_path: Option<PathBuf>,
    title_key_hex: String,
}

impl AppConfig {
    fn load() -> Self {
        if let Some(proj_dirs) = ProjectDirs::from("com", "zardstudios", "kairo") {
            let config_path = proj_dirs.config_dir().join("config.json");
            if let Ok(file) = std::fs::File::open(config_path) {
                if let Ok(config) = serde_json::from_reader(file) {
                    return config;
                }
            }
        }
        Self::default()
    }

    fn save(&self) {
        if let Some(proj_dirs) = ProjectDirs::from("com", "zardstudios", "kairo") {
            let config_dir = proj_dirs.config_dir();
            if std::fs::create_dir_all(config_dir).is_ok() {
                let config_path = config_dir.join("config.json");
                if let Ok(file) = std::fs::File::create(config_path) {
                    let _ = serde_json::to_writer_pretty(file, self);
                }
            }
        }
    }
}

/// Operation mode
#[derive(Default, Clone, Copy, PartialEq)]
pub enum Operation {
    #[default]
    ConvertToWud,
    ExtractToWup,
}

/// Operation status
#[derive(Default, Clone, PartialEq)]
pub enum Status {
    #[default]
    Idle,
    Running,
    Success(String),
    Error(String),
}

/// Application state
pub struct KairoApp {
    // File paths
    input_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    
    // Keys
    common_key_path: Option<PathBuf>,
    common_key_hex: String,
    use_common_hex: bool,
    title_key_path: Option<PathBuf>,
    title_key_hex: String,
    use_title_hex: bool,
    
    // Options
    operation: Operation,
    verify_hashes: bool,
    
    // Progress
    progress: Arc<Mutex<Progress>>,
    status: Arc<Mutex<Status>>,
}

#[derive(Default, Clone)]
pub struct Progress {
    pub percent: f32,
    pub message: String,
}

impl KairoApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = AppConfig::load();
        
        Self {
            input_path: config.input_path,
            output_path: config.output_path,
            common_key_path: config.common_key_path,
            common_key_hex: config.common_key_hex.clone(),
            use_common_hex: !config.common_key_hex.is_empty(),
            title_key_path: config.title_key_path,
            title_key_hex: config.title_key_hex.clone(),
            use_title_hex: !config.title_key_hex.is_empty(),
            operation: Operation::default(),
            verify_hashes: true,
            progress: Arc::new(Mutex::new(Progress::default())),
            status: Arc::new(Mutex::new(Status::Idle)),
        }
    }
    
    fn save_config(&self) {
        let config = AppConfig {
            input_path: self.input_path.clone(),
            output_path: self.output_path.clone(),
            common_key_path: self.common_key_path.clone(),
            common_key_hex: self.common_key_hex.clone(),
            title_key_path: self.title_key_path.clone(),
            title_key_hex: self.title_key_hex.clone(),
        };
        config.save();
    }
    
    fn pick_file(&self, filter: &[&str]) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .add_filter("Wii U Images", filter)
            .pick_file()
    }
    
    fn pick_folder(&self) -> Option<PathBuf> {
        rfd::FileDialog::new().pick_folder()
    }
    
    fn pick_key_file(&self) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .add_filter("Key files", &["key", "bin"])
            .pick_file()
    }
    
    fn can_start(&self) -> bool {
        let status = self.status.lock().unwrap();
        if *status == Status::Running {
            return false;
        }
        drop(status);
        
        // Basic checks
        let has_input = self.input_path.is_some();
        let has_output = self.output_path.is_some();
        
        if !has_input || !has_output {
            return false;
        }
        
        // Validation must pass
        if self.validate_input().is_some() {
            return false;
        }
        
        // For convert operation, no keys needed
        if self.operation == Operation::ConvertToWud {
            return true;
        }
        
        // For extract, need keys
        let has_common = self.common_key_path.is_some() || self.common_key_hex.len() == 32;
        let has_title = self.title_key_path.is_some() || self.title_key_hex.len() == 32;
        
        has_common && has_title
    }
    
    /// Validate input file and return error message if invalid
    fn validate_input(&self) -> Option<String> {
        let input = self.input_path.as_ref()?;
        
        // Check file exists
        if !input.exists() {
            return Some(format!("File not found: {}", input.display()));
        }
        
        // Check file size
        if let Ok(metadata) = std::fs::metadata(input) {
            if metadata.len() == 0 {
                return Some("Input file is empty (0 bytes)".to_string());
            }
        } else {
            return Some("Cannot read file metadata".to_string());
        }
        
        // Check extension matches operation
        let ext = input.extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        
        match self.operation {
            Operation::ConvertToWud => {
                if ext != "wux" {
                    return Some(format!(
                        "Wrong file type for WUX→WUD conversion!\nExpected: .wux\nGot: .{}\n\nDid you mean to use 'Extract WUD → WUP'?",
                        ext
                    ));
                }
            }
            Operation::ExtractToWup => {
                if ext != "wud" {
                    if ext == "wux" {
                        return Some(
                            "Cannot extract .wux directly!\n\nFirst convert WUX→WUD, then extract.".to_string()
                        );
                    }
                    return Some(format!(
                        "Wrong file type for WUD→WUP extraction!\nExpected: .wud\nGot: .{}",
                        ext
                    ));
                }
            }
        }
        
        None // All good!
    }
    
    fn start_operation(&self) {
        let input = self.input_path.clone().unwrap();
        let output = self.output_path.clone().unwrap();
        let operation = self.operation;
        let progress = Arc::clone(&self.progress);
        let status = Arc::clone(&self.status);
        
        // Clone keys for the thread
        let common_key_hex = self.common_key_hex.clone();
        let title_key_hex = self.title_key_hex.clone();
        
        // Set running status
        {
            let mut s = status.lock().unwrap();
            *s = Status::Running;
        }
        
        thread::spawn(move || {
            let result = match operation {
                Operation::ConvertToWud => {
                    // WUX -> WUD conversion using external wux crate
                    let output_path = if output.is_dir() {
                        let name = input.file_stem().unwrap_or_default();
                        output.join(format!("{}.wud", name.to_string_lossy()))
                    } else {
                        output
                    };
                    
                    // Open files
                    let input_file = std::fs::File::open(&input);
                    let output_file = std::fs::File::create(&output_path);
                    
                    match (input_file, output_file) {
                        (Ok(mut reader), Ok(mut writer)) => {
                            let progress_clone = Arc::clone(&progress);
                            
                            ::wux::decompress_with_progress(
                                &mut reader,
                                &mut writer,
                                |wux_progress| {
                                    let mut p = progress_clone.lock().unwrap();
                                    p.percent = wux_progress.bytes_processed as f32 / wux_progress.total_bytes as f32;
                                    let mb_done = wux_progress.bytes_processed / 1_000_000;
                                    let mb_total = wux_progress.total_bytes / 1_000_000;
                                    p.message = format!("{} MB / {} MB", mb_done, mb_total);
                                },
                            ).map_err(|e| crate::error::KairoError::Io(
                                std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))
                            ))
                        }
                        (Err(e), _) => Err(crate::error::KairoError::Io(e)),
                        (_, Err(e)) => Err(crate::error::KairoError::Io(e)),
                    }
                }
                Operation::ExtractToWup => {
                    // WUD -> WUP extraction
                    // Parse keys from hex or load from files
                    let common_key = parse_hex_key(&common_key_hex);
                    let title_key = parse_hex_key(&title_key_hex);
                    
                    match (common_key, title_key) {
                        (Some(ck), Some(tk)) => {
                            let progress_clone = Arc::clone(&progress);
                            let progress_cb: crate::wup::ProgressCallback = Arc::new(Mutex::new(
                                move |percent: f32, msg: &str| {
                                    let mut p = progress_clone.lock().unwrap();
                                    p.percent = percent;
                                    p.message = msg.to_string();
                                }
                            ));
                            
                            let options = crate::wup::ExtractOptions {
                                wud_path: &input,
                                output_dir: &output,
                                common_key: &ck,
                                title_key: &tk,
                                progress: Some(progress_cb),
                            };
                            
                            crate::wup::extract_wud_to_wup(&options)
                        }
                        _ => {
                            Err(crate::error::KairoError::InvalidKey(
                                "Invalid key format".to_string()
                            ))
                        }
                    }
                }
            };
            
            // Update status
            let mut s = status.lock().unwrap();
            *s = match result {
                Ok(()) => Status::Success("Operation completed!".to_string()),
                Err(e) => Status::Error(format!("{}", e)),
            };
        });
    }
    
    fn is_running(&self) -> bool {
        let status = self.status.lock().unwrap();
        *status == Status::Running
    }
}

/// Parse a 32-character hex string into a 16-byte key
fn parse_hex_key(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    
    let mut key = [0u8; 16];
    for i in 0..16 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        key[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(key)
}

impl eframe::App for KairoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint while running
        if self.is_running() {
            ctx.request_repaint();
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🎮 KAIRO");
            ui.label("Wii U Disc Image Tool");
            ui.separator();
            
            // Input file
            ui.horizontal(|ui| {
                ui.label("Input:");
                let text = self.input_path
                    .as_ref()
                    .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                    .unwrap_or_else(|| "Select file...".into());
                ui.label(&text);
                if ui.button("📁 Browse").clicked() {
                    self.input_path = self.pick_file(&["wux", "wud"]);
                    self.save_config();
                }
            });
            
            // Output path
            ui.horizontal(|ui| {
                ui.label("Output:");
                let text = self.output_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Select folder...".into());
                ui.label(&text);
                if ui.button("📁 Browse").clicked() {
                    self.output_path = self.pick_folder();
                    self.save_config();
                }
            });
            
            ui.separator();
            ui.label("🔑 Keys");
            
            // Common key
            ui.horizontal(|ui| {
                ui.label("Common:");
                if self.use_common_hex {
                    if ui.add(egui::TextEdit::singleline(&mut self.common_key_hex)
                        .hint_text("32 hex chars (e.g. D7B0...)")
                        .desired_width(250.0)).changed() {
                            self.save_config();
                        }
                    let valid = self.common_key_hex.len() == 32;
                    ui.label(if valid { "✅" } else { "❌" });
                } else {
                    let status = if self.common_key_path.is_some() { "✅" } else { "❌" };
                    ui.label(status);
                    if let Some(path) = &self.common_key_path {
                        ui.label(path.file_name().unwrap_or_default().to_string_lossy());
                    }
                    if ui.button("Browse").clicked() {
                        self.common_key_path = self.pick_key_file();
                        self.save_config();
                    }
                }
                if ui.button(if self.use_common_hex { "📄 File" } else { "🔢 Hex" }).clicked() {
                    self.use_common_hex = !self.use_common_hex;
                }
            });
            
            // Title key
            ui.horizontal(|ui| {
                ui.label("Title:");
                if self.use_title_hex {
                    if ui.add(egui::TextEdit::singleline(&mut self.title_key_hex)
                        .hint_text("32 hex chars")
                        .desired_width(250.0)).changed() {
                            self.save_config();
                        }
                    let valid = self.title_key_hex.len() == 32;
                    ui.label(if valid { "✅" } else { "❌" });
                } else {
                    let status = if self.title_key_path.is_some() { "✅" } else { "❌" };
                    ui.label(status);
                    if let Some(path) = &self.title_key_path {
                        ui.label(path.file_name().unwrap_or_default().to_string_lossy());
                    }
                    if ui.button("Browse").clicked() {
                        self.title_key_path = self.pick_key_file();
                        self.save_config();
                    }
                }
                if ui.button(if self.use_title_hex { "📄 File" } else { "🔢 Hex" }).clicked() {
                    self.use_title_hex = !self.use_title_hex;
                }
            });
            
            ui.separator();
            ui.label("⚙️ Operation");
            
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.operation, Operation::ConvertToWud, "Convert WUX → WUD");
                ui.radio_value(&mut self.operation, Operation::ExtractToWup, "Extract WUD → WUP");
            });
            
            if self.operation == Operation::ExtractToWup {
                ui.checkbox(&mut self.verify_hashes, "Verify SHA-1 hashes");
            }
            
            ui.separator();
            
            // Progress & Status
            let progress = self.progress.lock().unwrap().clone();
            let status = self.status.lock().unwrap().clone();
            
            match &status {
                Status::Running => {
                    ui.add(egui::ProgressBar::new(progress.percent)
                        .text(&progress.message)
                        .animate(true));
                }
                Status::Success(msg) => {
                    ui.colored_label(egui::Color32::GREEN, format!("✅ {}", msg));
                }
                Status::Error(msg) => {
                    ui.colored_label(egui::Color32::RED, format!("❌ {}", msg));
                }
                Status::Idle => {
                    // Show validation errors if any
                    if let Some(error) = self.validate_input() {
                        ui.colored_label(egui::Color32::from_rgb(255, 165, 0), format!("⚠️ {}", error));
                    }
                }
            }
            
            ui.add_space(10.0);
            
            // Buttons
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_start = self.can_start();
                    if ui.add_enabled(can_start, egui::Button::new("▶ Start")).clicked() {
                        self.save_config(); // Save also on start to be sure
                        self.start_operation();
                    }
                    
                    if self.is_running() {
                        if ui.button("⏹ Cancel").clicked() {
                            // TODO: Implement cancellation
                            let mut s = self.status.lock().unwrap();
                            *s = Status::Error("Cancelled".to_string());
                        }
                    }
                });
            });
        });
    }
}
