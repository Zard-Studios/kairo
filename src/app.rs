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
    
    // Key detection error message
    key_detect_error: Option<String>,
    
    // Progress
    progress: Arc<Mutex<Progress>>,
    status: Arc<Mutex<Status>>,
}

#[derive(Clone)]
pub struct Progress {
    pub percent: f32,
    pub message: String,
    pub start_time: Option<std::time::Instant>,
    pub files_extracted: usize,
    pub total_files: usize,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            percent: 0.0,
            message: String::new(),
            start_time: None,
            files_extracted: 0,
            total_files: 0,
        }
    }
}

impl KairoApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = AppConfig::load();
        
        let app = Self {
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
            key_detect_error: None,
            progress: Arc::new(Mutex::new(Progress::default())),
            status: Arc::new(Mutex::new(Status::Idle)),
        };
        
        app
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
    
    /// Try to automatically look up the disc key based on the WUD's product code or Title ID
    fn try_auto_lookup_key(&mut self, path: &PathBuf) {
        use std::io::{Read, Seek, SeekFrom};
        
        if let Ok(mut file) = std::fs::File::open(path) {
            let mut buffer = vec![0u8; 65536]; // Read 64KB for deeper scan
            // We use read (not read_exact) because file might be smaller than 64KB (unlikely for WUD but possible for test files)
            if let Ok(bytes_read) = file.read(&mut buffer) {
                let buffer = &buffer[..bytes_read];
                // Try Product Code first
                if let Some(code) = crate::disc_keys::extract_product_code(&buffer) {
                    println!("Detected product code: {}", code);
                    
                    // Display info
                    if let Some(name) = crate::disc_keys::get_game_name(&code) {
                        let region = crate::disc_keys::get_region(&code);
                         println!("🔑 Auto-detected: {} [{}]", name, region);
                    }
                    
                    if let Some(key) = crate::disc_keys::lookup_disc_key(&code) {
                        println!("   Found key in DB!");
                        println!("   Disc Key: {}", key);
                        self.title_key_hex = key;
                        self.use_title_hex = true;
                        self.title_key_path = None;
                        return;
                    }
                    

                }
                
                // Try Title ID (Heuristic - Check all candidates)
                let candidates = crate::disc_keys::extract_title_candidates(&buffer);
                let mut found_tid = false;
                
                if !candidates.is_empty() {
                    println!("Detected Title ID candidates: {:?}", candidates);
                    for tid in candidates {
                        if let Some(key) = crate::disc_keys::lookup_by_title_id(&tid) {
                            println!("   Found key in DB via Title ID: {}", tid);
                            println!("   Disc Key: {}", key);
                            
                            self.title_key_hex = key;
                            self.use_title_hex = true;
                            self.title_key_path = None;
                            
                            // If we haven't detected name via product code, maybe we can? 
                            // Current DB doesn't store names, but at least we have the key.
                            found_tid = true;
                            break;
                        }
                    }
                    
                    if !found_tid {
                         println!("⚠️ No key found for any Title ID candidate.");
                    }
                } else {
                    println!("⚠️ No Title ID candidates found in header.");
                }
                
                if found_tid {
                    return;
                }
                
                // Try Product Code again just to show error if not found by either
                 if let Some(code) = crate::disc_keys::extract_product_code(&buffer) {
                    println!("⚠️ No disc key found for product code: {}", code);
                    println!("   You'll need to provide the key manually.");
                 }
            }
        }
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
        
        // Set running status and start time
        {
            let mut s = status.lock().unwrap();
            *s = Status::Running;
        }
        {
            let mut p = progress.lock().unwrap();
            p.start_time = Some(std::time::Instant::now());
            p.percent = 0.0;
            p.message = "Starting...".to_string();
            p.files_extracted = 0;
            p.total_files = 0;
        }
        
        let output_dir = output.clone();
        
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
                            
                            // Set start time if not set
                            {
                                let mut p = progress_clone.lock().unwrap();
                                if p.start_time.is_none() {
                                    p.start_time = Some(std::time::Instant::now());
                                }
                            }
                            
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
                                    // Extract file count from message if possible
                                    if msg.starts_with("Extracting:") {
                                        p.files_extracted += 1;
                                    }
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
                Ok(()) => {
                    // Open output folder on success
                    #[cfg(target_os = "macos")]
                    {
                        let _ = std::process::Command::new("open")
                            .arg(&output_dir)
                            .spawn();
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let _ = std::process::Command::new("explorer")
                            .arg(&output_dir)
                            .spawn();
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let _ = std::process::Command::new("xdg-open")
                            .arg(&output_dir)
                            .spawn();
                    }
                    Status::Success("Operation completed!".to_string())
                }
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
                    if let Some(path) = self.pick_file(&["wux", "wud"]) {
                        self.input_path = Some(path.clone());
                        self.try_auto_lookup_key(&path);
                        self.save_config();
                    }
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
                ui.label("Disc key:");
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
                
                // Detect button
                if ui.button("🔍 Detect").clicked() {
                    if let Some(path) = &self.input_path.clone() {
                        self.key_detect_error = None;
                        let old_key = self.title_key_hex.clone();
                        self.try_auto_lookup_key(path);
                        // Check if key was found
                        if self.title_key_hex == old_key || self.title_key_hex.is_empty() {
                            self.key_detect_error = Some("No disc key found for this game. Try updating keys first.".to_string());
                        } else {
                            self.key_detect_error = None;
                        }
                    } else {
                        self.key_detect_error = Some("Select a WUD file first".to_string());
                    }
                }
            });
            
            // Show detection error if any
            if let Some(err) = &self.key_detect_error {
                ui.colored_label(egui::Color32::RED, format!("⚠️ {}", err));
            }
            
            ui.add_space(5.0);
            
            // Dynamic Key Fetching
            ui.horizontal(|ui| {
                if ui.button("⬇️ Update Keys from Web").clicked() {
                     let status = Arc::clone(&self.status);
                     let progress = Arc::clone(&self.progress);
                     
                     // Run in background to avoid freezing UI
                     thread::spawn(move || {
                         {
                             let mut s = status.lock().unwrap();
                             *s = Status::Running;
                             let mut p = progress.lock().unwrap();
                             p.message = "Fetching keys from web...".to_string();
                             p.percent = 0.0;
                         }
                         
                         match crate::disc_keys::update_keys() {
                             Ok(count) => {
                                 thread::sleep(std::time::Duration::from_millis(500)); // Show message briefly
                                 let mut s = status.lock().unwrap();
                                 *s = Status::Success(format!("Fetched {} new keys!", count));
                             }
                             Err(e) => {
                                 let mut s = status.lock().unwrap();
                                 *s = Status::Error(format!("Key update failed: {}", e));
                             }
                         }
                     });
                }
                ui.label(egui::RichText::new("Fetches latest keys from community DBs").small().italics());
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
                    // Calculate elapsed time
                    let elapsed_str = if let Some(start) = progress.start_time {
                        let elapsed = start.elapsed();
                        let secs = elapsed.as_secs();
                        let mins = secs / 60;
                        let hours = mins / 60;
                        if hours > 0 {
                            format!("{:02}:{:02}:{:02}", hours, mins % 60, secs % 60)
                        } else {
                            format!("{:02}:{:02}", mins, secs % 60)
                        }
                    } else {
                        "00:00".to_string()
                    };
                    
                    // Calculate ETA
                    let eta_str = if progress.percent > 0.01 {
                        if let Some(start) = progress.start_time {
                            let elapsed = start.elapsed().as_secs_f64();
                            let total_estimated = elapsed / progress.percent as f64;
                            let remaining = (total_estimated - elapsed).max(0.0) as u64;
                            let mins = remaining / 60;
                            let hours = mins / 60;
                            if hours > 0 {
                                format!("{:02}:{:02}:{:02}", hours, mins % 60, remaining % 60)
                            } else {
                                format!("{:02}:{:02}", mins, remaining % 60)
                            }
                        } else {
                            "--:--".to_string()
                        }
                    } else {
                        "--:--".to_string()
                    };
                    
                    // Progress bar with percentage (no animation)
                    let percent_text = format!("{:.1}%", progress.percent * 100.0);
                    ui.add(egui::ProgressBar::new(progress.percent)
                        .text(&percent_text));
                    
                    // Time info row
                    ui.horizontal(|ui| {
                        ui.label(format!("⏱ Elapsed: {}", elapsed_str));
                        ui.separator();
                        ui.label(format!("⏳ ETA: {}", eta_str));
                        if progress.total_files > 0 {
                            ui.separator();
                            ui.label(format!("📁 {}/{} files", progress.files_extracted, progress.total_files));
                        }
                    });
                    
                    // Current operation message
                    if !progress.message.is_empty() {
                        ui.label(egui::RichText::new(&progress.message).color(egui::Color32::GRAY).small());
                    }
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
