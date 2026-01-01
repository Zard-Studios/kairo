//! Main application state and UI

use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::keys;
use crate::wux;

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
    title_key_path: Option<PathBuf>,
    title_key_hex: String,
    use_hex_key: bool,
    
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
        Self {
            input_path: None,
            output_path: None,
            common_key_path: None,
            title_key_path: None,
            title_key_hex: String::new(),
            use_hex_key: false,
            operation: Operation::default(),
            verify_hashes: true,
            progress: Arc::new(Mutex::new(Progress::default())),
            status: Arc::new(Mutex::new(Status::Idle)),
        }
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
        
        let has_input = self.input_path.is_some();
        let has_output = self.output_path.is_some();
        
        // For convert operation, no keys needed
        if self.operation == Operation::ConvertToWud {
            return has_input && has_output;
        }
        
        // For extract, need keys
        let has_common = self.common_key_path.is_some();
        let has_title = self.title_key_path.is_some() || self.title_key_hex.len() == 32;
        
        has_input && has_output && has_common && has_title
    }
    
    fn start_operation(&self) {
        let input = self.input_path.clone().unwrap();
        let output = self.output_path.clone().unwrap();
        let operation = self.operation;
        let progress = Arc::clone(&self.progress);
        let status = Arc::clone(&self.status);
        
        // Set running status
        {
            let mut s = status.lock().unwrap();
            *s = Status::Running;
        }
        
        thread::spawn(move || {
            let result = match operation {
                Operation::ConvertToWud => {
                    // WUX -> WUD conversion
                    let output_file = if output.is_dir() {
                        let name = input.file_stem().unwrap_or_default();
                        output.join(format!("{}.wud", name.to_string_lossy()))
                    } else {
                        output
                    };
                    
                    let progress_clone = Arc::clone(&progress);
                    wux::decompress_wux(
                        &input,
                        &output_file,
                        Some(Box::new(move |percent, msg| {
                            let mut p = progress_clone.lock().unwrap();
                            p.percent = percent;
                            p.message = msg.to_string();
                        })),
                    )
                }
                Operation::ExtractToWup => {
                    // WUD -> WUP extraction
                    // TODO: Implement full extraction
                    let mut p = progress.lock().unwrap();
                    p.percent = 1.0;
                    p.message = "WUP extraction not yet implemented".to_string();
                    Ok(())
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
                }
            });
            
            ui.separator();
            ui.label("🔑 Keys");
            
            // Common key
            ui.horizontal(|ui| {
                ui.label("Common:");
                let status = if self.common_key_path.is_some() { "✅" } else { "❌" };
                ui.label(status);
                if let Some(path) = &self.common_key_path {
                    ui.label(path.file_name().unwrap_or_default().to_string_lossy());
                }
                if ui.button("Browse").clicked() {
                    self.common_key_path = self.pick_key_file();
                }
            });
            
            // Title key
            ui.horizontal(|ui| {
                ui.label("Title:");
                if self.use_hex_key {
                    ui.add(egui::TextEdit::singleline(&mut self.title_key_hex)
                        .hint_text("32 hex characters")
                        .desired_width(250.0));
                } else {
                    let status = if self.title_key_path.is_some() { "✅" } else { "❌" };
                    ui.label(status);
                    if let Some(path) = &self.title_key_path {
                        ui.label(path.file_name().unwrap_or_default().to_string_lossy());
                    }
                    if ui.button("Browse").clicked() {
                        self.title_key_path = self.pick_key_file();
                    }
                }
                if ui.button(if self.use_hex_key { "📄 File" } else { "🔢 Hex" }).clicked() {
                    self.use_hex_key = !self.use_hex_key;
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
                Status::Idle => {}
            }
            
            ui.add_space(10.0);
            
            // Buttons
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_start = self.can_start();
                    if ui.add_enabled(can_start, egui::Button::new("▶ Start")).clicked() {
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
