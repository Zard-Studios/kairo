//! Main application state and UI

use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Operation mode
#[derive(Default, Clone, Copy, PartialEq)]
pub enum Operation {
    #[default]
    ConvertToWud,
    ExtractToWup,
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
    is_running: bool,
}

#[derive(Default)]
pub struct Progress {
    pub percent: f32,
    pub message: String,
    pub speed: String,
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
            is_running: false,
        }
    }
    
    fn pick_file(&mut self, filter: &[&str]) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .add_filter("Wii U Images", filter)
            .pick_file()
    }
    
    fn pick_folder(&mut self) -> Option<PathBuf> {
        rfd::FileDialog::new().pick_folder()
    }
    
    fn pick_key_file(&mut self) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .add_filter("Key files", &["key", "bin"])
            .pick_file()
    }
    
    fn can_start(&self) -> bool {
        self.input_path.is_some() 
            && self.output_path.is_some()
            && self.common_key_path.is_some()
            && (self.title_key_path.is_some() || self.title_key_hex.len() == 32)
    }
}

impl eframe::App for KairoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("KAIRO");
            ui.separator();
            
            // Input file
            ui.horizontal(|ui| {
                ui.label("Input:");
                let text = self.input_path
                    .as_ref()
                    .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                    .unwrap_or_else(|| "Select file...".into());
                ui.label(&text);
                if ui.button("Browse").clicked() {
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
                if ui.button("Browse").clicked() {
                    self.output_path = self.pick_folder();
                }
            });
            
            ui.separator();
            ui.label("Keys");
            
            // Common key
            ui.horizontal(|ui| {
                ui.label("Common:");
                let status = if self.common_key_path.is_some() { "✓" } else { "✗" };
                ui.label(status);
                if ui.button("Browse").clicked() {
                    self.common_key_path = self.pick_key_file();
                }
            });
            
            // Title key
            ui.horizontal(|ui| {
                ui.label("Title:");
                if self.use_hex_key {
                    ui.text_edit_singleline(&mut self.title_key_hex);
                } else {
                    let status = if self.title_key_path.is_some() { "✓" } else { "✗" };
                    ui.label(status);
                    if ui.button("Browse").clicked() {
                        self.title_key_path = self.pick_key_file();
                    }
                }
                if ui.button(if self.use_hex_key { "File" } else { "Hex" }).clicked() {
                    self.use_hex_key = !self.use_hex_key;
                }
            });
            
            ui.separator();
            ui.label("Operation");
            
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.operation, Operation::ConvertToWud, "Convert → WUD");
                ui.radio_value(&mut self.operation, Operation::ExtractToWup, "Extract → WUP");
            });
            
            ui.checkbox(&mut self.verify_hashes, "Verify hashes");
            
            ui.separator();
            
            // Progress
            let progress = self.progress.lock().unwrap();
            if self.is_running {
                ui.add(egui::ProgressBar::new(progress.percent).text(&progress.message));
                ui.label(&progress.speed);
            }
            drop(progress);
            
            // Buttons
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let start_enabled = self.can_start() && !self.is_running;
                    if ui.add_enabled(start_enabled, egui::Button::new("▶ Start")).clicked() {
                        // TODO: Start operation
                        self.is_running = true;
                    }
                    
                    if ui.add_enabled(self.is_running, egui::Button::new("Cancel")).clicked() {
                        self.is_running = false;
                    }
                });
            });
        });
    }
}
