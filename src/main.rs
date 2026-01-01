//! KAIRO - Wii U Disc Image Tool
//! 
//! A lightweight GUI application for processing Wii U disc images.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod disc_keys;
mod error;
mod keys;
mod wux;
mod wud;
mod wup;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 400.0])
            .with_min_inner_size([400.0, 300.0])
            .with_icon(eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")).unwrap_or_default()),
        ..Default::default()
    };
    
    eframe::run_native(
        "KAIRO",
        options,
        Box::new(|cc| Ok(Box::new(app::KairoApp::new(cc)))),
    )
}
