use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::info;

pub struct UvManager;

impl UvManager {
    /// Ensure a hermetic Python runtime exists at the target directory.
    /// If it doesn't exist, use `uv venv` to create it.
    pub async fn ensure_hermetic_runtime(version: &str, target_dir: &Path) -> Result<PathBuf> {
        let python_exe = if cfg!(windows) {
            target_dir.join("Scripts").join("python.exe")
        } else {
            target_dir.join("bin").join("python")
        };

        if !python_exe.exists() {
            info!(
                "Provisioning hermetic runtime (Python {}) at {}...",
                version,
                target_dir.display()
            );

            if let Some(parent) = target_dir.parent() {
                std::fs::create_dir_all(parent)
                    .context("Failed to create parent directory for hermetic runtime")?;
            }

            let mut cmd = Command::new("uv");
            cmd.arg("venv")
                .arg(target_dir)
                .arg("--python")
                .arg(version)
                .arg("--link-mode")
                .arg("copy")
                .arg("--seed");

            let output = cmd.output().await.context("Failed to execute uv venv")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("uv venv failed: {}", stderr));
            }
        }

        // --- Hermetic Seeding (Critical for Sandbox) ---
        // Copy base DLLs into Scripts directory to ensure they are in the loader search path.
        if cfg!(windows) && target_dir.exists() {
            let scripts_dir = target_dir.join("Scripts");
            let cfg_path = target_dir.join("pyvenv.cfg");
            if cfg_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&cfg_path) {
                    let mut base_home = None;
                    for line in content.lines() {
                        if line.trim().starts_with("home =") {
                            base_home =
                                Some(line.split('=').nth(1).unwrap_or("").trim().to_string());
                        }
                    }

                    if let Some(home) = base_home {
                        let home_path = Path::new(&home);
                        info!("Seeding hermetic runtime with DLLs from {}...", home);

                        let dlls = [
                            "python3.dll",
                            "python312.dll",
                            "python311.dll",
                            "python310.dll",
                            "vcruntime140.dll",
                            "vcruntime140_1.dll",
                        ];
                        for dll in dlls {
                            let src = home_path.join(dll);
                            let dst = scripts_dir.join(dll);
                            if src.exists() && !dst.exists() {
                                info!("Copying {} to hermetic root...", dll);
                                let _ = std::fs::copy(&src, &dst);
                                // Ensure everyone (including AppContainers) can read the DLL
                                if cfg!(windows) {
                                    let _ = std::process::Command::new("icacls")
                                        .arg(&dst)
                                        .arg("/grant")
                                        .arg("Everyone:R")
                                        .output();
                                }
                            }
                        }
                    }
                }
            }
        }

        if cfg!(windows) {
            let _ = std::process::Command::new("icacls")
                .arg(&python_exe)
                .arg("/grant")
                .arg("Everyone:R")
                .output();
        }

        Ok(python_exe)
    }
}
