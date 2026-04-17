// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::info;

/// Manages hermetic Python runtime provisioning via the `uv` tool.
pub struct UvManager;

impl UvManager {
    /// Ensure a hermetic Python virtual environment for `version` exists at `target_dir`.
    ///
    /// If the environment is already present, this is a no-op.  On Windows, additionally
    /// seeds required DLLs into the Scripts directory for fully isolated execution.
    ///
    /// Returns the path to the `python` executable within the created environment.
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
